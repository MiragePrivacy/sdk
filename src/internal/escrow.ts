import {
  type Address,
  type Hash,
  type PublicClient,
  type WalletClient,
  decodeErrorResult,
  encodeFunctionData,
  erc20Abi,
  getAddress,
  keccak256,
  parseAbi,
  toHex,
  toRlp,
} from "viem";
import { ContractError, MirageError } from "../errors.js";
import { isNativeToken } from "../token.js";
import type { ApprovalCallbacks, ApprovalCheckpoint, GasPrice } from "../types.js";

const GAS_BUFFER_NUMERATOR = 12n;
const GAS_BUFFER_DENOMINATOR = 10n;

/** Add 20% headroom to simulated wallet transaction gas limits. */
export function bufferedGasLimit(estimate: bigint): bigint {
  return (
    (estimate * GAS_BUFFER_NUMERATOR + GAS_BUFFER_DENOMINATOR - 1n) / GAS_BUFFER_DENOMINATOR
  );
}

const escrowAbi = parseAbi(["function is_bonded() external view returns (bool)"]);

const CANCEL_ABI = [
  {
    name: "cancelAndWithdraw",
    type: "function" as const,
    stateMutability: "nonpayable" as const,
    inputs: [],
    outputs: [],
  },
  { name: "OnlyDeployer", type: "error" as const, inputs: [] },
  { name: "NotFunded", type: "error" as const, inputs: [] },
  { name: "BondActive", type: "error" as const, inputs: [] },
  { name: "CancellationRequested", type: "error" as const, inputs: [] },
  { name: "NoWithdrawableFunds", type: "error" as const, inputs: [] },
  { name: "TokenTransferFailed", type: "error" as const, inputs: [] },
  { name: "ETHTransferFailed", type: "error" as const, inputs: [] },
] as const;

const CANCEL_REASON_MESSAGES: Record<string, string> = {
  BondActive: "a node has already bonded",
  NotFunded: "escrow is not funded",
  OnlyDeployer: "only the deployer can cancel",
  NoWithdrawableFunds: "no funds to withdraw",
  CancellationRequested: "cancellation already requested",
  TokenTransferFailed: "token transfer back to deployer failed",
  ETHTransferFailed: "ETH transfer back to deployer failed",
};

export function predictContractAddress(deployerAddress: Address, nonce: number): Address {
  const rlpEncoded = toRlp([deployerAddress, nonce === 0 ? "0x" : toHex(nonce)]);
  return getAddress(`0x${keccak256(rlpEncoded).slice(26)}` as Address);
}

/** Convert the API's exact funding map into ERC-20 approval calls. */
export function buildQuotedApprovalBuckets(
  depositByAsset: Record<string, bigint>,
): Array<{ tokenAddress: Address; amount: bigint }> {
  return Object.entries(depositByAsset)
    .map(([asset, amount]) => ({ tokenAddress: getAddress(asset), amount }))
    .filter(({ tokenAddress, amount }) => !isNativeToken(tokenAddress) && amount > 0n);
}

/** Simulate every exact ERC-20 approval required before escrow deployment. */
export async function estimateQuotedApprovalGas(params: {
  predictedEscrowAddress?: Address;
  depositByAsset: Record<string, bigint>;
  publicClient: PublicClient;
  account: Address;
}): Promise<bigint> {
  const { depositByAsset, publicClient, account } = params;
  const buckets = buildQuotedApprovalBuckets(depositByAsset);
  if (buckets.length === 0) return 0n;

  const predictedEscrowAddress = params.predictedEscrowAddress ?? predictContractAddress(
    account, await publicClient.getTransactionCount({ address: account, blockTag: "pending" }) + buckets.length,
  );
  const estimates = await Promise.all(
    buckets.map((bucket) =>
      publicClient.estimateContractGas({
        address: bucket.tokenAddress,
        abi: erc20Abi,
        functionName: "approve",
        args: [predictedEscrowAddress, bucket.amount],
        account,
      }),
    ),
  );
  return estimates.reduce((total, estimate) => total + estimate, 0n);
}

async function approveToken(params: ApprovalCallbacks & {
  tokenAddress: Address;
  spender: Address;
  amount: bigint;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
  gasPrice?: GasPrice;
}): Promise<{ hash: Hash; gasUsed: bigint }> {
  const { tokenAddress, spender, amount, walletClient, publicClient, account, gasPrice } = params;
  const gasEstimate = await publicClient.estimateContractGas({
    address: tokenAddress,
    abi: erc20Abi,
    functionName: "approve",
    args: [spender, amount],
    account,
  });
  params.onWalletRequest?.();
  const hash = await walletClient.writeContract({
    address: tokenAddress,
    abi: erc20Abi,
    functionName: "approve",
    args: [spender, amount],
    chain: walletClient.chain,
    account,
    gas: bufferedGasLimit(gasEstimate),
    ...gasPrice,
  });
  params.onBroadcast?.(hash);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new ContractError("Token approval failed", { txHash: hash });
  }
  return { hash, gasUsed: receipt.gasUsed };
}

/** Approve the exact API-quoted deposits against the predicted escrow. */
export async function* approveQuotedForDeployment(params: ApprovalCallbacks & {
  expectedEscrowAddress?: Address;
  depositByAsset: Record<string, bigint>;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
  gasPrice?: GasPrice;
  onAbortCheck?: () => void;
}): AsyncGenerator<
  { hash: Hash; tokenAddress: Address; gasUsed: bigint; index: number; total: number },
  ApprovalCheckpoint
> {
  const { depositByAsset, walletClient, publicClient, account, gasPrice, onAbortCheck } = params;
  const buckets = buildQuotedApprovalBuckets(depositByAsset);
  const nonce = await publicClient.getTransactionCount({ address: account, blockTag: "pending" });
  const predictedEscrowAddress = predictContractAddress(account, nonce + buckets.length);
  if (params.expectedEscrowAddress && predictedEscrowAddress !== params.expectedEscrowAddress) {
    throw new MirageError("STALE_PREPARATION", "The wallet nonce changed. Review a fresh quote before approving.");
  }
  onAbortCheck?.();
  const approvals: ApprovalCheckpoint["approvals"] = [];
  let approveGasUsed = 0n;

  for (const [index, bucket] of buckets.entries()) {
    onAbortCheck?.();
    const result = await approveToken({
      tokenAddress: bucket.tokenAddress,
      spender: predictedEscrowAddress,
      amount: bucket.amount,
      walletClient,
      publicClient,
      account,
      gasPrice,
      onWalletRequest: () => { onAbortCheck?.(); params.onWalletRequest?.(); },
      onBroadcast: params.onBroadcast,
    });
    approveGasUsed += result.gasUsed;
    const approval = { ...result, tokenAddress: bucket.tokenAddress };
    approvals.push(approval);
    yield { ...approval, index, total: buckets.length };
  }

  return {
    stage: "approved",
    account,
    predictedEscrowAddress,
    approvals,
    approveGasUsed,
  };
}

/** Submit once. Receipt recovery is a separate read-only operation. */
export async function submitQuotedDeployment(params: {
  bytecode: `0x${string}`;
  constructorArgs: `0x${string}`;
  depositByAsset: Record<string, bigint>;
  msgValue: bigint;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
  gasEstimate?: bigint;
  gasPrice?: GasPrice;
  checkpoint?: ApprovalCheckpoint;
  expectedEscrowAddress?: Address;
  chainId: number;
  beforeSend: (intent: { escrowAddress: Address; nonce: number; inputHash: Hash; fromBlock: string }) => Promise<void>;
}): Promise<Hash> {
  const {
    bytecode,
    constructorArgs,
    depositByAsset,
    msgValue,
    walletClient,
    publicClient,
    account,
    gasEstimate,
    gasPrice,
    checkpoint,
  } = params;
  if (buildQuotedApprovalBuckets(depositByAsset).length > 0 && !checkpoint) {
    throw new ContractError("Token approvals must complete before deployment");
  }
  if (checkpoint && checkpoint.account.toLowerCase() !== account.toLowerCase()) {
    throw new ContractError("Approval checkpoint belongs to a different account");
  }

  const data = `${bytecode}${constructorArgs.slice(2)}` as const;
  // Simulate current allowances while independently capturing the deployment
  // nonce and the recovery search bound. None depends on another RPC response.
  const [chainId, nonce, fromBlock, localGasEstimate] = await Promise.all([
    publicClient.getChainId(),
    publicClient.getTransactionCount({ address: account, blockTag: "pending" }),
    publicClient.getBlockNumber({ cacheTime: 0 }),
    publicClient.estimateGas({ account, to: null, data, value: msgValue }),
  ]);
  if (chainId !== params.chainId || (walletClient.chain && walletClient.chain.id !== chainId)) {
    throw new ContractError("The deployment network changed. Switch back to the quoted network.");
  }
  const escrowAddress = predictContractAddress(account, nonce);
  if ([checkpoint?.predictedEscrowAddress, params.expectedEscrowAddress].some(
    expected => expected && getAddress(expected) !== escrowAddress,
  )) {
    throw new ContractError("The sender nonce changed. Review a new transfer before deploying.");
  }
  const estimatedGas =
    gasEstimate === undefined || localGasEstimate > gasEstimate ? localGasEstimate : gasEstimate;
  await params.beforeSend({ nonce, escrowAddress, inputHash: keccak256(data), fromBlock: fromBlock.toString() });
  return walletClient.sendTransaction({
    to: null,
    data,
    value: msgValue,
    chain: walletClient.chain,
    account,
    nonce,
    gas: bufferedGasLimit(estimatedGas),
    ...gasPrice,
  });
}

export async function withdrawFromEscrow(params: {
  escrowAddress: Address;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
  selectorMapping?: Record<string, string>;
}): Promise<Hash> {
  const { escrowAddress, walletClient, publicClient, account, selectorMapping } = params;
  const standardData = encodeFunctionData({
    abi: CANCEL_ABI,
    functionName: "cancelAndWithdraw",
    args: [],
  });
  const obfuscatedSelector = selectorMapping?.[standardData.slice(0, 10)];
  const data = obfuscatedSelector
    ? (`${obfuscatedSelector}${standardData.slice(10)}` as `0x${string}`)
    : standardData;
  const hash = await walletClient.sendTransaction({
    account,
    to: escrowAddress,
    data,
    chain: walletClient.chain,
    gas: 500_000n,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status === "success") return hash;

  let reason = "unknown reason";
  try {
    await publicClient.call({ to: escrowAddress, data, account });
  } catch (simulationError) {
    const error = simulationError as {
      data?: `0x${string}`;
      cause?: { data?: `0x${string}` };
    };
    const revertData = error.data ?? error.cause?.data;
    if (revertData) {
      try {
        reason = decodeErrorResult({ abi: CANCEL_ABI, data: revertData }).errorName;
      } catch {
        reason = revertData;
      }
    }
  }
  throw new ContractError(
    `cancelAndWithdraw reverted: ${CANCEL_REASON_MESSAGES[reason] ?? reason}`,
    { txHash: hash },
  );
}

export async function getEscrowStatus(params: {
  escrowAddress: Address;
  publicClient: PublicClient;
  selectorMapping?: Record<string, string>;
}): Promise<{ bonded: boolean; cancellable: boolean }> {
  const standardData = encodeFunctionData({ abi: escrowAbi, functionName: "is_bonded" });
  const mapped = params.selectorMapping?.[standardData.slice(0, 10)];
  const data = mapped ? (`${mapped}${standardData.slice(10)}` as `0x${string}`) : standardData;
  const result = await params.publicClient.call({ to: params.escrowAddress, data });
  const bonded = BigInt(result.data ?? "0x0") !== 0n;
  return { bonded, cancellable: !bonded };
}

export const cancelTransfer = withdrawFromEscrow;
