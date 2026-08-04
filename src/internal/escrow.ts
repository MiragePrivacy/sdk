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
import { ContractError } from "../errors.js";
import { isNativeToken } from "../token.js";
import type { ApprovalCheckpoint, TransferRow } from "../types.js";

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

/** Reward denomination selected by the API from the first ordered Signal. */
export function pickRewardToken(transfers: TransferRow[]): Address {
  return transfers[0].tokenAddress;
}

/** Convert the API's exact funding map into ERC-20 approval calls. */
export function buildQuotedApprovalBuckets(
  depositByAsset: Record<string, bigint>,
): Array<{ tokenAddress: Address; amount: bigint }> {
  return Object.entries(depositByAsset)
    .map(([asset, amount]) => ({ tokenAddress: getAddress(asset), amount }))
    .filter(({ tokenAddress, amount }) => !isNativeToken(tokenAddress) && amount > 0n);
}

async function approveToken(params: {
  tokenAddress: Address;
  spender: Address;
  amount: bigint;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
}): Promise<{ hash: Hash; gasUsed: bigint }> {
  const { tokenAddress, spender, amount, walletClient, publicClient, account } = params;
  const hash = await walletClient.writeContract({
    address: tokenAddress,
    abi: erc20Abi,
    functionName: "approve",
    args: [spender, amount],
    chain: walletClient.chain,
    account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new ContractError("Token approval failed", { txHash: hash });
  }
  return { hash, gasUsed: receipt.gasUsed };
}

/** Approve the exact API-quoted deposits against the predicted escrow. */
export async function* approveQuotedForDeployment(params: {
  depositByAsset: Record<string, bigint>;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
  onAbortCheck?: () => void;
}): AsyncGenerator<
  { hash: Hash; tokenAddress: Address; gasUsed: bigint; index: number; total: number },
  ApprovalCheckpoint
> {
  const { depositByAsset, walletClient, publicClient, account, onAbortCheck } = params;
  const buckets = buildQuotedApprovalBuckets(depositByAsset);
  const nonce = await publicClient.getTransactionCount({ address: account, blockTag: "pending" });
  const predictedEscrowAddress = predictContractAddress(account, nonce + buckets.length);
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

export interface DeployResult {
  hash: Hash;
  escrowAddress: Address;
  deployGasUsed: bigint;
  deployEffectiveGasPrice: bigint;
  deployBlock: bigint;
}

/** Deploy the exact bytecode plus constructor suffix returned by pricing. */
export async function deployQuotedApproved(params: {
  bytecode: `0x${string}`;
  constructorArgs: `0x${string}`;
  depositByAsset: Record<string, bigint>;
  msgValue: bigint;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
  checkpoint?: ApprovalCheckpoint;
}): Promise<DeployResult> {
  const {
    bytecode,
    constructorArgs,
    depositByAsset,
    msgValue,
    walletClient,
    publicClient,
    account,
    checkpoint,
  } = params;
  if (buildQuotedApprovalBuckets(depositByAsset).length > 0 && !checkpoint) {
    throw new ContractError("Token approvals must complete before deployment");
  }
  if (checkpoint && checkpoint.account.toLowerCase() !== account.toLowerCase()) {
    throw new ContractError("Approval checkpoint belongs to a different account");
  }

  const predictedEscrowAddress =
    checkpoint?.predictedEscrowAddress ??
    predictContractAddress(
      account,
      await publicClient.getTransactionCount({ address: account, blockTag: "pending" }),
    );
  const hash = await walletClient.sendTransaction({
    to: null,
    data: `${bytecode}${constructorArgs.slice(2)}` as `0x${string}`,
    value: msgValue,
    chain: walletClient.chain,
    account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new ContractError("Escrow deployment failed", { txHash: hash });
  }
  if (receipt.contractAddress && getAddress(receipt.contractAddress) !== predictedEscrowAddress) {
    throw new ContractError(
      `Escrow deployed to ${receipt.contractAddress} but ${predictedEscrowAddress} was predicted`,
      { txHash: hash },
    );
  }
  return {
    hash,
    escrowAddress: predictedEscrowAddress,
    deployGasUsed: receipt.gasUsed,
    deployEffectiveGasPrice: receipt.effectiveGasPrice,
    deployBlock: receipt.blockNumber,
  };
}

/** Tempo call-vector equivalent of exact quoted approvals and deployment. */
export async function deployQuotedAtomic(params: {
  bytecode: `0x${string}`;
  constructorArgs: `0x${string}`;
  depositByAsset: Record<string, bigint>;
  msgValue: bigint;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
}): Promise<DeployResult> {
  const {
    bytecode,
    constructorArgs,
    depositByAsset,
    msgValue,
    walletClient,
    publicClient,
    account,
  } = params;
  const nonce = await publicClient.getTransactionCount({ address: account, blockTag: "pending" });
  const predictedEscrowAddress = predictContractAddress(account, nonce);
  const approvalCalls = buildQuotedApprovalBuckets(depositByAsset).map((bucket) => ({
    to: bucket.tokenAddress,
    data: encodeFunctionData({
      abi: erc20Abi,
      functionName: "approve",
      args: [predictedEscrowAddress, bucket.amount],
    }),
    value: 0n,
  }));
  const hash = await (walletClient as unknown as {
    sendTransaction: (args: unknown) => Promise<Hash>;
  }).sendTransaction({
    calls: [
      ...approvalCalls,
      { data: `${bytecode}${constructorArgs.slice(2)}` as `0x${string}`, value: msgValue },
    ],
    chain: walletClient.chain,
    account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new ContractError("Batched escrow deployment failed", { txHash: hash });
  }
  if (receipt.contractAddress && getAddress(receipt.contractAddress) !== predictedEscrowAddress) {
    throw new ContractError(
      `Escrow deployed to ${receipt.contractAddress} but ${predictedEscrowAddress} was predicted`,
      { txHash: hash },
    );
  }
  return {
    hash,
    escrowAddress: predictedEscrowAddress,
    deployGasUsed: receipt.gasUsed,
    deployEffectiveGasPrice: receipt.effectiveGasPrice,
    deployBlock: receipt.blockNumber,
  };
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
