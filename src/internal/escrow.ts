import {
  type Address,
  type Hash,
  type PublicClient,
  type WalletClient,
  decodeErrorResult,
  encodeAbiParameters,
  encodeFunctionData,
  erc20Abi,
  getAddress,
  keccak256,
  toHex,
  toRlp,
  parseAbi,
} from "viem";
import { ContractError } from "../errors.js";
import { isNativeToken } from "../token.js";
import type { EscrowKind, TransferRow } from "../types.js";

const escrowAbi = parseAbi([
  "function cancelAndWithdraw() external",
  "function fund(uint256 _currentRewardAmount) external",
]);

// EscrowNative funds the bond pot alongside the reward.
const nativeEscrowAbi = parseAbi(["function fund(uint256 _currentRewardAmount, uint256 _bondAmount) external"]);

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

const BATCH_TRANSFER_COMPONENTS = [
  { type: "address", name: "asset" },
  { type: "address", name: "recipient" },
  { type: "uint256", name: "amount" },
] as const;

export function predictContractAddress(deployerAddress: Address, nonce: number): Address {
  const rlpEncoded = toRlp([deployerAddress, toHex(nonce)]);
  const hash = keccak256(rlpEncoded);
  return getAddress(`0x${hash.slice(26)}` as Address);
}

/**
 * Reward asset: the first ERC20 row, else the first row. Must agree across fee
 * calculation, approvals, constructor encoding, and the signal's tokenContract
 * or the deploy reverts.
 */
export function pickRewardToken(transfers: TransferRow[]): Address {
  const erc20 = transfers.find((t) => !isNativeToken(t.tokenAddress));
  return erc20 ? erc20.tokenAddress : transfers[0].tokenAddress;
}

/** Sum of native ETH rows, which the escrow holds directly rather than pulling. */
export function sumNativeAmount(transfers: TransferRow[]): bigint {
  return transfers.reduce((sum, t) => (isNativeToken(t.tokenAddress) ? sum + t.amount : sum), 0n);
}

/** Derive the escrow variant. Row count wins over reward-token nativeness. */
export function deriveEscrowKind(transfers: TransferRow[]): EscrowKind {
  if (transfers.length > 1) return "batch";
  return isNativeToken(pickRewardToken(transfers)) ? "native" : "erc20";
}

/**
 * Allowance buckets: one approval per distinct ERC20, with the node reward
 * folded into the reward asset's bucket.
 */
export function buildApprovalBuckets(
  transfers: TransferRow[],
  rewardAmount: bigint,
): Array<{ tokenAddress: Address; amount: bigint }> {
  const buckets = new Map<string, { tokenAddress: Address; amount: bigint }>();

  for (const row of transfers) {
    if (isNativeToken(row.tokenAddress)) continue;
    const key = row.tokenAddress.toLowerCase();
    const existing = buckets.get(key);
    if (existing) {
      existing.amount += row.amount;
    } else {
      buckets.set(key, { tokenAddress: row.tokenAddress, amount: row.amount });
    }
  }

  const rewardToken = pickRewardToken(transfers);
  if (!isNativeToken(rewardToken) && rewardAmount > 0n) {
    const key = rewardToken.toLowerCase();
    const existing = buckets.get(key);
    if (existing) {
      existing.amount += rewardAmount;
    } else {
      buckets.set(key, { tokenAddress: rewardToken, amount: rewardAmount });
    }
  }

  return Array.from(buckets.values());
}

/**
 * Approve a spender, resetting to zero first when required. USDT and similar
 * tokens revert on a non-zero to non-zero allowance change.
 */
async function approveToken(params: {
  tokenAddress: Address;
  spender: Address;
  amount: bigint;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
}): Promise<{ hash: Hash; gasUsed: bigint }> {
  const { tokenAddress, spender, amount, walletClient, publicClient, account } = params;

  const current = await publicClient.readContract({
    address: tokenAddress,
    abi: erc20Abi,
    functionName: "allowance",
    args: [account, spender],
  });

  let resetGas = 0n;
  if (current > 0n && current < amount) {
    const resetHash = await walletClient.writeContract({
      address: tokenAddress,
      abi: erc20Abi,
      functionName: "approve",
      args: [spender, 0n],
      chain: walletClient.chain,
      account,
    });
    const resetReceipt = await publicClient.waitForTransactionReceipt({ hash: resetHash });
    if (resetReceipt.status !== "success") {
      throw new ContractError("Allowance reset failed", { txHash: resetHash });
    }
    resetGas = resetReceipt.gasUsed;
  } else if (current >= amount) {
    return { hash: "0x" as Hash, gasUsed: 0n };
  }

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

  return { hash, gasUsed: receipt.gasUsed + resetGas };
}

function encodeConstructorArgs(params: {
  escrowType: EscrowKind;
  transfers: TransferRow[];
  rewardToken: Address;
  rewardAmount: bigint;
  blindedSigner?: Address;
  bondPot: bigint;
}): `0x${string}` {
  const { escrowType, transfers, rewardToken, rewardAmount, blindedSigner, bondPot } = params;

  if (escrowType === "batch") {
    return encodeAbiParameters(
      [
        { type: "address", name: "_rewardAsset" },
        { type: "tuple[]", name: "_expectedTransfers", components: BATCH_TRANSFER_COMPONENTS },
        { type: "uint256", name: "_currentRewardAmount" },
      ],
      [
        rewardToken,
        transfers.map((t) => ({
          asset: t.tokenAddress,
          recipient: t.recipientAddress,
          amount: t.amount,
        })),
        rewardAmount,
      ],
    );
  }

  const row = transfers[0];

  if (escrowType === "native") {
    return encodeAbiParameters(
      [
        { type: "address", name: "_expectedRecipient" },
        { type: "uint256", name: "_expectedAmount" },
        { type: "address", name: "_blindedSigner" },
        { type: "uint256", name: "_currentRewardAmount" },
        { type: "uint256", name: "_bondAmount" },
      ],
      [row.recipientAddress, row.amount, blindedSigner!, rewardAmount, bondPot],
    );
  }

  return encodeAbiParameters(
    [
      { type: "address", name: "_tokenContract" },
      { type: "address", name: "_expectedRecipient" },
      { type: "uint256", name: "_expectedAmount" },
      { type: "address", name: "_blindedSigner" },
      { type: "uint256", name: "_currentRewardAmount" },
    ],
    [rewardToken, row.recipientAddress, row.amount, blindedSigner!, rewardAmount],
  );
}

/** msg.value at deploy: native payments plus, for single escrows, the bond pot. */
function computeDeployValue(params: {
  escrowType: EscrowKind;
  transfers: TransferRow[];
  rewardToken: Address;
  rewardAmount: bigint;
  bondPot: bigint;
}): bigint {
  const { escrowType, transfers, rewardToken, rewardAmount, bondPot } = params;

  if (escrowType === "batch") {
    return sumNativeAmount(transfers) + (isNativeToken(rewardToken) ? rewardAmount : 0n);
  }

  if (escrowType === "native") {
    return transfers[0].amount + rewardAmount + bondPot;
  }

  return bondPot;
}

export interface DeployResult {
  hash: Hash;
  escrowAddress: Address;
  deployGasUsed: bigint;
  deployEffectiveGasPrice: bigint;
}

export interface ApproveAndDeployResult {
  approvals: Array<{ hash: Hash; tokenAddress: Address; gasUsed: bigint }>;
  approveGasUsed: bigint;
  deployResult: DeployResult;
}

/**
 * Approve each distinct ERC20 against the predicted escrow, then deploy. With
 * K approvals the deploy lands at nonce N+K, so the address is predicted from
 * that offset and every approval targets it.
 */
export async function approveAndDeploy(params: {
  bytecode: `0x${string}`;
  escrowType: EscrowKind;
  transfers: TransferRow[];
  rewardAmount: bigint;
  blindedSigner?: Address;
  bondPot: bigint;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
  onApproval?: (approval: { hash: Hash; tokenAddress: Address; index: number; total: number }) => void;
}): Promise<ApproveAndDeployResult> {
  const {
    bytecode,
    escrowType,
    transfers,
    rewardAmount,
    blindedSigner,
    bondPot,
    walletClient,
    publicClient,
    account,
    onApproval,
  } = params;

  const rewardToken = pickRewardToken(transfers);
  const buckets = buildApprovalBuckets(transfers, rewardAmount);

  const nonce = await publicClient.getTransactionCount({ address: account, blockTag: "pending" });
  const predictedEscrowAddress = predictContractAddress(account, nonce + buckets.length);

  const approvals: Array<{ hash: Hash; tokenAddress: Address; gasUsed: bigint }> = [];
  let approveGasUsed = 0n;

  for (const [index, bucket] of buckets.entries()) {
    const { hash, gasUsed } = await approveToken({
      tokenAddress: bucket.tokenAddress,
      spender: predictedEscrowAddress,
      amount: bucket.amount,
      walletClient,
      publicClient,
      account,
    });
    approveGasUsed += gasUsed;
    if (hash !== "0x") {
      approvals.push({ hash, tokenAddress: bucket.tokenAddress, gasUsed });
      onApproval?.({ hash, tokenAddress: bucket.tokenAddress, index, total: buckets.length });
    }
  }

  const constructorArgs = encodeConstructorArgs({
    escrowType,
    transfers,
    rewardToken,
    rewardAmount,
    blindedSigner,
    bondPot,
  });

  const deployHash = await walletClient.sendTransaction({
    to: null,
    data: `${bytecode}${constructorArgs.slice(2)}` as `0x${string}`,
    chain: walletClient.chain,
    account,
    value: computeDeployValue({ escrowType, transfers, rewardToken, rewardAmount, bondPot }),
  });

  const deployReceipt = await publicClient.waitForTransactionReceipt({ hash: deployHash });
  if (deployReceipt.status !== "success") {
    throw new ContractError("Escrow deployment failed", { txHash: deployHash });
  }

  return {
    approvals,
    approveGasUsed,
    deployResult: {
      hash: deployHash,
      // receipt.contractAddress is unreliable on some chains; prefer the
      // CREATE-predicted address.
      escrowAddress: predictedEscrowAddress ?? deployReceipt.contractAddress,
      deployGasUsed: deployReceipt.gasUsed,
      deployEffectiveGasPrice: deployReceipt.effectiveGasPrice,
    },
  };
}

/**
 * Tempo: deploy, approve, and fund in a single native-multicall transaction.
 * The constructor runs with a zero reward so it skips the pull, then fund()
 * moves the tokens once the allowances exist.
 */
export async function deployAtomicBatch(params: {
  bytecode: `0x${string}`;
  escrowType: EscrowKind;
  selectorMapping?: Record<string, string>;
  transfers: TransferRow[];
  rewardAmount: bigint;
  blindedSigner?: Address;
  bondPot: bigint;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
}): Promise<DeployResult> {
  const {
    bytecode,
    escrowType,
    selectorMapping,
    transfers,
    rewardAmount,
    blindedSigner,
    bondPot,
    walletClient,
    publicClient,
    account,
  } = params;

  const rewardToken = pickRewardToken(transfers);
  const nonce = await publicClient.getTransactionCount({ address: account });
  const predictedEscrowAddress = predictContractAddress(account, nonce);

  // Deploy with a zero reward so the constructor skips funding.
  const constructorArgs = encodeConstructorArgs({
    escrowType,
    transfers,
    rewardToken,
    rewardAmount: 0n,
    blindedSigner,
    bondPot,
  });

  const approveCalls = buildApprovalBuckets(transfers, rewardAmount).map((bucket) => ({
    to: bucket.tokenAddress,
    data: encodeFunctionData({
      abi: erc20Abi,
      functionName: "approve",
      args: [predictedEscrowAddress, bucket.amount],
    }),
    value: 0n,
  }));

  const standardFundData =
    escrowType === "native"
      ? encodeFunctionData({
          abi: nativeEscrowAbi,
          functionName: "fund",
          args: [rewardAmount, bondPot],
        })
      : encodeFunctionData({ abi: escrowAbi, functionName: "fund", args: [rewardAmount] });
  const obfuscatedSelector = selectorMapping?.[standardFundData.slice(0, 10)];
  const fundData = obfuscatedSelector
    ? (`${obfuscatedSelector}${standardFundData.slice(10)}` as `0x${string}`)
    : standardFundData;

  // The constructor runs with a zero reward, so the pot and payment travel
  // with fund() instead of the deploy call.
  const fundValue =
    sumNativeAmount(transfers) + (isNativeToken(rewardToken) ? rewardAmount : 0n) + bondPot;

  const hash = await (walletClient as unknown as {
    sendTransaction: (args: unknown) => Promise<Hash>;
  }).sendTransaction({
    calls: [
      { data: `${bytecode}${constructorArgs.slice(2)}` as `0x${string}`, value: 0n },
      ...approveCalls,
      { to: predictedEscrowAddress, data: fundData, value: fundValue },
    ],
    chain: walletClient.chain,
    account,
  });

  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new ContractError("Batched escrow deployment failed", { txHash: hash });
  }

  return {
    hash,
    escrowAddress: predictedEscrowAddress,
    deployGasUsed: receipt.gasUsed,
    deployEffectiveGasPrice: receipt.effectiveGasPrice,
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
  } catch (simError) {
    const err = simError as { data?: `0x${string}`; cause?: { data?: `0x${string}` } };
    const revertData = err?.data ?? err?.cause?.data;
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
