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
import type { NetworkConfig } from "../types.js";

const escrowAbi = parseAbi([
  "function cancelAndWithdraw() external",
  "function fund(uint256 _currentRewardAmount, uint256 _currentPaymentAmount) external",
]);

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

export function predictContractAddress(
  deployerAddress: Address,
  nonce: number,
): Address {
  const rlpEncoded = toRlp([deployerAddress, toHex(nonce)]);
  const hash = keccak256(rlpEncoded);
  return getAddress(`0x${hash.slice(26)}` as Address);
}

export interface DeployResult {
  hash: Hash;
  escrowAddress: Address;
  deployGasUsed: bigint;
  deployEffectiveGasPrice: bigint;
}

// Ethereum: approve predicted escrow → deploy (constructor does transferFrom)
// Native ETH: deploy with value (no approve needed)
export async function approveAndDeploy(params: {
  bytecode: `0x${string}`;
  selectorMapping?: Record<string, string>;
  tokenAddress: Address;
  recipientAddress: Address;
  transferAmount: bigint;
  rewardAmount: bigint;
  totalAmount: bigint;
  isNativeEth: boolean;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
}): Promise<{
  approveHash: Hash | null;
  approveGasUsed: bigint | null;
  deployResult: DeployResult;
}> {
  const {
    bytecode, tokenAddress, recipientAddress,
    transferAmount, rewardAmount, totalAmount,
    isNativeEth, walletClient, publicClient, account,
  } = params;

  const nonce = await publicClient.getTransactionCount({ address: account, blockTag: "pending" });

  let approveHash: Hash | null = null;
  let approveGasUsed: bigint | null = null;

  if (!isNativeEth) {
    // Approve uses nonce N, deploy uses nonce N+1
    const predictedEscrowAddress = predictContractAddress(account, nonce + 1);

    approveHash = await walletClient.writeContract({
      address: tokenAddress,
      abi: erc20Abi,
      functionName: "approve",
      args: [predictedEscrowAddress, totalAmount],
      chain: walletClient.chain,
    });

    const approveReceipt = await publicClient.waitForTransactionReceipt({ hash: approveHash });
    if (approveReceipt.status !== "success") {
      throw new ContractError("Token approval failed", { txHash: approveHash });
    }
    approveGasUsed = approveReceipt.gasUsed;
  }

  // Build constructor args
  const constructorArgs = isNativeEth
    ? encodeAbiParameters(
        [
          { type: "address", name: "_expectedRecipient" },
          { type: "uint256", name: "_expectedAmount" },
          { type: "uint256", name: "_currentRewardAmount" },
          { type: "uint256", name: "_currentPaymentAmount" },
        ],
        [recipientAddress, transferAmount, rewardAmount, transferAmount],
      )
    : encodeAbiParameters(
        [
          { type: "address", name: "_tokenContract" },
          { type: "address", name: "_expectedRecipient" },
          { type: "uint256", name: "_expectedAmount" },
          { type: "uint256", name: "_currentRewardAmount" },
          { type: "uint256", name: "_currentPaymentAmount" },
        ],
        [tokenAddress, recipientAddress, transferAmount, rewardAmount, transferAmount],
      );

  const deploymentData = `${bytecode}${constructorArgs.slice(2)}` as `0x${string}`;
  const value = isNativeEth ? rewardAmount + transferAmount : undefined;

  const deployHash = await walletClient.sendTransaction({
    to: null,
    data: deploymentData,
    chain: walletClient.chain,
    value,
  });

  const deployReceipt = await publicClient.waitForTransactionReceipt({ hash: deployHash });
  if (deployReceipt.status !== "success") {
    throw new ContractError("Escrow deployment failed", { txHash: deployHash });
  }

  const escrowAddress = deployReceipt.contractAddress;
  if (!escrowAddress) {
    throw new ContractError("No contract address in deploy receipt", { txHash: deployHash });
  }

  return {
    approveHash,
    approveGasUsed,
    deployResult: {
      hash: deployHash,
      escrowAddress,
      deployGasUsed: deployReceipt.gasUsed,
      deployEffectiveGasPrice: deployReceipt.effectiveGasPrice,
    },
  };
}

// Tempo: deploy + approve + fund in a single batched transaction
export async function deployBatched(params: {
  bytecode: `0x${string}`;
  selectorMapping?: Record<string, string>;
  tokenAddress: Address;
  recipientAddress: Address;
  transferAmount: bigint;
  rewardAmount: bigint;
  totalAmount: bigint;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
}): Promise<DeployResult> {
  const {
    bytecode, selectorMapping, tokenAddress, recipientAddress,
    transferAmount, rewardAmount, totalAmount,
    walletClient, publicClient, account,
  } = params;

  const nonce = await publicClient.getTransactionCount({ address: account, blockTag: "pending" });
  const predictedEscrowAddress = predictContractAddress(account, nonce);

  // 1. Deploy with 0 amounts (constructor skips transferFrom)
  const constructorArgs = encodeAbiParameters(
    [
      { type: "address", name: "_tokenContract" },
      { type: "address", name: "_expectedRecipient" },
      { type: "uint256", name: "_expectedAmount" },
      { type: "uint256", name: "_currentRewardAmount" },
      { type: "uint256", name: "_currentPaymentAmount" },
    ],
    [tokenAddress, recipientAddress, transferAmount, 0n, 0n],
  );
  const deploymentData = `${bytecode}${constructorArgs.slice(2)}` as `0x${string}`;

  // 2. Approve the predicted escrow as spender
  const approveData = encodeFunctionData({
    abi: erc20Abi,
    functionName: "approve",
    args: [predictedEscrowAddress, totalAmount],
  });

  // 3. Call fund() — use obfuscated selector if available
  const standardFundData = encodeFunctionData({
    abi: escrowAbi,
    functionName: "fund",
    args: [rewardAmount, transferAmount],
  });
  const originalSelector = standardFundData.slice(0, 10);
  const obfuscatedSelector = selectorMapping?.[originalSelector];
  const fundData = obfuscatedSelector
    ? (`${obfuscatedSelector}${standardFundData.slice(10)}` as `0x${string}`)
    : standardFundData;

  // Submit batched transaction (Tempo native multicall)
  const hash = await (walletClient as any).sendTransaction({
    calls: [
      { data: deploymentData, value: 0n },
      { to: tokenAddress, data: approveData, value: 0n },
      { to: predictedEscrowAddress, data: fundData, value: 0n },
    ],
    chain: walletClient.chain,
  });

  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new ContractError("Batched escrow deployment failed", { txHash: hash });
  }

  return {
    hash,
    escrowAddress: receipt.contractAddress ?? predictedEscrowAddress,
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
