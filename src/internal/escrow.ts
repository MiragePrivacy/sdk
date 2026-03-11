import {
  type Address,
  type Hash,
  type PublicClient,
  type WalletClient,
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
  "function withdraw() external",
  "function fund(uint256 _currentRewardAmount, uint256 _currentPaymentAmount) external",
]);

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
}): Promise<{ approveHash: Hash | null; deployResult: DeployResult }> {
  const {
    bytecode, tokenAddress, recipientAddress,
    transferAmount, rewardAmount, totalAmount,
    isNativeEth, walletClient, publicClient, account,
  } = params;

  const nonce = await publicClient.getTransactionCount({ address: account });

  let approveHash: Hash | null = null;

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
    deployResult: { hash: deployHash, escrowAddress },
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

  const nonce = await publicClient.getTransactionCount({ address: account });
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
  };
}

export async function withdrawFromEscrow(params: {
  escrowAddress: Address;
  walletClient: WalletClient;
  publicClient: PublicClient;
  account: Address;
}): Promise<Hash> {
  const { escrowAddress, walletClient, publicClient, account } = params;

  const hash = await walletClient.writeContract({
    address: escrowAddress,
    abi: escrowAbi,
    functionName: "withdraw",
    chain: walletClient.chain,
  });

  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new ContractError("Escrow withdrawal failed", { txHash: hash });
  }

  return hash;
}
