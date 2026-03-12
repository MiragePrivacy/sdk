import type { Address, Hash } from "viem";

export type NetworkId = "sepolia" | "tempo" | "ethereum";
export type NetworkKind = "ethereum" | "tempo";

export interface GasConstants {
  approve: bigint;
  deploy: bigint;
  bond: bigint;
  transfer: bigint;
  collect: bigint;
}

export interface NetworkConfig {
  id: NetworkId;
  kind: NetworkKind;
  chainId: number;
  rpcUrl: string;
  nomadUrl: string;
  apiServer: string;
  enableCompliance: boolean;
  enableBatch: boolean;
  nodeFeeUsd: bigint;
  platformFeeRate: bigint;
  gas: GasConstants;
  // Uniswap V2 router address for ETH->token price conversion (EVM ERC20 fees)
  uniswapRouter?: Address;
  // WETH address override (normally fetched from router)
  wethAddress?: Address;
  // For testnets: use a different chain's RPC for pricing (e.g. mainnet for sepolia)
  priceRpcUrl?: string;
  priceChainId?: number;
  priceTokenContract?: Address;
  priceUniswapRouter?: Address;
}

export interface FeeEstimate {
  transferAmount: bigint;
  networkFee: bigint;
  nodeFee: bigint;
  platformFee: bigint;
  totalFee: bigint;
  totalAmount: bigint;
  decimals: number;
  isNativeEth: boolean;
}

export interface TransferEvent {
  transactionHash: Hash;
  blockNumber: bigint;
  amount: bigint;
  from: Address;
  to: Address;
}

export interface NetworkKeyStatus {
  publicKey: string;
  attested: boolean;
  debug: boolean;
  chainId: number;
  mrenclave?: string;
  mrsigner?: string;
}

export interface TokenMetadata {
  address: Address;
  name: string;
  symbol: string;
  decimals: number;
}

export interface GasPrice {
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

export type TransferStep =
  | { step: "fees"; fees: FeeEstimate }
  | { step: "approve"; hash: Hash }
  | { step: "deploy"; hash: Hash; escrowAddress: Address }
  | { step: "compliance"; approval: { signature: string; timestamp: number } }
  | { step: "signal"; hash: Hash }
  | { step: "complete"; transfer: TransferEvent };

export interface PreparedTransfer {
  fees: FeeEstimate;
  execute(): AsyncGenerator<TransferStep>;
}
