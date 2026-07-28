import type { Address, Hash } from "viem";

export type NetworkId = "sepolia" | "tempo" | "ethereum";
export type NetworkKind = "ethereum" | "tempo";

/**
 * Escrow variant. Determines the deployed bytecode, constructor shape, and is
 * cross-validated by the node against the signal's reward token.
 */
export type EscrowKind = "erc20" | "native" | "batch";

export interface GasConstants {
  approve: bigint;
  deploy: bigint;
  bond: bigint;
  fund: bigint;
  collect: bigint;
}

/** Gas constants for the native ETH escrow variant. */
export interface NativeGasConstants {
  deploy: bigint;
  bond: bigint;
  fund: bigint;
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
  /** Submit approve + deploy + fund as a single native-multicall tx (tempo). */
  enableAtomicBatch: boolean;
  nodeFeeUsd: bigint;
  /** Base node fee for native ETH transfers, in wei. */
  nodeFeeWei: bigint;
  platformFeeRate: bigint;
  gas: GasConstants;
  nativeGas: NativeGasConstants;
  /** Multiplier applied to bond + collect gas when sizing the bond pot (x100). */
  bondPotMarginBps: bigint;
  /**
   * Fixed ETH->token rate, bypassing the on-chain oracle. Intended for local
   * chains and tests where no Uniswap deployment exists.
   */
  ethToTokenRate?: number;
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
  /**
   * ETH the wallet fronts as msg.value at deploy to fund the node's bond and
   * collect transactions. Always wei, on both native and ERC20 escrows. Zero
   * for batch escrows. Refundable surplus, not a fee, so it is excluded from
   * totalFee but included in totalAmount.
   */
  bondPot: bigint;
  /**
   * Amount pulled by the escrow: transferAmount + nodeFee + platformFee.
   * Excludes networkFee, which the wallet pays as gas on its own txs.
   */
  escrowAmount: bigint;
  /** Paid to the node for executing the transfer: nodeFee + platformFee. */
  rewardAmount: bigint;
  /** Total leaving the wallet, including the bond pot. */
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

/** A single recipient row. A plain transfer is internally a one-row batch. */
export interface TransferRow {
  tokenAddress: Address;
  recipientAddress: Address;
  amount: bigint;
}

/**
 * Secret material required to complete a deployed escrow. The blinding scalar
 * never leaves the device in shareable form: without it the node cannot be
 * authorized to bond, so a resumed transfer must supply the original value.
 */
export interface TransferSecrets {
  escrowAddress: Address;
  escrowType: EscrowKind;
  /** Per-escrow secp256k1 blinding scalar. Absent for batch escrows. */
  blindingScalar?: `0x${string}`;
  seed: string;
  selectorMapping?: Record<string, string>;
  deployHash: Hash;
  deployedAt: number;
}

export type TransferStep =
  | { step: "fees"; fees: FeeEstimate }
  /** Emitted once per distinct ERC20 requiring an allowance. */
  | { step: "approve"; hash: Hash; tokenAddress: Address; index: number; total: number }
  | {
      step: "deploy";
      hash: Hash;
      escrowAddress: Address;
      escrowType: EscrowKind;
      /** Retain to resume this transfer later; never log or share. */
      secrets: TransferSecrets;
    }
  | { step: "compliance"; approval: { signature: string; timestamp: number } }
  | { step: "signal"; response: string }
  /** Emitted incrementally as each recipient's delivery lands on chain. */
  | {
      step: "transfer";
      transfer: TransferEvent;
      row: TransferRow;
      index: number;
      total: number;
    }
  /** All recipients delivered. */
  | { step: "complete"; transfers: TransferEvent[] };

export interface PreparedTransfer {
  fees: FeeEstimate;
  execute(): AsyncGenerator<TransferStep>;
}
