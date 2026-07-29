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
   * SGX quote verification policy. Verification is on by default: without it
   * the enclave key is only asserted by whatever host answered the request.
   */
  attestation?: {
    /**
     * Set false to skip verification entirely. Only for local chains and
     * non-SGX test nodes, which serve no quote to check.
     */
    required?: boolean;
    expectedMrEnclave?: string[];
    expectedMrSigner?: string[];
    allowedTcbStatus?: TcbStatus[];
    /**
     * Accept debug-mode enclaves, whose memory is not protected and whose
     * secrets can be read by the host. Testnets only.
     */
    allowDebug?: boolean;
    maxAgeSecs?: number;
  };
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
   * Gas-token amount the wallet fronts as msg.value at deploy to fund the
   * node's bond and collect transactions. Zero for batch escrows. Refundable
   * surplus rather than a fee, so it is excluded from totalFee.
   *
   * Denominated in the chain's gas token: wei on EVM (including for ERC20
   * escrows, which pay it in ETH), token units on tempo. It is only included
   * in totalAmount when that matches the transfer's own unit, so an ERC20
   * transfer on EVM must reserve this separately.
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

/** Intel TCB evaluation outcome for the platform that produced a quote. */
export type TcbStatus =
  | "UpToDate"
  | "SWHardeningNeeded"
  | "ConfigurationNeeded"
  | "ConfigurationAndSWHardeningNeeded"
  | "OutOfDate"
  | "OutOfDateConfigurationNeeded"
  | "Revoked"
  | "Unknown";

/**
 * Data the enclave commits to by hash in the quote's report data. Untrusted
 * until the hash is reproduced during verification.
 */
export interface AttestationPayload {
  /** Compressed secp256k1 public key, hex. */
  publicKey: string;
  chainId: number;
  /** Max USD a single EOA may process in one transaction. Zero on a global report. */
  maxBalanceUsd?: number;
  /** Ed25519 compliance signer keys the enclave enforces, hex. */
  complianceKeys?: string[];
}

export interface AttestationVerification {
  verified: true;
  tcbStatus: TcbStatus;
  advisoryIds: string[];
  mrenclave: string;
  mrsigner: string;
  debug: boolean;
  /** Unix seconds the enclave generated the report at. */
  timestamp: number;
}

export interface NetworkKeyStatus {
  publicKey: string;
  /** True when the node served a quote. Says nothing about its validity. */
  attested: boolean;
  debug: boolean;
  chainId: number;
  mrenclave?: string;
  mrsigner?: string;
  /**
   * Present only when the quote was cryptographically verified and bound to
   * the served payload. Absent when verification was not requested.
   */
  verification?: AttestationVerification;
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
