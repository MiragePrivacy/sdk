import type { Address, Hash, WalletClient } from "viem";

export type NetworkId = "sepolia" | "tempo" | "ethereum";
export type NetworkKind = "ethereum" | "tempo";

/**
 * Escrow variant. Determines the deployed bytecode, constructor shape, and is
 * cross-validated by the node against the signal's reward token.
 */
export type EscrowKind = "erc20" | "native" | "batch";

export interface NetworkConfig {
  id: NetworkId;
  kind: NetworkKind;
  chainId: number;
  rpcUrl: string;
  /**
   * API server base. Attestation and signal submission go through its nomad
   * proxy at `/nomad/{chainId}`, so nodes are never contacted directly.
   */
  apiServer: string;
  /** Submit exact quoted approvals and deployment as one native call vector (Tempo). */
  enableAtomicBatch: boolean;
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
    /**
     * Pin the enclave's signing identity. MRENCLAVE is not pinned, since it
     * changes on every enclave rebuild.
     */
    expectedMrSigner?: string[];
    allowedTcbStatus?: TcbStatus[];
    /**
     * Reject a quote if Intel reports an advisory outside this allowlist.
     * An empty list requires a quote with no advisory IDs.
     */
    allowedAdvisoryIds?: string[];
    /**
     * Minimum enclave security version. Releases must bump ISVSVN whenever a
     * security-relevant enclave fix is required by policy.
     */
    minimumIsvSvn?: number;
    /**
     * Accept debug-mode enclaves, whose memory is not protected and whose
     * secrets can be read by the host. Testnets only.
     */
    allowDebug?: boolean;
    maxAgeSecs?: number;
  };
}

export interface FeeEstimate {
  /** Single public fee quoted by the API; no node/platform split is exposed. */
  serviceFee: AssetAmount;
  /** Sum of gas units for every exact ERC-20 approval required by the quote. */
  approvalGasEstimate?: bigint;
  /** API-simulated gas units for deploying the obfuscated escrow. */
  deploymentGasEstimate?: bigint;
  /** Complete wallet gas units: approvals plus escrow deployment. */
  totalWalletGasEstimate?: bigint;
  /** Escrow reward denomination selected from the first ordered Signal. */
  rewardAsset: Address;
  /** Complete reward pot; equal to the public service fee amount. */
  rewardAmount: bigint;
  /**
   * Exact amount of each asset the API requires for principal plus the reward
   * pot. ERC-20 entries are approved; the native entry is sent as msg.value.
   */
  depositByAsset: Record<string, bigint>;
  msgValue: bigint;
  assetRequirements: AssetRequirement[];
}

/**
 * Display-only fees for a transfer with no committed sender. Carries the same
 * API-authored economics and wallet gas as a quoted transfer, but omits every
 * deployable field. Re-quote with `prepareTransfer` once a wallet is
 * connected: the sender is committed into the real quote, so a preview can
 * never be executed.
 */
export interface TransferPreview {
  serviceFee: AssetAmount;
  /**
   * Sum of gas units for every exact ERC-20 approval, simulated against a
   * stand-in sender. Present only when a `publicClient` was supplied.
   */
  approvalGasEstimate?: bigint;
  /** API-simulated gas units for deploying the obfuscated escrow. */
  deploymentGasEstimate?: bigint;
  /** Complete wallet gas units: approvals plus escrow deployment. */
  totalWalletGasEstimate?: bigint;
  rewardAsset: Address;
  rewardAmount: bigint;
  depositByAsset: Record<string, bigint>;
  msgValue: bigint;
  assetRequirements: AssetRequirement[];
}

export interface AssetAmount {
  asset: Address;
  amount: bigint;
}

export interface AssetRequirement {
  tokenAddress: Address;
  transferAmount: bigint;
  escrowAmount: bigint;
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
  /** Ed25519 pricing signer keys the enclave enforces, hex. */
  pricingKeys?: string[];
}

export interface AttestationVerification {
  verified: true;
  tcbStatus: TcbStatus;
  advisoryIds: string[];
  mrenclave: string;
  mrsigner: string;
  /** Enclave security version from the verified SGX report. */
  isvSvn: number;
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

/** One recipient transfer. A one-row request uses a single escrow. */
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
  /** Scalar used for a single signer or the batch's ordered one-time bid signers. */
  blindingScalar: `0x${string}`;
  seed: string;
  selectorMapping?: Record<string, string>;
  deployHash: Hash;
  deployedAt: number;
  /** Deployment block used as the recovery polling cursor. */
  fromBlock?: bigint;
  userApproveGas?: bigint;
  userDeployGas?: bigint;
  userGasPrice?: bigint;
  /** Reward committed in the deployed escrow; required for exact resume. */
  rewardAmount: bigint;
  rewardAsset: Address;
  quoteCommitment: `0x${string}`;
  /** Opaque API authorization encrypted directly for Nomad. */
  sealedPricingAuthorization: `0x${string}`;
  serviceFee: AssetAmount;
  depositByAsset: Record<string, bigint>;
  msgValue: bigint;
  /** Sender address signed into the pricing authorization. */
  senderAddress: Address;
}

export interface ApprovalCheckpoint {
  stage: "approved";
  account: Address;
  predictedEscrowAddress: Address;
  approvals: Array<{ hash: Hash; tokenAddress: Address; gasUsed: bigint }>;
  approveGasUsed: bigint;
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
  | { step: "compliance"; approval: ExecutionApproval }
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

export interface FeeRefreshOverrides {
  /** Updated EIP-1559 recommendation for wallet transactions; it does not alter quoted fees. */
  gasPrice?: GasPrice;
  /** @deprecated Pricing inputs are owned by the API and cannot be overridden. */
  ethToTokenRate?: number;
}

export interface ExecutionApproval {
  version: number;
  chainId: number;
  escrowContract: Address;
  deploymentTxHash: `0x${string}`;
  runtimeCodeHash: `0x${string}`;
  quoteCommitment: `0x${string}`;
  approvedAt: number;
  signature: string;
}

export interface PreparedTransfer {
  fees: FeeEstimate;
  /**
   * Re-estimate fees from the prepared context without refetching metadata,
   * limits, or bytecode. Makes no network calls when both overrides are
   * supplied. Throws once approval has begun, since the reward amount is
   * baked into the allowances.
   */
  refreshFees(overrides?: FeeRefreshOverrides): Promise<FeeEstimate>;
  /**
   * Replace transfer amounts and recipients, reusing the prepared context.
   * The token layout is fixed at preparation: same row count and the same
   * token per row, since the cached metadata, escrow kind, and bytecode all
   * derive from it. Re-checks limits and re-estimates fees without network
   * calls when overrides are supplied. Throws once approval has begun.
   */
  updateTransfers(transfers: TransferRow[], overrides?: FeeRefreshOverrides): Promise<FeeEstimate>;
  approve(walletClient: WalletClient): AsyncGenerator<TransferStep, ApprovalCheckpoint>;
  deploy(
    walletClient: WalletClient,
    checkpoint?: ApprovalCheckpoint,
  ): Promise<Extract<TransferStep, { step: "deploy" }>>;
  complete(
    walletClient: WalletClient,
    secrets?: TransferSecrets,
  ): AsyncGenerator<TransferStep>;
  execute(walletClient?: WalletClient): AsyncGenerator<TransferStep>;
}
