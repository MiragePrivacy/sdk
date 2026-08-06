// Public API
export { networks, createNetworkConfig, MIRAGE_MRSIGNER } from "./networks.js";
export { prepareTransfer, executeTransfer } from "./transfer.js";
export type { TransferParams } from "./transfer.js";
export type {
  ApiHealth,
  GasHistoryAverages,
  FetchNetworkKeyOptions,
} from "./internal/api.js";
export { verifyAttestation, hashAttestationPayload } from "./internal/attestation.js";
export type { VerifyAttestationOptions } from "./internal/attestation.js";
export {
  getTokenMetadata,
  getTokenBalance,
  getTokenAllowance,
  isNativeToken,
  NATIVE_TOKEN_ADDRESS,
} from "./token.js";
export {
  fetchNetworkKey,
  fetchNetworkStatus,
  nomadProxyUrl,
  fetchApiHealth,
  fetchTransferLimit,
  fetchGasHistoryAverages,
  checkWhitelist,
  checkWhitelistToken,
  isApprovalStale,
  APPROVAL_MAX_AGE_SECS,
} from "./internal/api.js";
export { getEscrowStatus, cancelTransfer } from "./internal/escrow.js";

// Errors
export {
  MirageError,
  ApiError,
  ContractError,
  TransferAbortedError,
  TransferTimeoutError,
  WhitelistRequiredError,
  MissingBlindingScalarError,
} from "./errors.js";

// Types
export type {
  NetworkId,
  NetworkKind,
  NetworkConfig,
  EscrowKind,
  FeeEstimate,
  AssetAmount,
  FeeRefreshOverrides,
  AssetRequirement,
  TransferEvent,
  TransferRow,
  TransferSecrets,
  TransferStep,
  PreparedTransfer,
  ApprovalCheckpoint,
  NetworkKeyStatus,
  AttestationPayload,
  AttestationVerification,
  TcbStatus,
  TokenMetadata,
  GasPrice,
  ExecutionApproval,
} from "./types.js";
