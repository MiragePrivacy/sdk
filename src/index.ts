// Public API
export { networks, createNetworkConfig, MIRAGE_MRSIGNER } from "./networks.js";
export { prepareTransfer, executeTransfer } from "./transfer.js";
export type { TransferParams } from "./transfer.js";
export type {
  GasAnalysis,
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
  fetchApiHealth,
  fetchTransferLimit,
  fetchGasHistoryAverages,
  checkWhitelist,
  isApprovalStale,
  APPROVAL_MAX_AGE_SECS,
} from "./internal/api.js";

// Errors
export {
  MirageError,
  ApiError,
  ContractError,
  TransferAbortedError,
  TransferTimeoutError,
  TransferLimitError,
  WhitelistRequiredError,
  MissingBlindingScalarError,
} from "./errors.js";

// Types
export type {
  NetworkId,
  NetworkKind,
  NetworkConfig,
  EscrowKind,
  GasConstants,
  NativeGasConstants,
  FeeEstimate,
  TransferEvent,
  TransferRow,
  TransferSecrets,
  TransferStep,
  PreparedTransfer,
  NetworkKeyStatus,
  AttestationPayload,
  AttestationVerification,
  TcbStatus,
  TokenMetadata,
  GasPrice,
} from "./types.js";
