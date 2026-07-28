// Public API
export { networks, createNetworkConfig } from "./networks.js";
export { prepareTransfer, executeTransfer } from "./transfer.js";
export type { TransferParams } from "./transfer.js";
export type { GasAnalysis, ApiHealth, GasHistoryAverages } from "./internal/api.js";
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
  TokenMetadata,
  GasPrice,
} from "./types.js";
