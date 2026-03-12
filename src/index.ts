// Public API
export { networks, createNetworkConfig } from "./networks.js";
export { prepareTransfer } from "./transfer.js";
export type { TransferParams } from "./transfer.js";
export type { GasAnalysis } from "./internal/api.js";
export {
  getTokenMetadata,
  getTokenBalance,
  getTokenAllowance,
  isNativeToken,
  NATIVE_TOKEN_ADDRESS,
} from "./token.js";
export { fetchNetworkKey, fetchApiHealth, fetchTransferLimit } from "./internal/api.js";

// Errors
export {
  MirageError,
  ApiError,
  ContractError,
  TransferAbortedError,
  TransferTimeoutError,
  TransferLimitError,
} from "./errors.js";

// Types
export type {
  NetworkId,
  NetworkKind,
  NetworkConfig,
  GasConstants,
  FeeEstimate,
  TransferEvent,
  TransferStep,
  PreparedTransfer,
  NetworkKeyStatus,
  TokenMetadata,
  GasPrice,
} from "./types.js";
