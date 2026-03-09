// Public API
export { networks, createNetworkConfig } from "./networks.js";
export { prepareTransfer, executeTransfer } from "./transfer.js";
export type { TransferParams } from "./transfer.js";
export {
  getTokenMetadata,
  getTokenBalance,
  getTokenAllowance,
  isNativeToken,
  NATIVE_TOKEN_ADDRESS,
} from "./token.js";
export { fetchNetworkKey, fetchApiHealth } from "./internal/api.js";

// Errors
export {
  MirageError,
  ApiError,
  ContractError,
  TransferAbortedError,
  TransferTimeoutError,
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
  NetworkKeyStatus,
  TokenMetadata,
  GasPrice,
} from "./types.js";
