import type { Address, Hash } from "viem";

export class MirageError extends Error {
  code: string;
  declare cause?: unknown;
  meta?: Record<string, unknown>;

  constructor(code: string, message: string, options?: { cause?: unknown; meta?: Record<string, unknown> }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "MirageError";
    this.code = code;
    this.meta = options?.meta;
  }
}

export class ApiError extends MirageError {
  statusCode: number;
  body?: unknown;

  constructor(statusCode: number, message: string, body?: unknown) {
    super("API_ERROR", message, { cause: body });
    this.name = "ApiError";
    this.statusCode = statusCode;
    this.body = body;
  }
}

export class ContractError extends MirageError {
  txHash?: Hash;

  constructor(message: string, options?: { cause?: unknown; txHash?: Hash }) {
    super("CONTRACT_ERROR", message, { cause: options?.cause });
    this.name = "ContractError";
    this.txHash = options?.txHash;
  }
}

export class TransferAbortedError extends MirageError {
  escrowAddress?: Address;
  withdrawHash?: Hash;
  withdrawError?: unknown;

  constructor(options?: {
    escrowAddress?: Address;
    withdrawHash?: Hash;
    withdrawError?: unknown;
  }) {
    super("TRANSFER_ABORTED", "Transfer was aborted");
    this.name = "TransferAbortedError";
    this.escrowAddress = options?.escrowAddress;
    this.withdrawHash = options?.withdrawHash;
    this.withdrawError = options?.withdrawError;
  }
}

export class TransferTimeoutError extends MirageError {
  constructor(timeoutMs: number) {
    super("TRANSFER_TIMEOUT", `Transfer did not complete within ${timeoutMs}ms`);
    this.name = "TransferTimeoutError";
  }
}
