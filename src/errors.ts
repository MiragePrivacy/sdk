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

export class TransferLimitError extends MirageError {
  amountUsd: number;
  limitUsd: number;
  /** Index of the offending row. Limits apply per transfer, not per batch. */
  rowIndex: number;

  constructor(amountUsd: number, limitUsd: number, rowIndex = 0) {
    super(
      "TRANSFER_LIMIT_EXCEEDED",
      `Transfer amount $${amountUsd} exceeds network limit of $${limitUsd}`,
      { meta: { rowIndex } },
    );
    this.name = "TransferLimitError";
    this.amountUsd = amountUsd;
    this.limitUsd = limitUsd;
    this.rowIndex = rowIndex;
  }
}

/**
 * Thrown when a transfer exceeds the network's whitelist threshold and no
 * valid access token was supplied. Callers should run the whitelist flow and
 * retry with the resulting token.
 */
export class WhitelistRequiredError extends MirageError {
  amountUsd: number;
  thresholdUsd: number;

  constructor(amountUsd: number, thresholdUsd: number) {
    super(
      "WHITELIST_REQUIRED",
      `Transfers above $${thresholdUsd} require whitelist verification (amount: $${amountUsd})`,
      { meta: { amountUsd, thresholdUsd } },
    );
    this.name = "WhitelistRequiredError";
    this.amountUsd = amountUsd;
    this.thresholdUsd = thresholdUsd;
  }
}

/**
 * Thrown when a priced EscrowBatch is resumed without its base blinding
 * scalar. Nomad cannot derive the constructor's one-time bid signers without
 * it, so completion must use the secrets retained at deployment.
 */
export class MissingBlindingScalarError extends MirageError {
  escrowAddress?: Address;

  constructor(escrowAddress?: Address) {
    super(
      "MISSING_BLINDING_SCALAR",
      "Missing blinding scalar for this escrow. Resume the transfer on the device that deployed it.",
      { meta: { escrowAddress } },
    );
    this.name = "MissingBlindingScalarError";
    this.escrowAddress = escrowAddress;
  }
}
