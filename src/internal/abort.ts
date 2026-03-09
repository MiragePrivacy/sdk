import { TransferAbortedError } from "../errors.js";
import type { Address, Hash } from "viem";

export function checkAbort(
  signal: AbortSignal | undefined,
  context?: {
    escrowAddress?: Address;
    withdrawHash?: Hash;
    withdrawError?: unknown;
  },
): void {
  if (signal?.aborted) {
    throw new TransferAbortedError(context);
  }
}
