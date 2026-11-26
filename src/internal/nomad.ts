import type { Address } from "viem";
import { ApiError, MissingBlindingScalarError } from "../errors.js";
import { nomadProxyUrl } from "./api.js";
import type { EscrowKind, ExecutionApproval, NetworkKeyStatus } from "../types.js";
import { lookupAdmission, verifyAdmissionReceipt } from "./admission.js";

async function encryptSignal(payload: Uint8Array, publicKeyHex: string): Promise<Uint8Array> {
  const ecies = await import("eciesjs");
  // Vite can expose this CommonJS dependency as a default-only namespace.
  const { encrypt } = typeof ecies.encrypt === "function"
    ? ecies
    : ((ecies as unknown as { default: typeof ecies }).default ?? ecies);
  return encrypt(publicKeyHex.replace(/^0x/, ""), payload) as unknown as Uint8Array;
}

function toHexString(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export interface SignalParams {
  seed: string;
  escrowType: EscrowKind;
  escrowAddress: Address;
  blindingScalar: `0x${string}`;
  sealedPricingAuthorization: `0x${string}`;
  executionApproval: ExecutionApproval;
  selectorMapping?: Record<string, string>;
  deployedAt?: number;
  userApproveGas?: bigint;
  userDeployGas?: bigint;
  userGasPrice?: bigint;
  apiServer: string;
  chainId: number;
  networkKey: NetworkKeyStatus;
  abortSignal?: AbortSignal;
}

/** Encrypt and submit the minimal pricing-authorized Signal envelope. */
export async function submitSignal(params: SignalParams): Promise<string> {
  if (!params.blindingScalar) {
    throw new MissingBlindingScalarError(params.escrowAddress);
  }

  const signal = {
    escrowType: params.escrowType,
    escrowContract: params.escrowAddress,
    blindingScalar: params.blindingScalar,
    sealedPricingAuthorization: params.sealedPricingAuthorization,
    executionApproval: params.executionApproval,
    ...(params.selectorMapping ? { selectorMapping: params.selectorMapping } : {}),
    ...(params.deployedAt !== undefined ? { deployedAt: params.deployedAt } : {}),
    ...(params.userApproveGas !== undefined
      ? { userApproveGas: Number(params.userApproveGas) }
      : {}),
    ...(params.userDeployGas !== undefined
      ? { userDeployGas: Number(params.userDeployGas) }
      : {}),
    ...(params.userGasPrice !== undefined ? { userGasPrice: Number(params.userGasPrice) } : {}),
  };

  const encrypted = await encryptSignal(
    new TextEncoder().encode(JSON.stringify(signal)),
    params.networkKey.publicKey,
  );
  const payload = `0x${toHexString(encrypted)}` as `0x${string}`;
  // Reuse the exact ciphertext if a connection fails after durable admission.
  const body = JSON.stringify({ payload, executionApproval: params.executionApproval,
    seed: params.seed, escrowType: params.escrowType });
  const request = () => fetch(`${nomadProxyUrl(params.apiServer, params.chainId)}/signal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
    signal: params.abortSignal,
  });
  let res: Response | undefined;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      res = await request();
      if (![502, 503, 504].includes(res.status) || attempt === 2) break;
    } catch (error) {
      if (params.abortSignal?.aborted || attempt === 2) throw error;
    }
  }
  if (!res) throw new ApiError(503, "Signal admission unavailable");
  if (res.status === 409) {
    // Another call may already have admitted this exact authorized request.
    const existing = await lookupAdmission({ ...params, quoteCommitment: params.executionApproval.quoteCommitment });
    if (existing) return JSON.stringify({ status: "admitted", admissionReceipt: existing });
  }
  if (!res.ok) {
    const errorText = await res.text().catch(() => "unknown error");
    throw new ApiError(res.status, `Signal submission failed: ${errorText}`);
  }

  const response = await res.json() as { status: string; admissionReceipt: unknown };
  verifyAdmissionReceipt(response.admissionReceipt, {
    ...params, quoteCommitment: params.executionApproval.quoteCommitment, payload,
  });
  return JSON.stringify(response);
}
