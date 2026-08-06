import type { Address } from "viem";
import { ApiError, MissingBlindingScalarError } from "../errors.js";
import type { ExecutionApproval, NetworkKeyStatus } from "../types.js";

async function encryptSignal(payload: Uint8Array, publicKeyHex: string): Promise<Uint8Array> {
  const { encrypt } = await import("eciesjs");
  return encrypt(publicKeyHex.replace(/^0x/, ""), payload) as unknown as Uint8Array;
}

function toHexString(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export interface SignalParams {
  escrowAddress: Address;
  blindingScalar: `0x${string}`;
  sealedPricingAuthorization: `0x${string}`;
  executionApproval: ExecutionApproval;
  selectorMapping?: Record<string, string>;
  deployedAt?: number;
  userApproveGas?: bigint;
  userDeployGas?: bigint;
  userGasPrice?: bigint;
  nomadUrl: string;
  networkKey: NetworkKeyStatus;
}

/** Encrypt and submit the minimal pricing-authorized Signal envelope. */
export async function submitSignal(params: SignalParams): Promise<string> {
  if (!params.blindingScalar) {
    throw new MissingBlindingScalarError(params.escrowAddress);
  }

  const signal = {
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
  const res = await fetch(`${params.nomadUrl}/signal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(`0x${toHexString(encrypted)}`),
  });

  if (!res.ok) {
    const errorText = await res.text().catch(() => "unknown error");
    throw new ApiError(res.status, `Signal submission failed: ${errorText}`);
  }

  return res.text();
}
