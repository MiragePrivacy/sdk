import type { Address } from "viem";
import { ApiError } from "../errors.js";
import type { NetworkKeyStatus } from "../types.js";

async function encryptSignal(
  payload: Uint8Array,
  publicKeyHex: string,
): Promise<Uint8Array> {
  const { encrypt } = await import("eciesjs");
  // Strip 0x prefix if present
  const keyHex = publicKeyHex.replace(/^0x/, "");
  return encrypt(keyHex, payload) as unknown as Uint8Array;
}

function toHexString(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface SignalParams {
  escrowAddress: Address;
  recipientAddress: Address;
  transferAmount: bigint;
  rewardAmount: bigint;
  tokenAddress: Address;
  selectorMapping?: Record<string, string>;
  complianceSignature?: string;
  complianceTimestamp?: number;
  nomadUrl: string;
  networkKey: NetworkKeyStatus;
}

export async function submitSignal(params: SignalParams): Promise<string> {
  const {
    escrowAddress,
    recipientAddress,
    transferAmount,
    rewardAmount,
    tokenAddress,
    selectorMapping,
    complianceSignature,
    complianceTimestamp,
    nomadUrl,
    networkKey,
  } = params;

  const signal: Record<string, unknown> = {
    escrowContract: escrowAddress,
    tokenContract: tokenAddress,
    recipient: recipientAddress,
    transferAmount: transferAmount.toString(),
    rewardAmount: rewardAmount.toString(),
    selectorMapping: selectorMapping ?? null,
    approval: complianceSignature
      ? { signature: complianceSignature, timestamp: complianceTimestamp }
      : null,
  };

  const signalJson = JSON.stringify(signal);
  const signalBytes = new TextEncoder().encode(signalJson);

  const encrypted = await encryptSignal(signalBytes, networkKey.publicKey);
  const encryptedHex = "0x" + toHexString(encrypted);

  // Submit as JSON-encoded hex string (matches nomad API expectation)
  const res = await fetch(`${nomadUrl}/signal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(encryptedHex),
  });

  if (!res.ok) {
    const errorText = await res.text().catch(() => "unknown error");
    throw new ApiError(res.status, `Signal submission failed: ${errorText}`);
  }

  return res.text();
}
