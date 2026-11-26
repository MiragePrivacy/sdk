import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes, keccak256, toHex, type Address } from "viem";
import { admissionDigest } from "../../src/internal/admission.js";
import type { AdmissionReceipt } from "../../src/types.js";
const key = new Uint8Array(32).fill(7);
export const complianceKey = toHex(ed25519.getPublicKey(key));
export function signedAdmission(overrides: Partial<AdmissionReceipt> = {}, payload: `0x${string}` = "0x010203"): AdmissionReceipt {
  const receipt: AdmissionReceipt = {
    version: 1, chainId: 31337,
    escrowContract: "0x00000000000000000000000000000000000000ff" as Address,
    quoteCommitment: `0x${"11".repeat(32)}`,
    payloadHash: keccak256(payload), acceptedAt: 1700000060,
    executeUntil: 1700000900, redeemUntil: 1700001800, signature: "",
    ...overrides,
  };
  receipt.signature = toHex(ed25519.sign(hexToBytes(admissionDigest(receipt)), key));
  return receipt;
}
