import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeAbiParameters, hexToBytes, keccak256, stringToHex, type Address } from "viem";
import { ApiError, MirageError } from "../errors.js";
import type { AdmissionReceipt, NetworkKeyStatus } from "../types.js";
import { nomadProxyUrl } from "./api.js";

export const ADMISSION_RECEIPT_TYPE = "AdmissionReceipt(uint8 version,uint64 chainId,address escrowContract,bytes32 quoteCommitment,bytes32 payloadHash,uint64 acceptedAt,uint64 executeUntil,uint64 redeemUntil)";

export function admissionDigest(receipt: AdmissionReceipt): `0x${string}` {
  return keccak256(encodeAbiParameters([
    { type: "bytes32" }, { type: "uint8" }, { type: "uint64" }, { type: "address" },
    { type: "bytes32" }, { type: "bytes32" }, { type: "uint64" },
    { type: "uint64" }, { type: "uint64" },
  ], [keccak256(stringToHex(ADMISSION_RECEIPT_TYPE)), receipt.version, BigInt(receipt.chainId),
    receipt.escrowContract, receipt.quoteCommitment, receipt.payloadHash,
    BigInt(receipt.acceptedAt), BigInt(receipt.executeUntil), BigInt(receipt.redeemUntil)]));
}

export function verifyAdmissionReceipt(
  value: unknown,
  expected: { chainId: number; escrowAddress: Address; quoteCommitment: `0x${string}`; payload?: `0x${string}`; networkKey: NetworkKeyStatus },
): AdmissionReceipt {
  const invalid = () => new MirageError("INVALID_ADMISSION", "Admission receipt does not match the original authorized request");
  try {
    const receipt = value as AdmissionReceipt;
    const fields = ["version", "chainId", "escrowContract", "quoteCommitment", "payloadHash", "acceptedAt", "executeUntil", "redeemUntil", "signature"];
    if (!receipt || Object.keys(receipt).length !== fields.length || fields.some(field => !(field in receipt))) throw invalid();
    if (![receipt.chainId, receipt.acceptedAt, receipt.executeUntil, receipt.redeemUntil].every(value => Number.isSafeInteger(value) && value >= 0)
      || receipt.version !== 1 || receipt.chainId !== expected.chainId
      || receipt.escrowContract.toLowerCase() !== expected.escrowAddress.toLowerCase()
      || receipt.quoteCommitment.toLowerCase() !== expected.quoteCommitment.toLowerCase()
      || receipt.acceptedAt >= receipt.executeUntil || receipt.executeUntil >= receipt.redeemUntil
      || (expected.payload !== undefined && receipt.payloadHash.toLowerCase() !== keccak256(expected.payload))) throw invalid();
    const signature = hexToBytes(receipt.signature as `0x${string}`);
    const digest = hexToBytes(admissionDigest(receipt));
    if (!expected.networkKey.complianceKeys?.some(key => {
      try { return ed25519.verify(signature, digest, hexToBytes((key.startsWith("0x") ? key : `0x${key}`) as `0x${string}`)); }
      catch { return false; }
    })) throw invalid();
    return receipt;
  } catch { throw invalid(); }
}

/** Recover the original receipt without screening, repricing, or changing ciphertext. */
export async function lookupAdmission(params: {
  apiServer: string; chainId: number; escrowAddress: Address;
  quoteCommitment: `0x${string}`; networkKey: NetworkKeyStatus; abortSignal?: AbortSignal;
}): Promise<AdmissionReceipt | undefined> {
  const res = await fetch(`${nomadProxyUrl(params.apiServer, params.chainId)}/admission/lookup`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ escrowContract: params.escrowAddress, quoteCommitment: params.quoteCommitment }),
    signal: params.abortSignal,
  });
  if (res.status === 404) return undefined;
  if (!res.ok) throw new ApiError(res.status, `Admission lookup failed: ${await res.text().catch(() => "unknown error")}`);
  const response = await res.json() as { admissionReceipt?: unknown };
  return verifyAdmissionReceipt(response.admissionReceipt, params);
}
