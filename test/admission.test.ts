import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { admissionDigest, lookupAdmission, verifyAdmissionReceipt } from "../src/internal/admission.js";
import type { AdmissionReceipt } from "../src/types.js";
import { complianceKey, signedAdmission } from "./helpers/admission.js";
const vector = JSON.parse(readFileSync(new URL("./vectors/admission-receipt.json", import.meta.url), "utf8"));
const expected = { chainId: vector.receipt.chainId, escrowAddress: vector.receipt.escrowContract,
  quoteCommitment: vector.receipt.quoteCommitment, payload: vector.payload,
  networkKey: { publicKey: "", complianceKeys: [vector.publicKey], attested: true, debug: false, chainId: vector.receipt.chainId } };

afterEach(() => vi.unstubAllGlobals());

describe("immutable admission receipts", () => {
  it("matches the canonical Rust signing vector", () => {
    expect(admissionDigest(vector.receipt)).toBe(vector.digest);
    expect(verifyAdmissionReceipt(vector.receipt, expected)).toEqual(vector.receipt);
  });
  it.each(["version", "chainId", "escrowContract", "quoteCommitment", "payloadHash", "acceptedAt", "executeUntil", "redeemUntil", "signature"])("rejects tampered %s", field => {
    const changed = { ...vector.receipt, [field]: typeof vector.receipt[field] === "number" ? vector.receipt[field]+1 : "0x"+"33".repeat(field === "escrowContract" ? 20 : field === "signature" ? 64 : 32) };
    expect(() => verifyAdmissionReceipt(changed, expected)).toThrow();
  });
  it("rejects an untrusted signer and economic overrides", () => {
    expect(() => verifyAdmissionReceipt(vector.receipt, { ...expected, networkKey: { ...expected.networkKey, complianceKeys: [] } })).toThrow();
    expect(() => verifyAdmissionReceipt({ ...vector.receipt, rewardAmount: "0" }, expected)).toThrow();
  });
  it("recovers an old receipt without imposing quote freshness again", async () => {
    const receipt = signedAdmission();
    const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: "admitted", admissionReceipt: receipt }) });
    vi.stubGlobal("fetch", fetch);
    const result = await lookupAdmission({ apiServer: "https://api.test", chainId: 31337,
      escrowAddress: receipt.escrowContract, quoteCommitment: receipt.quoteCommitment,
      networkKey: { publicKey: "", complianceKeys: [complianceKey], attested: true, debug: true, chainId: 31337 } });
    expect(result).toEqual(receipt);
    expect(fetch).toHaveBeenCalledOnce();
    expect(String(fetch.mock.calls[0][0])).toMatch(/admission\/lookup$/);
  });
  it("returns absence only on 404 and propagates outages", async () => {
    const receipt = signedAdmission();
    const params = { apiServer: "https://api.test", chainId: 31337, escrowAddress: receipt.escrowContract,
      quoteCommitment: receipt.quoteCommitment, networkKey: expected.networkKey };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce({ status: 404 }).mockResolvedValueOnce({ status: 503, text: async () => "offline" }));
    expect(await lookupAdmission(params)).toBeUndefined();
    await expect(lookupAdmission(params)).rejects.toMatchObject({ statusCode: 503 });
  });
});
