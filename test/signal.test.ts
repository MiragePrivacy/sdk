import { beforeEach, describe, expect, it, vi } from "vitest";
import { submitSignal } from "../src/internal/nomad.js";
import { complianceKey, signedAdmission } from "./helpers/admission.js";
import { nomadProxyUrl } from "../src/internal/api.js";
import { MissingBlindingScalarError } from "../src/errors.js";
import type { ExecutionApproval, NetworkKeyStatus } from "../src/types.js";

const ESCROW = "0x00000000000000000000000000000000000000ff" as const;
const SCALAR = `0x${"ab".repeat(32)}` as `0x${string}`;
const SEALED = `0x${"cd".repeat(32)}` as `0x${string}`;
const COMMITMENT = `0x${"11".repeat(32)}` as `0x${string}`;
const DEPLOY_HASH = `0x${"22".repeat(32)}` as `0x${string}`;
const RUNTIME_HASH = `0x${"33".repeat(32)}` as `0x${string}`;

const captured: { payload?: Record<string, unknown> } = {};

vi.mock("eciesjs", () => ({
  encrypt: (_key: string, data: Uint8Array) => {
    captured.payload = JSON.parse(new TextDecoder().decode(data));
    return new Uint8Array([1, 2, 3]);
  },
}));

const networkKey: NetworkKeyStatus = {
  publicKey: `0x${"02".repeat(33)}`,
  complianceKeys: [complianceKey],
  attested: true,
  debug: false,
  chainId: 1,
};

const executionApproval: ExecutionApproval = {
  version: 1,
  chainId: 1,
  escrowContract: ESCROW,
  deploymentTxHash: DEPLOY_HASH,
  runtimeCodeHash: RUNTIME_HASH,
  quoteCommitment: COMMITMENT,
  approvedAt: 1_700_000_000,
  signature: `0x${"44".repeat(64)}`,
};

const baseParams = {
  seed: `0x${"77".repeat(32)}`,
  escrowType: "batch" as const,
  escrowAddress: ESCROW,
  blindingScalar: SCALAR,
  sealedPricingAuthorization: SEALED,
  executionApproval,
  apiServer: "http://api.test",
  chainId: 31337,
  networkKey,
};

beforeEach(() => {
  captured.payload = undefined;
  globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ status: "admitted", admissionReceipt: signedAdmission() }) }) as any;
});

describe("submitSignal", () => {
  it("sends only the pricing-authorized envelope", async () => {
    await submitSignal(baseParams);

    expect(captured.payload).toEqual({
      escrowType: "batch",
      escrowContract: ESCROW,
      blindingScalar: SCALAR,
      sealedPricingAuthorization: SEALED,
      executionApproval,
    });
    expect(captured.payload).not.toHaveProperty("transfers");
    expect(captured.payload).not.toHaveProperty("rewardAmount");
    expect(captured.payload).not.toHaveProperty("platformFee");
  });

  it("includes optional selector and metrics fields without changing economics", async () => {
    await submitSignal({
      ...baseParams,
      selectorMapping: { "0x12345678": "0x87654321" },
      deployedAt: 1_700_000_001,
      userApproveGas: 46_686n,
      userDeployGas: 2_167_182n,
      userGasPrice: 30_000_000_000n,
    });

    expect(captured.payload).toMatchObject({
      selectorMapping: { "0x12345678": "0x87654321" },
      deployedAt: 1_700_000_001,
      userApproveGas: 46_686,
      userDeployGas: 2_167_182,
      userGasPrice: 30_000_000_000,
    });
  });

  it("requires the batch base scalar before any network call", async () => {
    await expect(
      submitSignal({ ...baseParams, blindingScalar: "" as `0x${string}` }),
    ).rejects.toBeInstanceOf(MissingBlindingScalarError);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("posts ciphertext with the original approval and deployment seed", async () => {
    await submitSignal(baseParams);
    const [url, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(url).toBe("http://api.test/nomad/31337/signal");
    expect(JSON.parse(String(init!.body))).toEqual({ payload: "0x010203", executionApproval, seed: baseParams.seed, escrowType: "batch" });
  });

  it("retries a lost admission response with the same ciphertext", async () => {
    vi.mocked(globalThis.fetch).mockRejectedValueOnce(new TypeError("connection lost"));
    await submitSignal(baseParams);
    const calls = vi.mocked(globalThis.fetch).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls[0][1]!.body).toBe(calls[1][1]!.body);
  });

  it("rejects a receipt for different ciphertext", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce({ ok: true, json: async () => ({ admissionReceipt: signedAdmission({}, "0x040506") }) } as Response);
    await expect(submitSignal(baseParams)).rejects.toMatchObject({ code: "INVALID_ADMISSION" });
  });
});

describe("nomadProxyUrl", () => {
  it("builds the per-chain proxy base", () => {
    expect(nomadProxyUrl("https://api.mirageprivacy.com", 1)).toBe(
      "https://api.mirageprivacy.com/nomad/1",
    );
  });

  it("does not double up the separator on a trailing slash", () => {
    expect(nomadProxyUrl("http://api.test/", 31337)).toBe("http://api.test/nomad/31337");
  });
});
