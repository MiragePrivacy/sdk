import { beforeEach, describe, expect, it, vi } from "vitest";
import { submitSignal } from "../src/internal/nomad.js";
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
  escrowAddress: ESCROW,
  blindingScalar: SCALAR,
  sealedPricingAuthorization: SEALED,
  executionApproval,
  nomadUrl: "http://nomad.test",
  networkKey,
};

beforeEach(() => {
  captured.payload = undefined;
  globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, text: async () => "accepted" }) as any;
});

describe("submitSignal", () => {
  it("sends only the pricing-authorized envelope", async () => {
    await submitSignal(baseParams);

    expect(captured.payload).toEqual({
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

  it("posts the ciphertext as a JSON hex string", async () => {
    await submitSignal(baseParams);
    const [url, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(url).toBe("http://nomad.test/signal");
    expect(init!.body).toBe(JSON.stringify("0x010203"));
  });
});
