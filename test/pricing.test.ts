import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  fetchApiHealth,
  fetchComplianceApproval,
  fetchCamouflage,
  fetchPricingQuote,
} from "../src/internal/api.js";
import { ApiError } from "../src/errors.js";

const SENDER = "0x0000000000000000000000000000000000000001" as const;
const TOKEN = "0x0000000000000000000000000000000000000002" as const;
const RECIPIENT = "0x0000000000000000000000000000000000000003" as const;
const SIGNER = "0x0000000000000000000000000000000000000004" as const;
const COMMITMENT = `0x${"11".repeat(32)}` as `0x${string}`;
const DEPLOY_HASH = `0x${"22".repeat(32)}` as `0x${string}`;

beforeEach(() => vi.restoreAllMocks());

describe("fetchCamouflage", () => {
  it("exposes the API-simulated deployment gas units", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        camouflaged_bytecode: "0x6000",
        original_size: 2,
        camouflaged_size: 2,
        gas_analysis: { camouflaged_gas_estimate: 1_234_567 },
      }),
    }) as any;

    await expect(fetchCamouflage("https://api.test", "batch")).resolves.toMatchObject({
      deploymentGasEstimate: 1_234_567n,
    });
  });
});

describe("fetchPricingQuote", () => {
  it("sends the selected escrow type, signers, and Signals", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        chain_id: 1,
        service_fee: { asset: TOKEN, amount: "25" },
        deployment: {
          escrow_type: "erc20",
          constructor_args: "0x1234",
          quote_commitment: COMMITMENT,
          reward_asset: TOKEN,
          reward_amount: "25",
          deposit_by_asset: { [TOKEN]: "1025" },
          msg_value: "0",
        },
        sealed_pricing_authorization: "0xabcd",
      }),
    }) as any;

    const signals = [
      {
        asset: TOKEN,
        execution_mode: "private" as const,
        items: [{ client_row_id: "row-0", recipient: RECIPIENT, amount: "1000" }],
      },
    ];
    const quote = await fetchPricingQuote("https://api.test", {
      chainId: 1,
      sender: SENDER,
      escrowType: "erc20",
      blindedSigners: [SIGNER],
      signals,
      ...({ accessToken: "legacy-token" } as Record<string, unknown>),
    });

    expect(quote.serviceFee.amount).toBe(25n);
    expect(quote.deployment.depositByAsset[TOKEN]).toBe(1025n);
    expect(quote.deployment.constructorArgs).toBe("0x1234");
    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(JSON.parse(String(init!.body))).toEqual({
      chain_id: 1,
      sender: SENDER,
      escrow_type: "erc20",
      blinded_signers: [SIGNER],
      signals,
    });
  });
});

describe("fetchComplianceApproval", () => {
  it("binds compliance to the issued quote commitment", async () => {
    const approval = {
      version: 1,
      chainId: 1,
      escrowContract: SENDER,
      deploymentTxHash: DEPLOY_HASH,
      runtimeCodeHash: `0x${"33".repeat(32)}` as `0x${string}`,
      quoteCommitment: COMMITMENT,
      approvedAt: 1_700_000_000,
      signature: `0x${"44".repeat(64)}`,
    };
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => approval }) as any;

    await expect(
      fetchComplianceApproval("https://api.test", {
        txHash: DEPLOY_HASH,
        chainId: 1,
        seed: `0x${"55".repeat(32)}`,
        escrowType: "batch",
        quoteCommitment: COMMITMENT,
        screeningReceipts: [],
      }),
    ).resolves.toEqual(approval);

    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(JSON.parse(String(init!.body))).toMatchObject({
      escrow_type: "batch",
      quote_commitment: COMMITMENT,
    });
  });
});

describe("removed early-access gate", () => {
  it("does not expose legacy whitelist health metadata", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: "ok", max_tx_usd: { "1": 10000 }, whitelist_required_usd: { "1": 1000 } }),
    }) as any;
    await expect(fetchApiHealth("https://api.test")).resolves.toEqual({
      status: "ok", version: undefined, maxTransferUsd: { "1": "10000" },
    });
  });

  it("preserves policy rejections from signed pricing", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false, status: 403,
      text: async () => JSON.stringify({ error: "Transfer exceeds configured limit" }),
    }) as any;
    const request = fetchPricingQuote("https://api.test", {
      chainId: 1, sender: SENDER, escrowType: "erc20", blindedSigners: [SIGNER], signals: [],
    });
    await expect(request).rejects.toBeInstanceOf(ApiError);
    await expect(request).rejects.toMatchObject({ code: "API_ERROR", statusCode: 403 });
  });
});
