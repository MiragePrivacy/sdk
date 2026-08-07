import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  fetchComplianceApproval,
  fetchObfuscation,
  fetchPricingQuote,
  whitelistRequirementFromError,
} from "../src/internal/api.js";
import { ApiError } from "../src/errors.js";

const SENDER = "0x0000000000000000000000000000000000000001" as const;
const TOKEN = "0x0000000000000000000000000000000000000002" as const;
const RECIPIENT = "0x0000000000000000000000000000000000000003" as const;
const SIGNER = "0x0000000000000000000000000000000000000004" as const;
const COMMITMENT = `0x${"11".repeat(32)}` as `0x${string}`;
const DEPLOY_HASH = `0x${"22".repeat(32)}` as `0x${string}`;

beforeEach(() => vi.restoreAllMocks());

describe("fetchObfuscation", () => {
  it("exposes the API-simulated deployment gas units", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        obfuscated_bytecode: "0x6000",
        original_size: 2,
        obfuscated_size: 2,
        gas_analysis: { obfuscated_gas_estimate: 1_234_567 },
      }),
    }) as any;

    await expect(fetchObfuscation("https://api.test", "batch")).resolves.toMatchObject({
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
      }),
    ).resolves.toEqual(approval);

    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(JSON.parse(String(init!.body))).toMatchObject({
      escrow_type: "batch",
      quote_commitment: COMMITMENT,
    });
  });
});

describe("whitelistRequirementFromError", () => {
  it("extracts the API-calculated amount and configured threshold", () => {
    const error = new ApiError(
      403,
      "Caller is not whitelisted for transactions above $1000",
      {
        error: "Caller is not whitelisted for transactions above $1000",
        details: "transaction_value_usd=~$1,250.50",
      },
    );

    expect(whitelistRequirementFromError(error)).toEqual({
      amountUsd: 1_250.5,
      thresholdUsd: 1_000,
    });
  });

  it("does not classify unrelated forbidden responses as whitelist failures", () => {
    expect(
      whitelistRequirementFromError(new ApiError(403, "Predicate screening failed")),
    ).toBeUndefined();
  });
});
