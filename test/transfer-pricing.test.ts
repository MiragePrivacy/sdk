import { beforeEach, describe, expect, it, vi } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { prepareTransfer } from "../src/transfer.js";
import { createNetworkConfig } from "../src/networks.js";
import { NATIVE_TOKEN_ADDRESS } from "../src/token.js";

const SENDER = "0x0000000000000000000000000000000000000001" as const;
const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;
const RECIPIENT_A = "0x0000000000000000000000000000000000000011" as const;
const RECIPIENT_B = "0x0000000000000000000000000000000000000012" as const;
const COMMITMENT = `0x${"11".repeat(32)}` as `0x${string}`;
const DEPLOY_HASH = `0x${"22".repeat(32)}` as `0x${string}`;

const VALID_RESUME = {
  escrowAddress: SENDER,
  escrowType: "batch" as const,
  blindingScalar: `0x${"33".repeat(32)}` as `0x${string}`,
  seed: `0x${"44".repeat(32)}`,
  deployHash: DEPLOY_HASH,
  deployedAt: 1_700_000_000,
  rewardAmount: 25n,
  rewardAsset: USDC,
  quoteCommitment: COMMITMENT,
  sealedPricingAuthorization: "0xabcd" as `0x${string}`,
  serviceFee: { asset: USDC, amount: 25n },
  depositByAsset: { [USDC]: 125n },
  msgValue: 0n,
  senderAddress: SENDER,
};

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

const networkKey = `0x${toHex(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true))}`;
let pricingBody: any;
let attestedChainId: number;
let attestUrl: string | undefined;

beforeEach(() => {
  pricingBody = undefined;
  attestedChainId = 31337;
  attestUrl = undefined;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/attest")) {
      attestUrl = url;
      return {
        ok: true,
        json: async () => ({
          payload: { publicKey: networkKey, chainId: attestedChainId, pricingKeys: [] },
          attestation: null,
          isDebug: true,
        }),
      } as Response;
    }
    if (url.endsWith("/obfuscate_escrow")) {
      return {
        ok: true,
        json: async () => ({
          obfuscated_bytecode: "0x6000",
          original_size: 2,
          obfuscated_size: 2,
          selector_mapping: null,
        }),
      } as Response;
    }
    if (url.endsWith("/pricing/quote")) {
      pricingBody = JSON.parse(String(init?.body));
      const rewardAsset = pricingBody.signals[0].asset;
      return {
        ok: true,
        json: async () => ({
          chain_id: 31337,
          service_fee: { asset: rewardAsset, amount: "25" },
          deployment: {
            escrow_type: "batch",
            constructor_args: "0x1234",
            quote_commitment: COMMITMENT,
            reward_asset: rewardAsset,
            reward_amount: "25",
            deposit_by_asset: { [rewardAsset]: "125" },
            msg_value: rewardAsset === NATIVE_TOKEN_ADDRESS ? "125" : "0",
          },
          sealed_pricing_authorization: "0xabcd",
        }),
      } as Response;
    }
    throw new Error(`Unexpected URL ${url}`);
  }) as any;
});

const network = createNetworkConfig("ethereum", {
  chainId: 31337,
  apiServer: "https://api.test",
  attestation: { required: false },
});

describe("prepareTransfer pricing flow", () => {
  it("quotes a one-row transfer as an EscrowBatch with one blinded signer", async () => {
    const prepared = await prepareTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      senderAddress: SENDER,
      publicClient: {} as any,
      network,
    });

    expect(pricingBody.escrow_type).toBe("batch");
    expect(pricingBody.blinded_signers).toHaveLength(1);
    expect(pricingBody.signals).toEqual([
      {
        asset: USDC,
        execution_mode: "private",
        items: [{ client_row_id: "row-0", recipient: RECIPIENT_A, amount: "100" }],
      },
    ]);
    expect(prepared.fees.serviceFee).toEqual({ asset: USDC, amount: 25n });
  });

  it("groups rows by asset while preserving the first asset as the reward asset", async () => {
    const prepared = await prepareTransfer({
      transfers: [
        { tokenAddress: NATIVE_TOKEN_ADDRESS, recipientAddress: RECIPIENT_A, amount: 100n },
        { tokenAddress: USDC, recipientAddress: RECIPIENT_B, amount: 200n },
        { tokenAddress: NATIVE_TOKEN_ADDRESS, recipientAddress: RECIPIENT_B, amount: 50n },
      ],
      senderAddress: SENDER,
      publicClient: {} as any,
      network,
    });

    expect(pricingBody.blinded_signers).toHaveLength(3);
    expect(pricingBody.signals.map((signal: any) => signal.asset)).toEqual([
      NATIVE_TOKEN_ADDRESS,
      USDC,
    ]);
    expect(pricingBody.signals[0].execution_mode).toBe("native");
    expect(pricingBody.signals[0].items).toHaveLength(2);
    expect(pricingBody.signals[1].execution_mode).toBe("private");
    expect(prepared.fees.rewardAsset).toBe(NATIVE_TOKEN_ADDRESS);
  });

  it("requires the sender before requesting a quote", async () => {
    await expect(
      prepareTransfer({
        tokenAddress: USDC,
        recipientAddress: RECIPIENT_A,
        amount: 100n,
        publicClient: {} as any,
        network,
      }),
    ).rejects.toMatchObject({ code: "SENDER_REQUIRED" });
  });

  it.each(["depositByAsset", "msgValue"] as const)(
    "rejects resume data missing %s with INVALID_RESUME",
    async (field) => {
      await expect(
        prepareTransfer({
          tokenAddress: USDC,
          recipientAddress: RECIPIENT_A,
          amount: 100n,
          publicClient: {} as any,
          network,
          resume: { ...VALID_RESUME, [field]: undefined } as any,
        }),
      ).rejects.toMatchObject({
        code: "INVALID_RESUME",
        message: "Resume data is missing or contains invalid pricing and funding values",
      });
    },
  );

  it("surfaces real whitelist values returned by compliance", async () => {
    const prepared = await prepareTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      publicClient: {} as any,
      network,
      resume: VALID_RESUME,
    });
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      statusText: "Forbidden",
      text: async () =>
        JSON.stringify({
          error: "Caller is not whitelisted for transactions above $1000",
          details: "transaction_value_usd=~$1250.50",
        }),
    }) as any;

    const completion = prepared.complete({ account: { address: SENDER } } as any);
    await expect(completion.next()).rejects.toMatchObject({
      code: "WHITELIST_REQUIRED",
      amountUsd: 1_250.5,
      thresholdUsd: 1_000,
    });
  });
});

describe("nomad proxy routing", () => {
  const prepare = () =>
    prepareTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      senderAddress: SENDER,
      publicClient: {} as any,
      network,
    });

  it("requests attestation through the per-chain proxy path", async () => {
    await prepare();
    expect(attestUrl).toBe("https://api.test/nomad/31337/attest");
  });

  it("rejects a key attested for a different chain than the one requested", async () => {
    // The proxy picks the node, so a wrong-chain answer must fail rather than
    // encrypt the signal to an enclave keyed to another chain.
    attestedChainId = 1;
    await expect(prepare()).rejects.toMatchObject({ code: "INVALID_NETWORK_KEY" });
  });

  it("accepts an attestation that reports no chain", async () => {
    attestedChainId = 0;
    await expect(prepare()).resolves.toBeDefined();
  });
});
