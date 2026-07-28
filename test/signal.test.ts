import { describe, it, expect, vi, beforeEach } from "vitest";
import { submitSignal } from "../src/internal/nomad.js";
import { MissingBlindingScalarError } from "../src/errors.js";
import { NATIVE_TOKEN_ADDRESS } from "../src/token.js";
import type { NetworkKeyStatus, TransferRow } from "../src/types.js";

const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;
const USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7" as const;
const ESCROW = "0x00000000000000000000000000000000000000ff" as const;
const R1 = "0x0000000000000000000000000000000000000001" as const;
const R2 = "0x0000000000000000000000000000000000000002" as const;
const SCALAR = `0x${"ab".repeat(32)}` as `0x${string}`;

// Capture the plaintext before encryption so the payload contract can be asserted.
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

function row(tokenAddress: string, amount: bigint, recipientAddress: string = R1): TransferRow {
  return {
    tokenAddress: tokenAddress as `0x${string}`,
    recipientAddress: recipientAddress as `0x${string}`,
    amount,
  };
}

const baseParams = {
  escrowAddress: ESCROW,
  tokenAddress: USDC,
  rewardAmount: 5n,
  nomadUrl: "http://nomad.test",
  networkKey,
};

beforeEach(() => {
  captured.payload = undefined;
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    text: async () => "accepted",
  }) as any;
});

describe("submitSignal", () => {
  it("includes escrowType and the blinding scalar for single escrows", async () => {
    await submitSignal({
      ...baseParams,
      escrowType: "erc20",
      transfers: [row(USDC, 100n)],
      blindingScalar: SCALAR,
    });

    expect(captured.payload).toMatchObject({
      escrowType: "erc20",
      escrowContract: ESCROW,
      tokenContract: USDC,
      recipient: R1,
      transferAmount: "100",
      totalTransferAmount: "100",
      rewardAmount: "5",
      blindingScalar: SCALAR,
    });
  });

  it("serializes transfers as an array of asset/recipient/amount", async () => {
    await submitSignal({
      ...baseParams,
      escrowType: "batch",
      transfers: [row(USDC, 100n, R1), row(USDC, 200n, R2)],
    });

    expect(captured.payload!.transfers).toEqual([
      { asset: USDC, recipient: R1, amount: "100" },
      { asset: USDC, recipient: R2, amount: "200" },
    ]);
  });

  it("omits blindingScalar entirely for batch escrows", async () => {
    await submitSignal({
      ...baseParams,
      escrowType: "batch",
      transfers: [row(USDC, 100n, R1), row(USDC, 200n, R2)],
    });

    expect("blindingScalar" in captured.payload!).toBe(false);
  });

  it("sums only rows matching the first row's asset", async () => {
    await submitSignal({
      ...baseParams,
      escrowType: "batch",
      transfers: [row(USDC, 100n, R1), row(USDT, 900n, R2), row(USDC, 50n, R2)],
    });

    // Mixed-asset batches deliberately under-report this field.
    expect(captured.payload!.totalTransferAmount).toBe("150");
  });

  it("rejects a single escrow without a scalar before any network call", async () => {
    await expect(
      submitSignal({
        ...baseParams,
        escrowType: "native",
        tokenAddress: NATIVE_TOKEN_ADDRESS,
        transfers: [row(NATIVE_TOKEN_ADDRESS, 100n)],
      }),
    ).rejects.toBeInstanceOf(MissingBlindingScalarError);

    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("rejects an empty transfer list", async () => {
    await expect(
      submitSignal({ ...baseParams, escrowType: "batch", transfers: [] }),
    ).rejects.toMatchObject({ code: "EMPTY_TRANSFERS" });
  });

  it("nulls absent optional fields rather than omitting them", async () => {
    await submitSignal({
      ...baseParams,
      escrowType: "erc20",
      transfers: [row(USDC, 100n)],
      blindingScalar: SCALAR,
    });

    const payload = captured.payload!;
    expect(payload.deployedAt).toBeNull();
    expect(payload.selectorMapping).toBeNull();
    expect(payload.approval).toBeNull();
    expect(payload.userApproveGas).toBeNull();
    expect(payload.userDeployGas).toBeNull();
    expect(payload.userGasPrice).toBeNull();
  });

  it("sends gas fields as numbers and amounts as strings", async () => {
    await submitSignal({
      ...baseParams,
      escrowType: "erc20",
      transfers: [row(USDC, 100n)],
      blindingScalar: SCALAR,
      userApproveGas: 46_686n,
      userDeployGas: 2_167_182n,
      userGasPrice: 30_000_000_000n,
      complianceSignature: "0xsig",
      complianceTimestamp: 1_700_000_000,
    });

    const payload = captured.payload!;
    expect(payload.userApproveGas).toBe(46686);
    expect(payload.userDeployGas).toBe(2167182);
    expect(payload.userGasPrice).toBe(30000000000);
    expect(payload.rewardAmount).toBe("5");
    expect(payload.approval).toEqual({ signature: "0xsig", timestamp: 1_700_000_000 });
  });

  it("posts the ciphertext as a JSON string literal", async () => {
    await submitSignal({
      ...baseParams,
      escrowType: "erc20",
      transfers: [row(USDC, 100n)],
      blindingScalar: SCALAR,
    });

    const [url, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(url).toBe("http://nomad.test/signal");
    expect(init!.body).toBe(JSON.stringify("0x010203"));
  });
});
