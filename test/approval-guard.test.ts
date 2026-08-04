import { describe, it, expect, vi, beforeEach } from "vitest";
import { networks } from "../src/networks.js";

const USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as `0x${string}`;
const RECIPIENT = "0x0000000000000000000000000000000000000001" as `0x${string}`;
const ACCOUNT = "0x00000000000000000000000000000000000000aa" as `0x${string}`;

vi.mock("../src/internal/api.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/internal/api.js")>();
  return {
    ...actual,
    fetchLimits: vi.fn().mockResolvedValue({ status: "ok" }),
    fetchObfuscation: vi.fn().mockResolvedValue({
      obfuscatedBytecode: "0x00",
      selectorMapping: undefined,
      originalSize: 1,
      obfuscatedSize: 1,
      gasAnalysis: undefined,
      seed: "0".repeat(64),
    }),
  };
});

vi.mock("../src/internal/fees.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/internal/fees.js")>();
  return {
    ...actual,
    resolveEthPrice: vi.fn().mockResolvedValue(4500),
  };
});

vi.mock("../src/token.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/token.js")>();
  return {
    ...actual,
    getTokenMetadata: vi.fn(),
  };
});

vi.mock("../src/internal/escrow.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/internal/escrow.js")>();
  return {
    ...actual,
    approveForDeployment: vi.fn(),
  };
});

import { getTokenMetadata } from "../src/token.js";
import { approveForDeployment } from "../src/internal/escrow.js";
import { prepareTransfer } from "../src/transfer.js";

const mockedGetTokenMetadata = vi.mocked(getTokenMetadata);
const mockedApprove = vi.mocked(approveForDeployment);

function mockPublicClient() {
  return {
    getFeeHistory: vi.fn().mockResolvedValue({ reward: [[1_000_000_000n]] }),
    getBlock: vi.fn().mockResolvedValue({ baseFeePerGas: 15_000_000_000n }),
    getGasPrice: vi.fn().mockResolvedValue(30_000_000_000n),
  } as any;
}

const baseParams = {
  transfers: [{ tokenAddress: USDC_ADDRESS, recipientAddress: RECIPIENT, amount: 1_000_000n }],
  publicClient: mockPublicClient(),
  network: networks.ethereum,
  gasPrice: { maxFeePerGas: 30_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n },
};

const wallet = { account: { address: ACCOUNT } } as any;

describe("approval staging guard", () => {
  beforeEach(() => {
    mockedGetTokenMetadata.mockResolvedValue({
      address: USDC_ADDRESS,
      name: "USD Coin",
      symbol: "USDC",
      decimals: 6,
    });
    mockedApprove.mockReset();
  });

  it("stays mutable when the wallet prompt is rejected before any broadcast", async () => {
    const prepared = await prepareTransfer(baseParams);

    // No account: getAccount throws before any transaction is submitted.
    await expect(prepared.approve({} as any).next()).rejects.toMatchObject({
      code: "NO_ACCOUNT",
    });

    // Nothing was committed, so fees may still be refreshed and retried.
    await expect(prepared.refreshFees()).resolves.toBeDefined();

    mockedApprove.mockImplementation(async function* () {
      return { approvals: [], approveGasUsed: 0n } as any;
    });
    await expect(prepared.approve(wallet).next()).resolves.toBeDefined();
  });

  it("locks the transfer once an approval has been broadcast", async () => {
    mockedApprove.mockImplementation(async function* () {
      yield { hash: "0xaa", tokenAddress: USDC_ADDRESS, index: 0, total: 1 };
      return { approvals: [], approveGasUsed: 21_000n } as any;
    });

    const prepared = await prepareTransfer(baseParams);
    const iterator = prepared.approve(wallet);

    // Consume only the first yielded approval, mirroring a mined-but-incomplete
    // sequence. The generator has not returned its checkpoint yet.
    const first = await iterator.next();
    expect(first.done).toBe(false);

    await expect(prepared.refreshFees()).rejects.toMatchObject({ code: "INVALID_STAGE" });
    await expect(prepared.updateTransfers(baseParams.transfers)).rejects.toMatchObject({
      code: "INVALID_STAGE",
    });
  });

  it("rejects a concurrent approval sequence", async () => {
    mockedApprove.mockImplementation(async function* () {
      yield { hash: "0xaa", tokenAddress: USDC_ADDRESS, index: 0, total: 1 };
      return { approvals: [], approveGasUsed: 21_000n } as any;
    });

    const prepared = await prepareTransfer(baseParams);
    const first = prepared.approve(wallet);
    await first.next();

    await expect(prepared.approve(wallet).next()).rejects.toMatchObject({
      code: "INVALID_STAGE",
    });
  });
});
