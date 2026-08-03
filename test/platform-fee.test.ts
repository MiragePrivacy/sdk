import { describe, it, expect, vi, beforeEach } from "vitest";
import { networks } from "../src/networks.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as `0x${string}`;
const USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as `0x${string}`;
const RECIPIENT = "0x0000000000000000000000000000000000000001" as `0x${string}`;

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

import { resolveEthPrice } from "../src/internal/fees.js";
import { getTokenMetadata } from "../src/token.js";
import { prepareTransfer } from "../src/transfer.js";

const mockedResolveEthPrice = vi.mocked(resolveEthPrice);
const mockedGetTokenMetadata = vi.mocked(getTokenMetadata);

function mockPublicClient() {
  return {
    getFeeHistory: vi.fn().mockResolvedValue({ reward: [[1_000_000_000n]] }),
    getBlock: vi.fn().mockResolvedValue({ baseFeePerGas: 15_000_000_000n }),
    getGasPrice: vi.fn().mockResolvedValue(30_000_000_000n),
  } as any;
}

const ONE_ETH = 1_000_000_000_000_000_000n;

const ethMetadata = { address: ZERO_ADDRESS, name: "Ether", symbol: "ETH", decimals: 18 };
const usdcMetadata = { address: USDC_ADDRESS, name: "USD Coin", symbol: "USDC", decimals: 6 };

const baseParams = {
  walletClient: {} as any,
  publicClient: mockPublicClient(),
  network: networks.ethereum,
  gasPrice: { maxFeePerGas: 30_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n },
};

describe("platform fee base", () => {
  beforeEach(() => {
    mockedResolveEthPrice.mockResolvedValue(4500);
  });

  it("charges a native transfer's percentage fee in wei, not USD", async () => {
    mockedGetTokenMetadata.mockResolvedValue(ethMetadata);

    const prepared = await prepareTransfer({
      ...baseParams,
      tokenAddress: ZERO_ADDRESS,
      recipientAddress: RECIPIENT,
      amount: ONE_ETH,
    });

    // 0.50% of 1 ETH. Pricing the base in USD first would charge 22.5 ETH.
    expect(prepared.fees.platformFee).toBe((ONE_ETH * networks.ethereum.platformFeeRate) / 10_000n);
    expect(prepared.fees.platformFee).toBe(5_000_000_000_000_000n);
  });

  it("keeps the total requirement near the transfer amount for a native transfer", async () => {
    mockedGetTokenMetadata.mockResolvedValue(ethMetadata);

    const prepared = await prepareTransfer({
      ...baseParams,
      tokenAddress: ZERO_ADDRESS,
      recipientAddress: RECIPIENT,
      amount: ONE_ETH,
    });

    // Reported as ~23.58 ETH before the fix.
    expect(prepared.fees.totalAmount).toBeLessThan(11n * ONE_ETH / 10n);
  });

  it("still prices native rows in USD when the reward asset is an ERC20", async () => {
    mockedGetTokenMetadata.mockImplementation(async (address: string) =>
      address.toLowerCase() === USDC_ADDRESS.toLowerCase() ? usdcMetadata : ethMetadata,
    );

    const prepared = await prepareTransfer({
      ...baseParams,
      transfers: [
        { tokenAddress: USDC_ADDRESS, recipientAddress: RECIPIENT, amount: 1_000_000n },
        { tokenAddress: ZERO_ADDRESS, recipientAddress: RECIPIENT, amount: ONE_ETH },
      ],
    });

    // Base is 1 USDC + 1 ETH valued at $4,500 = 4501 USDC units.
    expect(prepared.fees.platformFee).toBe((4_501_000_000n * networks.ethereum.platformFeeRate) / 10_000n);
  });
});
