import { describe, it, expect, vi, beforeEach } from "vitest";
import { TransferLimitError } from "../src/errors.js";
import { networks } from "../src/networks.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as `0x${string}`;
const USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as `0x${string}`;

// Mock the API module
vi.mock("../src/internal/api.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/internal/api.js")>();
  return {
    ...actual,
    fetchTransferLimit: vi.fn(),
    fetchObfuscation: vi.fn().mockResolvedValue({
      obfuscatedBytecode: "0x00",
      selectorMapping: undefined,
      originalSize: 1,
      obfuscatedSize: 1,
      gasAnalysis: undefined,
    }),
  };
});

// Mock fees module to control resolveEthPrice and estimateFees
vi.mock("../src/internal/fees.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/internal/fees.js")>();
  return {
    ...actual,
    resolveEthPrice: vi.fn().mockResolvedValue(4500),
    estimateFees: vi.fn().mockImplementation((params: any) => ({
      transferAmount: params.amount,
      networkFee: 0n,
      nodeFee: 0n,
      platformFee: 0n,
      totalFee: 0n,
      totalAmount: params.amount,
      decimals: params.tokenDecimals,
      isNativeEth: false,
    })),
  };
});

// Mock getTokenMetadata to avoid real RPC calls
vi.mock("../src/token.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/token.js")>();
  return {
    ...actual,
    getTokenMetadata: vi.fn().mockResolvedValue({
      address: "0x0000000000000000000000000000000000000000",
      name: "Ether",
      symbol: "ETH",
      decimals: 18,
    }),
  };
});

import { fetchTransferLimit } from "../src/internal/api.js";
import { resolveEthPrice } from "../src/internal/fees.js";
import { getTokenMetadata } from "../src/token.js";
import { prepareTransfer } from "../src/transfer.js";

const mockedFetchLimit = vi.mocked(fetchTransferLimit);
const mockedResolveEthPrice = vi.mocked(resolveEthPrice);
const mockedGetTokenMetadata = vi.mocked(getTokenMetadata);

function mockPublicClient() {
  return {
    getFeeHistory: vi.fn().mockResolvedValue({
      reward: [[1_000_000_000n]],
    }),
    getBlock: vi.fn().mockResolvedValue({ baseFeePerGas: 15_000_000_000n }),
    getGasPrice: vi.fn().mockResolvedValue(30_000_000_000n),
  } as any;
}

const baseParams = {
  tokenAddress: ZERO_ADDRESS,
  recipientAddress: "0x0000000000000000000000000000000000000001" as `0x${string}`,
  amount: 1_000_000_000_000_000_000n, // 1 ETH
  walletClient: {} as any,
  publicClient: mockPublicClient(),
  network: networks.ethereum,
  gasPrice: { maxFeePerGas: 30_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n },
};

describe("transfer limit check", () => {
  describe("native ETH", () => {
    it("converts ETH amount to USD using eth price", async () => {
      // 1 ETH at $4500 = $4500, limit is $1000
      mockedResolveEthPrice.mockResolvedValue(4500);
      mockedFetchLimit.mockResolvedValue("1000");

      try {
        await prepareTransfer(baseParams);
        expect.unreachable("should have thrown");
      } catch (e) {
        expect(e).toBeInstanceOf(TransferLimitError);
        const err = e as TransferLimitError;
        expect(err.amountUsd).toBe(4500);
        expect(err.limitUsd).toBe(1000);
      }
    });

    it("passes when ETH value in USD is within limit", async () => {
      // 0.1 ETH at $4500 = $450, limit is $1000
      mockedResolveEthPrice.mockResolvedValue(4500);
      mockedFetchLimit.mockResolvedValue("1000");

      const prepared = await prepareTransfer({
        ...baseParams,
        amount: 100_000_000_000_000_000n, // 0.1 ETH
      });
      expect(prepared.fees.transferAmount).toBe(100_000_000_000_000_000n);
    });
  });

  describe("stablecoin (ERC20)", () => {
    const usdcParams = {
      ...baseParams,
      tokenAddress: USDC_ADDRESS,
      amount: 500_000_000n, // 500 USDC (6 decimals)
    };

    beforeEach(() => {
      mockedGetTokenMetadata.mockResolvedValue({
        address: USDC_ADDRESS,
        name: "USD Coin",
        symbol: "USDC",
        decimals: 6,
      });
      mockedResolveEthPrice.mockResolvedValue(4500);
    });

    it("throws when stablecoin amount exceeds limit", async () => {
      mockedFetchLimit.mockResolvedValue("100");

      await expect(prepareTransfer(usdcParams)).rejects.toThrow(TransferLimitError);
    });

    it("uses token amount directly as USD for stablecoins", async () => {
      mockedFetchLimit.mockResolvedValue("100");

      try {
        await prepareTransfer(usdcParams);
        expect.unreachable("should have thrown");
      } catch (e) {
        expect(e).toBeInstanceOf(TransferLimitError);
        const err = e as TransferLimitError;
        expect(err.amountUsd).toBe(500); // 500 USDC = $500
        expect(err.limitUsd).toBe(100);
      }
    });

    it("passes when amount is within limit", async () => {
      mockedFetchLimit.mockResolvedValue("1000");

      const prepared = await prepareTransfer(usdcParams);
      expect(prepared.fees.transferAmount).toBe(usdcParams.amount);
    });
  });

  describe("no limit configured", () => {
    it("passes when limit is null", async () => {
      mockedFetchLimit.mockResolvedValue(null);

      const prepared = await prepareTransfer(baseParams);
      expect(prepared.fees.transferAmount).toBe(baseParams.amount);
    });

    it("passes when limit is undefined", async () => {
      mockedFetchLimit.mockResolvedValue(undefined);

      const prepared = await prepareTransfer(baseParams);
      expect(prepared.fees.transferAmount).toBe(baseParams.amount);
    });
  });

  describe("PreparedTransfer", () => {
    it("returns fees and execute function", async () => {
      mockedFetchLimit.mockResolvedValue(null);

      const prepared = await prepareTransfer(baseParams);
      expect(prepared.fees).toBeDefined();
      expect(prepared.fees.transferAmount).toBe(baseParams.amount);
      expect(typeof prepared.execute).toBe("function");
    });
  });
});
