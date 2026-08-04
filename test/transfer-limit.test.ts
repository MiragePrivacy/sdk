import { describe, it, expect, vi, beforeEach } from "vitest";
import { TransferLimitError, WhitelistRequiredError } from "../src/errors.js";
import { networks } from "../src/networks.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as `0x${string}`;
const USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as `0x${string}`;
const USDT_ADDRESS = "0xdAC17F958D2ee523a2206206994597C13D831ec7" as `0x${string}`;

vi.mock("../src/internal/api.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/internal/api.js")>();
  return {
    ...actual,
    fetchLimits: vi.fn(),
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

import { fetchLimits } from "../src/internal/api.js";
import { resolveEthPrice } from "../src/internal/fees.js";
import { getTokenMetadata } from "../src/token.js";
import { prepareTransfer } from "../src/transfer.js";

const mockedFetchLimits = vi.mocked(fetchLimits);
const mockedResolveEthPrice = vi.mocked(resolveEthPrice);
const mockedGetTokenMetadata = vi.mocked(getTokenMetadata);

const CHAIN = String(networks.ethereum.chainId);

function limits(options: { max?: string | null; whitelist?: string | null }) {
  return {
    status: "ok",
    maxTransferUsd: options.max === undefined ? undefined : { [CHAIN]: options.max },
    whitelistRequiredUsd:
      options.whitelist === undefined ? undefined : { [CHAIN]: options.whitelist },
  };
}

function mockPublicClient() {
  return {
    getFeeHistory: vi.fn().mockResolvedValue({ reward: [[1_000_000_000n]] }),
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

const ethMetadata = {
  address: ZERO_ADDRESS,
  name: "Ether",
  symbol: "ETH",
  decimals: 18,
};

const usdcMetadata = {
  address: USDC_ADDRESS,
  name: "USD Coin",
  symbol: "USDC",
  decimals: 6,
};

describe("transfer limit check", () => {
  beforeEach(() => {
    mockedResolveEthPrice.mockResolvedValue(4500);
    mockedGetTokenMetadata.mockResolvedValue(ethMetadata);
  });

  describe("native ETH", () => {
    it("converts ETH amount to USD using eth price", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: "1000" }));

      await expect(prepareTransfer(baseParams)).rejects.toMatchObject({
        name: "TransferLimitError",
        amountUsd: 4500,
        limitUsd: 1000,
      });
    });

    it("passes when ETH value in USD is within limit", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: "1000" }));

      const prepared = await prepareTransfer({
        ...baseParams,
        amount: 100_000_000_000_000_000n, // 0.1 ETH = $450
      });
      expect(prepared.fees.transferAmount).toBe(100_000_000_000_000_000n);
    });

    it("blocks when the ETH price is unavailable", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: "1000" }));
      mockedResolveEthPrice.mockResolvedValue(0);

      await expect(prepareTransfer(baseParams)).rejects.toMatchObject({
        code: "MISSING_ETH_PRICE",
      });
    });
  });

  describe("stablecoin (ERC20)", () => {
    const usdcParams = {
      ...baseParams,
      tokenAddress: USDC_ADDRESS,
      amount: 500_000_000n, // 500 USDC (6 decimals)
    };

    beforeEach(() => {
      mockedGetTokenMetadata.mockResolvedValue(usdcMetadata);
    });

    it("throws when stablecoin amount exceeds limit", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: "100" }));

      await expect(prepareTransfer(usdcParams)).rejects.toThrow(TransferLimitError);
    });

    it("uses token amount directly as USD for stablecoins", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: "100" }));

      await expect(prepareTransfer(usdcParams)).rejects.toMatchObject({
        amountUsd: 500,
        limitUsd: 100,
      });
    });

    it("passes when amount is within limit", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: "1000" }));

      const prepared = await prepareTransfer(usdcParams);
      expect(prepared.fees.transferAmount).toBe(usdcParams.amount);
    });
  });

  describe("per-transaction application", () => {
    beforeEach(() => {
      mockedGetTokenMetadata.mockResolvedValue(usdcMetadata);
    });

    it("allows a batch whose total exceeds the limit but whose rows do not", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: "6000" }));

      const prepared = await prepareTransfer({
        ...baseParams,
        tokenAddress: undefined,
        recipientAddress: undefined,
        amount: undefined,
        transfers: Array.from({ length: 10 }, (_, i) => ({
          tokenAddress: USDC_ADDRESS,
          recipientAddress: `0x${String(i + 1).padStart(40, "0")}` as `0x${string}`,
          amount: 5_000_000_000n, // $5,000 each, $50,000 total
        })),
      });

      expect(prepared.fees).toBeDefined();
    });

    it("reports the offending row index", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: "1000" }));

      await expect(
        prepareTransfer({
          ...baseParams,
          tokenAddress: undefined,
          recipientAddress: undefined,
          amount: undefined,
          transfers: [
            {
              tokenAddress: USDC_ADDRESS,
              recipientAddress: "0x0000000000000000000000000000000000000001",
              amount: 100_000_000n, // $100
            },
            {
              tokenAddress: USDC_ADDRESS,
              recipientAddress: "0x0000000000000000000000000000000000000002",
              amount: 5_000_000_000n, // $5,000
            },
          ],
        }),
      ).rejects.toMatchObject({ name: "TransferLimitError", rowIndex: 1 });
    });
  });

  describe("whitelist threshold", () => {
    beforeEach(() => {
      mockedGetTokenMetadata.mockResolvedValue(usdcMetadata);
    });

    const usdcParams = {
      ...baseParams,
      tokenAddress: USDC_ADDRESS,
      amount: 500_000_000n, // $500
    };

    it("requires whitelist above the threshold", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: null, whitelist: "100" }));

      await expect(prepareTransfer(usdcParams)).rejects.toMatchObject({
        name: "WhitelistRequiredError",
        amountUsd: 500,
        thresholdUsd: 100,
      });
    });

    it("passes below the threshold without a token", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: null, whitelist: "1000" }));

      const prepared = await prepareTransfer(usdcParams);
      expect(prepared.fees).toBeDefined();
    });

    it("passes above the threshold when an access token is supplied", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: null, whitelist: "100" }));

      const prepared = await prepareTransfer({ ...usdcParams, accessToken: "deadbeef" });
      expect(prepared.fees).toBeDefined();
    });

    it("does not require whitelist when no threshold is configured", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: null, whitelist: null }));

      const prepared = await prepareTransfer(usdcParams);
      expect(prepared.fees).toBeDefined();
    });
  });

  describe("no limit configured", () => {
    it("passes when limit is null", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: null }));

      const prepared = await prepareTransfer(baseParams);
      expect(prepared.fees.transferAmount).toBe(baseParams.amount);
    });

    it("passes when limits are unavailable", async () => {
      mockedFetchLimits.mockResolvedValue(limits({}));

      const prepared = await prepareTransfer(baseParams);
      expect(prepared.fees.transferAmount).toBe(baseParams.amount);
    });
  });

  describe("PreparedTransfer", () => {
    it("returns fees and execute function", async () => {
      mockedFetchLimits.mockResolvedValue(limits({ max: null }));

      const prepared = await prepareTransfer(baseParams);
      expect(prepared.fees).toBeDefined();
      expect(prepared.fees.transferAmount).toBe(baseParams.amount);
      expect(typeof prepared.execute).toBe("function");
    });
  });
});

describe("WhitelistRequiredError", () => {
  it("carries the threshold for caller-side recovery", () => {
    const err = new WhitelistRequiredError(500, 100);
    expect(err.code).toBe("WHITELIST_REQUIRED");
    expect(err.thresholdUsd).toBe(100);
  });
});
