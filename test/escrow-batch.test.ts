import { describe, it, expect } from "vitest";
import { decodeAbiParameters, encodeAbiParameters } from "viem";
import {
  buildApprovalBuckets,
  deriveEscrowKind,
  pickRewardToken,
  sumNativeAmount,
} from "../src/internal/escrow.js";
import { NATIVE_TOKEN_ADDRESS } from "../src/token.js";
import type { TransferRow } from "../src/types.js";

const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;
const USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7" as const;
const R1 = "0x0000000000000000000000000000000000000001" as const;
const R2 = "0x0000000000000000000000000000000000000002" as const;

function row(tokenAddress: string, amount: bigint, recipientAddress: string = R1): TransferRow {
  return {
    tokenAddress: tokenAddress as `0x${string}`,
    recipientAddress: recipientAddress as `0x${string}`,
    amount,
  };
}

describe("pickRewardToken", () => {
  it("prefers the first ERC20 row", () => {
    expect(pickRewardToken([row(NATIVE_TOKEN_ADDRESS, 1n), row(USDC, 2n)])).toBe(USDC);
  });

  it("falls back to the first row when all rows are native", () => {
    expect(pickRewardToken([row(NATIVE_TOKEN_ADDRESS, 1n)])).toBe(NATIVE_TOKEN_ADDRESS);
  });

  it("keeps the earliest ERC20 when several are present", () => {
    expect(pickRewardToken([row(USDT, 1n), row(USDC, 2n)])).toBe(USDT);
  });
});

describe("deriveEscrowKind", () => {
  it("classifies a single ERC20 row", () => {
    expect(deriveEscrowKind([row(USDC, 1n)])).toBe("erc20");
  });

  it("classifies a single native row", () => {
    expect(deriveEscrowKind([row(NATIVE_TOKEN_ADDRESS, 1n)])).toBe("native");
  });

  it("classifies any multi-row transfer as batch, even all-native", () => {
    expect(
      deriveEscrowKind([row(NATIVE_TOKEN_ADDRESS, 1n, R1), row(NATIVE_TOKEN_ADDRESS, 2n, R2)]),
    ).toBe("batch");
  });
});

describe("sumNativeAmount", () => {
  it("sums only the native rows", () => {
    expect(
      sumNativeAmount([
        row(NATIVE_TOKEN_ADDRESS, 10n),
        row(USDC, 500n),
        row(NATIVE_TOKEN_ADDRESS, 5n),
      ]),
    ).toBe(15n);
  });

  it("is zero when no rows are native", () => {
    expect(sumNativeAmount([row(USDC, 500n)])).toBe(0n);
  });
});

describe("buildApprovalBuckets", () => {
  it("creates one bucket per distinct ERC20", () => {
    const buckets = buildApprovalBuckets(
      [row(USDC, 100n, R1), row(USDT, 200n, R2), row(USDC, 50n, R2)],
      0n,
    );

    expect(buckets).toHaveLength(2);
    expect(buckets.find((b) => b.tokenAddress === USDC)?.amount).toBe(150n);
    expect(buckets.find((b) => b.tokenAddress === USDT)?.amount).toBe(200n);
  });

  it("folds the reward into the reward asset's bucket", () => {
    const buckets = buildApprovalBuckets([row(USDC, 100n)], 7n);
    expect(buckets).toHaveLength(1);
    expect(buckets[0].amount).toBe(107n);
  });

  it("skips native rows, which need no allowance", () => {
    const buckets = buildApprovalBuckets(
      [row(NATIVE_TOKEN_ADDRESS, 100n, R1), row(USDC, 200n, R2)],
      3n,
    );
    expect(buckets).toHaveLength(1);
    expect(buckets[0].tokenAddress).toBe(USDC);
    expect(buckets[0].amount).toBe(203n);
  });

  it("returns nothing for an all-native transfer", () => {
    expect(buildApprovalBuckets([row(NATIVE_TOKEN_ADDRESS, 100n)], 0n)).toHaveLength(0);
  });

  it("treats differently-cased addresses as one token", () => {
    const buckets = buildApprovalBuckets(
      [row(USDC, 100n, R1), row(USDC.toLowerCase(), 200n, R2)],
      0n,
    );
    expect(buckets).toHaveLength(1);
    expect(buckets[0].amount).toBe(300n);
  });

  it("does not fold a native reward into any bucket", () => {
    const buckets = buildApprovalBuckets([row(NATIVE_TOKEN_ADDRESS, 100n)], 25n);
    expect(buckets).toHaveLength(0);
  });
});

describe("batch constructor encoding", () => {
  // Mirrors the escrow's tuple layout: asset, recipient, amount.
  it("round-trips rows through the tuple layout", () => {
    const rows = [row(USDC, 100n, R1), row(NATIVE_TOKEN_ADDRESS, 200n, R2)];
    const components = [
      { type: "address", name: "asset" },
      { type: "address", name: "recipient" },
      { type: "uint256", name: "amount" },
    ] as const;

    const encoded = encodeAbiParameters(
      [
        { type: "address", name: "_rewardAsset" },
        { type: "tuple[]", name: "_expectedTransfers", components },
        { type: "uint256", name: "_currentRewardAmount" },
      ],
      [
        USDC,
        rows.map((r) => ({
          asset: r.tokenAddress,
          recipient: r.recipientAddress,
          amount: r.amount,
        })),
        42n,
      ],
    );

    const [rewardAsset, transfers, reward] = decodeAbiParameters(
      [
        { type: "address", name: "_rewardAsset" },
        { type: "tuple[]", name: "_expectedTransfers", components },
        { type: "uint256", name: "_currentRewardAmount" },
      ],
      encoded,
    );

    expect(rewardAsset).toBe(USDC);
    expect(reward).toBe(42n);
    expect(transfers).toHaveLength(2);
    expect((transfers as any)[0].asset).toBe(USDC);
    expect((transfers as any)[0].recipient).toBe(R1);
    expect((transfers as any)[1].amount).toBe(200n);
  });
});
