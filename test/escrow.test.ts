import { describe, expect, it, vi } from "vitest";
import { getContractAddress, zeroAddress } from "viem";
import {
  buildQuotedApprovalBuckets,
  approveQuotedForDeployment,
  deployQuotedApproved,
  pickRewardToken,
  predictContractAddress,
} from "../src/internal/escrow.js";

const DEPLOYER = "0x0000000000000000000000000000000000000001" as const;
const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;
const USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7" as const;

describe("quoted escrow funding", () => {
  it("uses exact API deposits and excludes native msg.value from approvals", () => {
    expect(
      buildQuotedApprovalBuckets({ [USDC]: 1_025n, [USDT]: 500n, [zeroAddress]: 2n }),
    ).toEqual([
      { tokenAddress: USDC, amount: 1_025n },
      { tokenAddress: USDT, amount: 500n },
    ]);
  });

  it("keeps the first transfer asset as the reward denomination", () => {
    expect(
      pickRewardToken([
        { tokenAddress: zeroAddress, recipientAddress: DEPLOYER, amount: 1n },
        { tokenAddress: USDC, recipientAddress: DEPLOYER, amount: 2n },
      ]),
    ).toBe(zeroAddress);
  });

  it("predicts the standard CREATE address, including nonce zero", () => {
    expect(predictContractAddress(DEPLOYER, 0)).toBe(
      getContractAddress({ from: DEPLOYER, nonce: 0n }),
    );
    expect(predictContractAddress(DEPLOYER, 3)).toBe(
      getContractAddress({ from: DEPLOYER, nonce: 3n }),
    );
  });
});

describe("quoted escrow transactions", () => {
  it("approves exact deposits at the nonce-adjusted deployment address", async () => {
    const approvalHashes = [
      `0x${"11".repeat(32)}`,
      `0x${"22".repeat(32)}`,
    ] as `0x${string}`[];
    const writes: any[] = [];
    const walletClient = {
      chain: undefined,
      writeContract: vi.fn(async (request) => {
        writes.push(request);
        return approvalHashes[writes.length - 1];
      }),
    } as any;
    const publicClient = {
      getTransactionCount: vi.fn(async () => 5),
      waitForTransactionReceipt: vi.fn(async () => ({ status: "success", gasUsed: 50_000n })),
    } as any;

    const iterator = approveQuotedForDeployment({
      depositByAsset: { [USDC]: 1_025n, [USDT]: 500n, [zeroAddress]: 2n },
      walletClient,
      publicClient,
      account: DEPLOYER,
    });
    let checkpoint;
    while (true) {
      const next = await iterator.next();
      if (next.done) {
        checkpoint = next.value;
        break;
      }
    }

    const predicted = predictContractAddress(DEPLOYER, 7);
    expect(checkpoint.predictedEscrowAddress).toBe(predicted);
    expect(checkpoint.approveGasUsed).toBe(100_000n);
    expect(writes.map((write) => write.args)).toEqual([
      [predicted, 1_025n],
      [predicted, 500n],
    ]);
  });

  it("appends the exact constructor suffix and uses quoted msg.value", async () => {
    const hash = `0x${"33".repeat(32)}` as const;
    const predicted = predictContractAddress(DEPLOYER, 5);
    const sendTransaction = vi.fn(async () => hash);
    const walletClient = { chain: undefined, sendTransaction } as any;
    const publicClient = {
      waitForTransactionReceipt: vi.fn(async () => ({
        status: "success",
        contractAddress: predicted,
        gasUsed: 1_000_000n,
        effectiveGasPrice: 2n,
        blockNumber: 9n,
      })),
    } as any;

    const result = await deployQuotedApproved({
      bytecode: "0x6000",
      constructorArgs: "0x1234",
      depositByAsset: { [USDC]: 1_025n },
      msgValue: 7n,
      walletClient,
      publicClient,
      account: DEPLOYER,
      checkpoint: {
        stage: "approved",
        account: DEPLOYER,
        predictedEscrowAddress: predicted,
        approvals: [],
        approveGasUsed: 0n,
      },
    });

    expect(sendTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ to: null, data: "0x60001234", value: 7n }),
    );
    expect(result.escrowAddress).toBe(predicted);
  });
});
