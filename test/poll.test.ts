import { describe, it, expect, vi } from "vitest";
import { pollTransfers } from "../src/internal/poll.js";
import { TransferTimeoutError } from "../src/errors.js";
import { NATIVE_TOKEN_ADDRESS } from "../src/token.js";
import type { TransferRow } from "../src/types.js";

const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;
const R1 = "0x0000000000000000000000000000000000000001" as const;
const R2 = "0x0000000000000000000000000000000000000002" as const;
const R3 = "0x0000000000000000000000000000000000000003" as const;

function row(tokenAddress: string, amount: bigint, recipientAddress: string): TransferRow {
  return {
    tokenAddress: tokenAddress as `0x${string}`,
    recipientAddress: recipientAddress as `0x${string}`,
    amount,
  };
}

function log(to: string, value: bigint, hash: string, logIndex = 0) {
  return {
    address: USDC,
    transactionHash: hash,
    blockNumber: 100n,
    logIndex,
    args: { from: "0x00000000000000000000000000000000000000aa", to, value },
  };
}

/** Public client whose logs grow over successive polls. */
function mockClient(rounds: any[][]) {
  let round = 0;
  return {
    getBlockNumber: vi.fn().mockResolvedValue(100n),
    getLogs: vi.fn().mockImplementation(({ args }: any) => {
      const current = rounds[Math.min(round, rounds.length - 1)];
      return Promise.resolve(current.filter((l) => l.args.to === args.to));
    }),
    advance: () => {
      round += 1;
    },
  } as any;
}

describe("pollTransfers", () => {
  it("yields each recipient as it lands rather than waiting for all", async () => {
    const rows = [row(USDC, 100n, R1), row(USDC, 200n, R2), row(USDC, 300n, R3)];

    const client = mockClient([
      [log(R1, 100n, "0xaa")],
      [log(R1, 100n, "0xaa"), log(R2, 200n, "0xbb")],
      [log(R1, 100n, "0xaa"), log(R2, 200n, "0xbb"), log(R3, 300n, "0xcc")],
    ]);

    const seen: Array<{ index: number; hash: string }> = [];
    for await (const delivered of pollTransfers({
      transfers: rows,
      publicClient: client,
      timeout: 5_000,
      pollIntervalMs: 1,
    })) {
      seen.push({ index: delivered.index, hash: delivered.transfer.transactionHash });
      client.advance();
    }

    expect(seen).toEqual([
      { index: 0, hash: "0xaa" },
      { index: 1, hash: "0xbb" },
      { index: 2, hash: "0xcc" },
    ]);
  });

  it("completes immediately when all deliveries are already on chain", async () => {
    const rows = [row(USDC, 100n, R1), row(USDC, 200n, R2)];
    const client = mockClient([[log(R1, 100n, "0xaa"), log(R2, 200n, "0xbb")]]);

    const seen = [];
    for await (const delivered of pollTransfers({
      transfers: rows,
      publicClient: client,
      timeout: 5_000,
      pollIntervalMs: 1,
    })) {
      seen.push(delivered.index);
    }

    expect(seen).toEqual([0, 1]);
    expect(client.getLogs).toHaveBeenCalledTimes(2);
  });

  it("matches identical rows to distinct deliveries", async () => {
    // Two identical payments to the same recipient must consume two events.
    const rows = [row(USDC, 100n, R1), row(USDC, 100n, R1)];
    const client = mockClient([[log(R1, 100n, "0xaa", 0), log(R1, 100n, "0xbb", 1)]]);

    const hashes = [];
    for await (const delivered of pollTransfers({
      transfers: rows,
      publicClient: client,
      timeout: 5_000,
      pollIntervalMs: 1,
    })) {
      hashes.push(delivered.transfer.transactionHash);
    }

    expect(new Set(hashes).size).toBe(2);
  });

  it("ignores an event whose amount does not match", async () => {
    const rows = [row(USDC, 100n, R1)];
    const client = mockClient([[log(R1, 99n, "0xaa")]]);

    await expect(
      (async () => {
        for await (const _ of pollTransfers({
          transfers: rows,
          publicClient: client,
          timeout: 30,
          pollIntervalMs: 1,
        })) {
          // no deliveries expected
        }
      })(),
    ).rejects.toBeInstanceOf(TransferTimeoutError);
  });

  it("times out when a recipient never receives a delivery", async () => {
    const rows = [row(USDC, 100n, R1), row(USDC, 200n, R2)];
    const client = mockClient([[log(R1, 100n, "0xaa")]]);

    const seen: number[] = [];
    await expect(
      (async () => {
        for await (const delivered of pollTransfers({
          transfers: rows,
          publicClient: client,
          timeout: 30,
          pollIntervalMs: 1,
        })) {
          seen.push(delivered.index);
        }
      })(),
    ).rejects.toBeInstanceOf(TransferTimeoutError);

    // The delivered row is still surfaced before the timeout.
    expect(seen).toEqual([0]);
  });

  it("aborts mid-poll when the signal fires", async () => {
    const rows = [row(USDC, 100n, R1)];
    const client = mockClient([[]]);
    const controller = new AbortController();
    controller.abort();

    await expect(
      (async () => {
        for await (const _ of pollTransfers({
          transfers: rows,
          publicClient: client,
          timeout: 5_000,
          pollIntervalMs: 1,
          signal: controller.signal,
        })) {
          // unreachable
        }
      })(),
    ).rejects.toMatchObject({ code: "TRANSFER_ABORTED" });
  });

  it("watches plain transactions for native ETH recipients", async () => {
    const rows = [row(NATIVE_TOKEN_ADDRESS, 1_000n, R1)];
    const client = {
      getBlockNumber: vi.fn().mockResolvedValue(10n),
      getBlock: vi.fn().mockResolvedValue({
        number: 10n,
        transactions: [
          { hash: "0xdd", to: R1, from: "0x00000000000000000000000000000000000000aa", value: 1_000n },
        ],
      }),
      getLogs: vi.fn(),
    } as any;

    const seen = [];
    for await (const delivered of pollTransfers({
      transfers: rows,
      publicClient: client,
      timeout: 5_000,
      fromBlock: 10n,
      pollIntervalMs: 1,
    })) {
      seen.push(delivered.transfer.transactionHash);
    }

    expect(seen).toEqual(["0xdd"]);
    expect(client.getLogs).not.toHaveBeenCalled();
  });
});
