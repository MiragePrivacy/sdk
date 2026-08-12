import { describe, it, expect, vi } from "vitest";
import { pollTransfers } from "../src/internal/poll.js";
import { TransferTimeoutError } from "../src/errors.js";
import { NATIVE_TOKEN_ADDRESS } from "../src/token.js";
import type { TransferRow } from "../src/types.js";

const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;
const R1 = "0x0000000000000000000000000000000000000001" as const;
const R2 = "0x0000000000000000000000000000000000000002" as const;
const R3 = "0x0000000000000000000000000000000000000003" as const;

function row(
  tokenAddress: string,
  amount: bigint,
  recipientAddress: string,
): TransferRow {
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
    const rows = [
      row(USDC, 100n, R1),
      row(USDC, 200n, R2),
      row(USDC, 300n, R3),
    ];

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
      seen.push({
        index: delivered.index,
        hash: delivered.transfer.transactionHash,
      });
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
    const client = mockClient([
      [log(R1, 100n, "0xaa", 0), log(R1, 100n, "0xbb", 1)],
    ]);

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
          {
            hash: "0xdd",
            to: R1,
            from: "0x00000000000000000000000000000000000000aa",
            value: 1_000n,
          },
        ],
      }),
      getLogs: vi.fn(),
      getTransactionReceipt: vi.fn().mockResolvedValue({ status: "success" }),
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

  it("ignores a reverted native transaction to the recipient", async () => {
    const rows = [row(NATIVE_TOKEN_ADDRESS, 1_000n, R1)];
    const client = {
      getBlockNumber: vi.fn().mockResolvedValue(10n),
      getBlock: vi.fn().mockResolvedValue({
        number: 10n,
        transactions: [
          {
            hash: "0xbad",
            to: R1,
            from: "0x00000000000000000000000000000000000000aa",
            value: 1_000n,
          },
        ],
      }),
      getLogs: vi.fn(),
      getTransactionReceipt: vi.fn().mockResolvedValue({ status: "reverted" }),
    } as any;

    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);

    await expect(
      (async () => {
        for await (const _ of pollTransfers({
          transfers: rows,
          publicClient: client,
          timeout: 5_000,
          fromBlock: 10n,
          pollIntervalMs: 1,
          signal: controller.signal,
        })) {
          // unreachable: the only candidate reverted
        }
      })(),
    ).rejects.toMatchObject({ code: "TRANSFER_ABORTED" });
  });

  it("scans in windows when the start block predates the provider cap", async () => {
    // A transfer resumed long after deploy spans more than one window.
    const rows = [row(USDC, 100n, R1)];
    const delivery = { ...log(R1, 100n, "0xaa"), blockNumber: 2_500n };
    const client = {
      getBlockNumber: vi.fn().mockResolvedValue(2_600n),
      getLogs: vi.fn().mockImplementation(({ fromBlock, toBlock }: any) => {
        // A window wider than the cap is what the provider would reject.
        if (toBlock !== undefined && toBlock - fromBlock >= 1_000n) {
          throw new Error("query returned more than 10000 results");
        }
        const upper = toBlock ?? 2_600n;
        return Promise.resolve(
          delivery.blockNumber >= fromBlock && delivery.blockNumber <= upper
            ? [delivery]
            : [],
        );
      }),
      getBlock: vi.fn(),
      getTransactionReceipt: vi.fn(),
    } as any;

    const seen = [];
    for await (const d of pollTransfers({
      transfers: rows,
      publicClient: client,
      timeout: 5_000,
      fromBlock: 0n,
      maxBlockRange: 1_000n,
      pollIntervalMs: 1,
    })) {
      seen.push(d.transfer.transactionHash);
    }

    expect(seen).toEqual(["0xaa"]);
    // Bounded windows 0-999 and 1000-1999, then the remainder to the head
    // (2000-2600 is under the cap) goes out unbounded.
    const ranges = client.getLogs.mock.calls.map((c: any) => [
      c[0].fromBlock,
      c[0].toBlock,
    ]);
    expect(ranges).toEqual([
      [0n, 999n],
      [1_000n, 1_999n],
      [2_000n, undefined],
    ]);
  });

  it("leaves the window reaching the head unbounded", async () => {
    // The last window must not pin toBlock, or a lagging node rejects it.
    const rows = [row(USDC, 100n, R1)];
    const client = {
      getBlockNumber: vi.fn().mockResolvedValue(500n),
      getLogs: vi.fn().mockResolvedValue([log(R1, 100n, "0xaa")]),
      getBlock: vi.fn(),
      getTransactionReceipt: vi.fn(),
    } as any;

    for await (const _ of pollTransfers({
      transfers: rows,
      publicClient: client,
      timeout: 5_000,
      fromBlock: 0n,
      maxBlockRange: 1_000n,
      pollIntervalMs: 1,
    })) {
      // single delivery
    }

    expect(client.getLogs.mock.calls[0][0]).not.toHaveProperty("toBlock");
  });

  it("surfaces a range rejection instead of retrying until timeout", async () => {
    // A request the provider always rejects must not be absorbed: retrying it
    // for the full poll timeout hides the real cause behind a bare timeout.
    const rows = [row(USDC, 100n, R1)];
    const client = mockClient([[]]);
    client.getLogs.mockRejectedValue(
      new Error("query returned more than 10000 results"),
    );

    await expect(
      (async () => {
        for await (const _ of pollTransfers({
          transfers: rows,
          publicClient: client,
          timeout: 5_000,
          pollIntervalMs: 1,
        })) {
          // unreachable
        }
      })(),
    ).rejects.toThrow(/more than 10000/);

    // Surfaced on the first attempt rather than retried.
    expect(client.getLogs).toHaveBeenCalledTimes(1);
  });

  it("caps how many native blocks one tick walks", async () => {
    // Each block costs a request, so a far-behind resume must not block the
    // tick on a single long sweep.
    const rows = [row(NATIVE_TOKEN_ADDRESS, 1_000n, R1)];
    const controller = new AbortController();
    const client = {
      getBlockNumber: vi.fn().mockResolvedValue(5_000n),
      getBlock: vi.fn().mockImplementation(({ blockNumber }: any) => {
        // Stop once the first capped tick completes, so the count is exact
        // rather than a race against a timer.
        if (blockNumber >= 200n) controller.abort();
        return Promise.resolve({ number: blockNumber, transactions: [] });
      }),
      getLogs: vi.fn(),
      getTransactionReceipt: vi.fn(),
    } as any;

    await expect(
      (async () => {
        for await (const _ of pollTransfers({
          transfers: rows,
          publicClient: client,
          timeout: 5_000,
          fromBlock: 0n,
          pollIntervalMs: 1,
          signal: controller.signal,
        })) {
          // no deliveries
        }
      })(),
    ).rejects.toMatchObject({ code: "TRANSFER_ABORTED" });

    // Blocks 0-200 inclusive: the cap bounds the tick well short of the 5000
    // blocks an uncapped sweep would have walked before yielding.
    expect(client.getBlock).toHaveBeenCalledTimes(201);
  });

  it("leaves toBlock unset so the node resolves its own head", async () => {
    // A pinned toBlock can exceed the head of a lagging node behind a load
    // balancer, which rejects the range outright.
    const rows = [row(USDC, 100n, R1)];
    const client = mockClient([[log(R1, 100n, "0xaa")]]);

    for await (const _ of pollTransfers({
      transfers: rows,
      publicClient: client,
      timeout: 5_000,
      fromBlock: 50n,
      pollIntervalMs: 1,
    })) {
      // single delivery
    }

    expect(client.getLogs).toHaveBeenCalledWith(
      expect.objectContaining({ fromBlock: 50n }),
    );
    expect(client.getLogs.mock.calls[0][0]).not.toHaveProperty("toBlock");
  });

  it("retries the next tick when the RPC rejects a poll", async () => {
    const rows = [row(USDC, 100n, R1)];
    const client = mockClient([[log(R1, 100n, "0xaa")]]);
    client.getLogs
      .mockRejectedValueOnce(
        new Error("block range extends beyond current head block"),
      )
      .mockResolvedValueOnce([log(R1, 100n, "0xaa")]);

    const seen = [];
    for await (const delivered of pollTransfers({
      transfers: rows,
      publicClient: client,
      timeout: 5_000,
      pollIntervalMs: 1,
    })) {
      seen.push(delivered.transfer.transactionHash);
    }

    // The rejection is absorbed and the delivery still lands.
    expect(seen).toEqual(["0xaa"]);
    expect(client.getLogs).toHaveBeenCalledTimes(2);
  });

  it("does not re-walk native blocks already scanned", async () => {
    const rows = [row(NATIVE_TOKEN_ADDRESS, 1_000n, R1)];
    let head = 10n;
    const client = {
      getBlockNumber: vi.fn().mockImplementation(() => {
        const current = head;
        if (head < 12n) head += 1n;
        return Promise.resolve(current);
      }),
      getBlock: vi.fn().mockImplementation(({ blockNumber }: any) =>
        Promise.resolve({
          number: blockNumber,
          transactions:
            blockNumber === 12n
              ? [
                  {
                    hash: "0xdd",
                    to: R1,
                    from: "0x00000000000000000000000000000000000000aa",
                    value: 1_000n,
                  },
                ]
              : [],
        }),
      ),
      getLogs: vi.fn(),
      getTransactionReceipt: vi.fn().mockResolvedValue({ status: "success" }),
    } as any;

    // Head advances while polling; blocks 10-12 should each be fetched once.
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
    const scanned = client.getBlock.mock.calls.map(
      (c: any) => c[0].blockNumber,
    );
    expect(scanned).toEqual([...new Set(scanned)]);
  });

  it("ignores a native transaction whose value does not match exactly", async () => {
    const rows = [row(NATIVE_TOKEN_ADDRESS, 1_000n, R1)];
    const client = {
      getBlockNumber: vi.fn().mockResolvedValue(10n),
      getBlock: vi.fn().mockResolvedValue({
        number: 10n,
        // An unrelated, larger payment to the same recipient.
        transactions: [
          {
            hash: "0xbig",
            to: R1,
            from: "0x00000000000000000000000000000000000000aa",
            value: 5_000n,
          },
        ],
      }),
      getLogs: vi.fn(),
      getTransactionReceipt: vi.fn().mockResolvedValue({ status: "success" }),
    } as any;

    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);

    await expect(
      (async () => {
        for await (const _ of pollTransfers({
          transfers: rows,
          publicClient: client,
          timeout: 5_000,
          fromBlock: 10n,
          pollIntervalMs: 1,
          signal: controller.signal,
        })) {
          // unreachable: value must match exactly
        }
      })(),
    ).rejects.toMatchObject({ code: "TRANSFER_ABORTED" });
  });
});
