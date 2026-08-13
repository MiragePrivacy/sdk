import type { Address, PublicClient } from "viem";
import { parseAbiItem } from "viem";
import { TransferTimeoutError } from "../errors.js";
import { checkAbort } from "./abort.js";
import { isNativeToken } from "../token.js";
import type { TransferEvent, TransferRow } from "../types.js";

const transferEventAbi = parseAbiItem(
  "event Transfer(address indexed from, address indexed to, uint256 value)",
);

export interface DeliveredTransfer {
  transfer: TransferEvent;
  row: TransferRow;
  index: number;
}

/**
 * Providers cap how many blocks one eth_getLogs may span. 10k is the common
 * ceiling (Alchemy, Infura); a resumed transfer deployed further back than
 * that must be scanned in windows rather than one request.
 */
const DEFAULT_MAX_BLOCK_RANGE = 10_000n;

/**
 * Native deliveries cost one getBlock per block, so a far-behind resume is
 * caught up across ticks rather than in one blocking sweep.
 */
const NATIVE_BLOCKS_PER_TICK = 200n;

/**
 * A malformed request fails identically on every retry, so it must surface
 * instead of being absorbed until the poll deadline. Range and parameter
 * rejections are permanent in that sense; a dropped connection or a node
 * briefly behind the head is not.
 */
function isPermanentRpcError(error: unknown): boolean {
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  // A stale head resolves itself on the next tick, so it stays retryable even
  // though the provider reports it as an invalid range.
  if (message.includes("beyond current head")) return false;
  return (
    message.includes("exceed") ||
    message.includes("more than") ||
    message.includes("too large") ||
    message.includes("range is too") ||
    message.includes("query timeout")
  );
}

/**
 * Watch for each recipient's delivery, yielding as they land. The node sends a
 * separate transaction per recipient, so a batch completes incrementally
 * rather than all at once.
 *
 * Each on-chain delivery is matched to at most one row, so repeated rows with
 * identical parameters each consume a distinct delivery.
 */
export async function* pollTransfers(params: {
  transfers: TransferRow[];
  publicClient: PublicClient;
  timeout: number;
  fromBlock?: bigint;
  pollIntervalMs?: number;
  maxBlockRange?: bigint;
  signal?: AbortSignal;
}): AsyncGenerator<DeliveredTransfer> {
  const {
    transfers,
    publicClient,
    timeout,
    signal,
    pollIntervalMs = 2000,
    maxBlockRange = DEFAULT_MAX_BLOCK_RANGE,
  } = params;

  const startBlock = params.fromBlock ?? (await publicClient.getBlockNumber());
  const deadline = Date.now() + timeout;

  const pending = new Set(transfers.map((_, i) => i));
  const claimed = new Set<string>();
  // Per-row scan cursors, so each poll resumes where the last one stopped
  // instead of re-walking the whole range. A transfer resumed long after its
  // deploy starts far behind the head and catches up across several ticks.
  const scanned = new Map<number, bigint>();
  const scannedLogs = new Map<number, bigint>();

  while (pending.size > 0) {
    checkAbort(signal);

    if (Date.now() >= deadline) {
      throw new TransferTimeoutError(timeout);
    }

    const delivered: DeliveredTransfer[] = [];

    for (const index of pending) {
      const row = transfers[index];

      try {
        if (isNativeToken(row.tokenAddress)) {
          // Native ETH arrives as a plain transaction to the recipient, so the
          // blocks must be walked individually. Uncached: a stale head names a
          // block a lagging node cannot serve yet.
          const currentBlock = await publicClient.getBlockNumber({
            cacheTime: 0,
          });

          // Blocks already walked are never re-fetched; anything past the head
          // this tick is picked up by the next one. Each block costs a request,
          // so a far-behind resume is capped per tick to stay responsive to
          // abort and to the deadline rather than blocking on a long catch-up.
          let blockNum = scanned.get(index) ?? startBlock;
          const until =
            currentBlock - blockNum > NATIVE_BLOCKS_PER_TICK
              ? blockNum + NATIVE_BLOCKS_PER_TICK
              : currentBlock;
          for (; blockNum <= until; blockNum++) {
            const block = await publicClient.getBlock({
              blockNumber: blockNum,
              includeTransactions: true,
            });

            // Exact value, matching the ERC20 branch: a larger unrelated payment
            // to the same recipient is not this delivery.
            const candidates = block.transactions.filter(
              (tx) =>
                typeof tx !== "string" &&
                tx.to?.toLowerCase() === row.recipientAddress.toLowerCase() &&
                tx.value === row.amount &&
                !claimed.has(tx.hash),
            );

            let match: (typeof candidates)[number] | undefined;
            for (const candidate of candidates) {
              if (typeof candidate === "string") continue;
              // A reverted transaction still appears in the block but moved no
              // value, so it must not count as a delivery.
              const receipt = await publicClient.getTransactionReceipt({
                hash: candidate.hash,
              });
              if (receipt.status === "success") {
                match = candidate;
                break;
              }
              claimed.add(candidate.hash);
            }

            if (match && typeof match !== "string") {
              claimed.add(match.hash);
              delivered.push({
                index,
                row,
                transfer: {
                  transactionHash: match.hash,
                  blockNumber: block.number,
                  amount: match.value,
                  from: match.from,
                  to: row.recipientAddress,
                },
              });
              break;
            }
          }
          scanned.set(index, blockNum);
        } else {
          const fetchWindow = (fromBlock: bigint, toBlock?: bigint) =>
            publicClient.getLogs({
              address: row.tokenAddress,
              event: transferEventAbi,
              args: { to: row.recipientAddress },
              fromBlock,
              ...(toBlock === undefined ? {} : { toBlock }),
            });

          let from = scannedLogs.get(index) ?? startBlock;
          let match:
            Awaited<ReturnType<typeof fetchWindow>>[number] | undefined;

          // Walk in windows until the remainder fits under the provider's cap.
          // Only a bounded window pins toBlock; the window that reaches the
          // head is left open so the node resolves its own tip, since a pinned
          // number can exceed the head of a lagging node behind a load
          // balancer and be rejected outright.
          while (!match) {
            const head = await publicClient.getBlockNumber({ cacheTime: 0 });
            const bounded = head - from >= maxBlockRange;
            if (!bounded && from > head) break;

            const logs = await fetchWindow(
              from,
              bounded ? from + maxBlockRange - 1n : undefined,
            );

            match = logs.find(
              (log) =>
                log.args.value === row.amount &&
                !claimed.has(`${log.transactionHash}:${log.logIndex}`),
            );

            if (!bounded) break;
            // Only a fully-scanned window may be skipped on the next pass.
            from += maxBlockRange;
            scannedLogs.set(index, from);
            checkAbort(signal);
          }

          if (match) {
            claimed.add(`${match.transactionHash}:${match.logIndex}`);
            delivered.push({
              index,
              row,
              transfer: {
                transactionHash: match.transactionHash!,
                blockNumber: match.blockNumber!,
                amount: match.args.value!,
                from: match.args.from!,
                to: match.args.to!,
              },
            });
          }
        }
      } catch (error) {
        // A transient RPC failure (stale head behind a load balancer, a node
        // dropping a request) must not fail the transfer: the signal is
        // already submitted and the node delivers regardless. Retry on the
        // next tick, still bounded by the deadline above.
        checkAbort(signal);
        if (error instanceof TransferTimeoutError) throw error;
        // A request the provider will reject every time must surface now
        // rather than be retried until the deadline yields a bare timeout.
        if (isPermanentRpcError(error)) throw error;
      }
    }

    for (const item of delivered) {
      pending.delete(item.index);
      yield item;
    }

    if (pending.size === 0) return;

    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
}
