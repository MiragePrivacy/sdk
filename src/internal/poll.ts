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
  signal?: AbortSignal;
}): AsyncGenerator<DeliveredTransfer> {
  const {
    transfers,
    publicClient,
    timeout,
    signal,
    pollIntervalMs = 2000,
  } = params;

  const startBlock = params.fromBlock ?? (await publicClient.getBlockNumber());
  const deadline = Date.now() + timeout;

  const pending = new Set(transfers.map((_, i) => i));
  const claimed = new Set<string>();
  // Per-row scan cursor for the native branch, so each poll resumes where the
  // last one stopped instead of re-walking the whole range.
  const scanned = new Map<number, bigint>();

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
          // this tick is picked up by the next one.
          let blockNum = scanned.get(index) ?? startBlock;
          for (; blockNum <= currentBlock; blockNum++) {
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
          // No toBlock: the node resolves the upper bound against its own head.
          // A pinned number can exceed the head of a lagging node behind a load
          // balancer, which rejects the range outright.
          const logs = await publicClient.getLogs({
            address: row.tokenAddress,
            event: transferEventAbi,
            args: { to: row.recipientAddress },
            fromBlock: startBlock,
          });

          const match = logs.find(
            (log) =>
              log.args.value === row.amount &&
              !claimed.has(`${log.transactionHash}:${log.logIndex}`),
          );

          if (match) {
            claimed.add(`${match.transactionHash}:${match.logIndex}`);
            delivered.push({
              index,
              row,
              transfer: {
                transactionHash: match.transactionHash!,
                blockNumber: match.blockNumber,
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
