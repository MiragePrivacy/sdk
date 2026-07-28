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
  const { transfers, publicClient, timeout, signal, pollIntervalMs = 2000 } = params;

  const startBlock = params.fromBlock ?? (await publicClient.getBlockNumber());
  const deadline = Date.now() + timeout;

  const pending = new Set(transfers.map((_, i) => i));
  const claimed = new Set<string>();

  while (pending.size > 0) {
    checkAbort(signal);

    if (Date.now() >= deadline) {
      throw new TransferTimeoutError(timeout);
    }

    const currentBlock = await publicClient.getBlockNumber();
    const delivered: DeliveredTransfer[] = [];

    for (const index of pending) {
      const row = transfers[index];

      if (isNativeToken(row.tokenAddress)) {
        // Native ETH arrives as a plain transaction to the recipient.
        for (let blockNum = startBlock; blockNum <= currentBlock; blockNum++) {
          const block = await publicClient.getBlock({
            blockNumber: blockNum,
            includeTransactions: true,
          });

          const match = block.transactions.find(
            (tx) =>
              typeof tx !== "string" &&
              tx.to?.toLowerCase() === row.recipientAddress.toLowerCase() &&
              tx.value >= row.amount &&
              !claimed.has(tx.hash),
          );

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
      } else {
        const logs = await publicClient.getLogs({
          address: row.tokenAddress,
          event: transferEventAbi,
          args: { to: row.recipientAddress },
          fromBlock: startBlock,
          toBlock: currentBlock,
        });

        const match = logs.find(
          (log) => log.args.value === row.amount && !claimed.has(`${log.transactionHash}:${log.logIndex}`),
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
    }

    for (const item of delivered) {
      pending.delete(item.index);
      yield item;
    }

    if (pending.size === 0) return;

    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
}
