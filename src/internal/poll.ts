import type { Address, PublicClient } from "viem";
import { parseAbiItem } from "viem";
import { TransferTimeoutError } from "../errors.js";
import { checkAbort } from "./abort.js";
import type { TransferEvent } from "../types.js";

const transferEventAbi = parseAbiItem(
  "event Transfer(address indexed from, address indexed to, uint256 value)",
);

export async function pollTransferEvent(params: {
  recipientAddress: Address;
  tokenAddress: Address;
  expectedAmount: bigint;
  publicClient: PublicClient;
  isNativeEth: boolean;
  timeout: number;
  signal?: AbortSignal;
}): Promise<TransferEvent> {
  const { recipientAddress, tokenAddress, expectedAmount, publicClient, isNativeEth, timeout, signal } = params;

  const startBlock = await publicClient.getBlockNumber();
  const deadline = Date.now() + timeout;

  while (Date.now() < deadline) {
    checkAbort(signal);

    if (isNativeEth) {
      // Native ETH: the node sends a regular transaction to the recipient.
      // Watch new blocks for tx.to === recipientAddress with matching value.
      const currentBlock = await publicClient.getBlockNumber();

      for (let blockNum = startBlock; blockNum <= currentBlock; blockNum++) {
        const block = await publicClient.getBlock({
          blockNumber: blockNum,
          includeTransactions: true,
        });

        for (const tx of block.transactions) {
          if (typeof tx === "string") continue;

          if (
            tx.to?.toLowerCase() === recipientAddress.toLowerCase() &&
            tx.value >= expectedAmount
          ) {
            return {
              transactionHash: tx.hash,
              blockNumber: block.number,
              amount: tx.value,
              from: tx.from,
              to: recipientAddress,
            };
          }
        }
      }
    } else {
      // ERC20: look for Transfer event to recipientAddress with matching amount
      const currentBlock = await publicClient.getBlockNumber();
      const logs = await publicClient.getLogs({
        address: tokenAddress,
        event: transferEventAbi,
        args: { to: recipientAddress },
        fromBlock: startBlock,
        toBlock: currentBlock,
      });

      for (const log of logs) {
        const transferAmount = BigInt(log.data);
        if (transferAmount === expectedAmount) {
          return {
            transactionHash: log.transactionHash!,
            blockNumber: log.blockNumber,
            amount: log.args.value!,
            from: log.args.from!,
            to: log.args.to!,
          };
        }
      }
    }

    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  throw new TransferTimeoutError(timeout);
}
