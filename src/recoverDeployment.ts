import { getAddress, keccak256, type Hash, type PublicClient } from "viem";
import { MirageError } from "./errors.js";
import { predictContractAddress } from "./internal/escrow.js";
import type { PendingDeployment, TransferStep } from "./types.js";

const lookupUnavailable = () => new MirageError("DEPLOYMENT_LOOKUP_UNAVAILABLE",
  "The RPC could not locate this deployment. Enter the creation transaction hash from the wallet to check it.");

// Find the earliest block at which the account nonce was greater than the
// submitted nonce. Fetch full transactions only for that single block.
async function findByNonce(publicClient: PublicClient, pending: PendingDeployment) {
  const address = pending.secrets.senderAddress;
  try {
    let high = await publicClient.getBlockNumber({ cacheTime: 0 });
    const count = (blockNumber: bigint) => publicClient.getTransactionCount({ address, blockNumber });
    if (await count(high) <= pending.nonce) {
      throw new MirageError("DEPLOYMENT_NOT_MINED", "The sender's deployment nonce has not been mined yet.");
    }
    if (!pending.fromBlock || !/^\d{1,20}$/.test(pending.fromBlock)) throw lookupUnavailable();
    let low = BigInt(pending.fromBlock);
    if (low > high || high - low >= 2n ** 32n) throw lookupUnavailable();
    while (low < high) {
      const middle = low + (high - low) / 2n;
      if (await count(middle) > pending.nonce) high = middle;
      else low = middle + 1n;
    }
    const block = await publicClient.getBlock({ blockNumber: low, includeTransactions: true });
    const tx = block.transactions.find(candidate =>
      candidate.nonce === pending.nonce && getAddress(candidate.from) === getAddress(address));
    if (!tx) throw lookupUnavailable();
    const receipt = await publicClient.getTransactionReceipt({ hash: tx.hash });
    if (block.hash !== receipt.blockHash) throw lookupUnavailable();
    return { tx, block, receipt };
  } catch (error) {
    if (error instanceof MirageError) throw error;
    throw lookupUnavailable();
  }
}

async function findByHash(publicClient: PublicClient, hash: Hash) {
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  // viem can return a replacement's receipt, including a wallet cancellation.
  const [tx, block] = await Promise.all([
    publicClient.getTransaction({ hash: receipt.transactionHash }),
    publicClient.getBlock({ blockNumber: receipt.blockNumber }),
  ]);
  return { tx, block, receipt };
}

/**
 * Verify a mined deployment against the device-local checkpoint. With no hash,
 * uses the sender and nonce on the original RPC network. Call again when a new
 * block arrives if the nonce has not yet mined. A wallet activity hash also
 * works when the RPC cannot read historical nonce state. Never submits.
 */
export async function recoverDeployment({ publicClient, pending, hash }: {
  publicClient: PublicClient;
  pending: PendingDeployment;
  hash?: Hash;
}): Promise<Extract<TransferStep, { step: "deploy" }>> {
  if (pending.version !== 1 || !Number.isSafeInteger(pending.nonce) || pending.nonce < 0 ||
      (hash !== undefined && !/^0x[0-9a-f]{64}$/i.test(hash)) || !/^0x[0-9a-f]{64}$/i.test(pending.inputHash)) {
    throw new MirageError("INVALID_DEPLOYMENT", "Invalid deployment checkpoint or transaction hash.");
  }
  const { senderAddress, escrowAddress, msgValue } = pending.secrets;
  const sender = getAddress(senderAddress);
  const escrow = getAddress(escrowAddress);
  if (predictContractAddress(sender, pending.nonce) !== escrow) {
    throw new MirageError("INVALID_DEPLOYMENT", "The checkpoint sender and nonce do not match the expected escrow.");
  }
  if ((publicClient.chain && publicClient.chain.id !== pending.chainId) || await publicClient.getChainId() !== pending.chainId) {
    throw new MirageError("DEPLOYMENT_NETWORK_CHANGED", "Switch to the original deployment network to check this transaction.");
  }
  const { tx, block, receipt } = hash
    ? await findByHash(publicClient, hash)
    : await findByNonce(publicClient, pending);
  const minedHash = receipt.transactionHash;
  // The block at this height must still be canonical. Looking up a block by
  // hash alone can return an orphaned block after a reorg.
  const included = block.transactions[receipt.transactionIndex];
  const includedHash = typeof included === "string" ? included : included?.hash;
  if (block.hash !== receipt.blockHash || block.number !== receipt.blockNumber ||
      tx.blockHash !== receipt.blockHash || tx.blockNumber !== receipt.blockNumber || includedHash !== minedHash) {
    throw lookupUnavailable();
  }
  if (tx.hash !== minedHash || getAddress(tx.from) !== sender || tx.nonce !== pending.nonce ||
      (tx.chainId !== undefined && tx.chainId !== pending.chainId)) {
    throw new MirageError("DEPLOYMENT_MISMATCH", "The mined transaction does not match the saved deployment.");
  }
  if (getAddress(receipt.from) !== sender || receipt.to?.toLowerCase() !== tx.to?.toLowerCase() ||
      (receipt.status !== "success" && receipt.status !== "reverted") ||
      (receipt.contractAddress && (tx.to !== null || getAddress(receipt.contractAddress) !== escrow)) ||
      (receipt.status === "success" && tx.to === null && !receipt.contractAddress)) {
    throw new MirageError("DEPLOYMENT_MISMATCH", "This receipt does not confirm creation of the expected escrow.");
  }
  // An unrelated pasted hash never reaches these terminal outcomes. Both require
  // a matching sender and nonce, membership in the canonical block, and an
  // internally consistent receipt on the checkpoint's chain.
  if (tx.to !== null || tx.value !== msgValue || keccak256(tx.input).toLowerCase() !== pending.inputHash.toLowerCase()) {
    throw new MirageError("DEPLOYMENT_NONCE_CONSUMED", "A different mined transaction used the saved deployment nonce.");
  }
  if (receipt.status === "reverted") {
    throw new MirageError("DEPLOYMENT_REVERTED", "The original escrow deployment reverted on-chain.");
  }
  return {
    step: "deploy",
    hash: minedHash,
    escrowAddress,
    escrowType: pending.secrets.escrowType,
    secrets: {
      ...pending.secrets,
      deployHash: minedHash,
      deployedAt: Number(block.timestamp) * 1000,
      fromBlock: receipt.blockNumber,
      userDeployGas: receipt.gasUsed,
      userGasPrice: receipt.effectiveGasPrice,
    },
  };
}
