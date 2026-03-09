import type { Address, Hash, PublicClient, WalletClient } from "viem";
import type {
  FeeEstimate,
  GasPrice,
  NetworkConfig,
  TransferStep,
} from "./types.js";
import { MirageError, TransferAbortedError } from "./errors.js";
import { isNativeToken } from "./token.js";
import { getTokenMetadata } from "./token.js";
import { estimateFees } from "./internal/fees.js";
import { fetchObfuscation, fetchComplianceApproval, fetchNetworkKey } from "./internal/api.js";
import { approveAndDeploy, deployBatched, withdrawFromEscrow } from "./internal/escrow.js";
import { submitSignal } from "./internal/nomad.js";
import { pollTransferEvent } from "./internal/poll.js";
import { checkAbort } from "./internal/abort.js";
import { getAccount, assertAccountUnchanged } from "./internal/account.js";

export interface TransferParams {
  tokenAddress: Address;
  recipientAddress: Address;
  amount: bigint;
  walletClient: WalletClient;
  publicClient: PublicClient;
  network: NetworkConfig;
  escrowAddress?: Address;
  accessToken?: string;
  gasPrice?: GasPrice;
  abortSignal?: AbortSignal;
  pollTimeout?: number;
}

const DEFAULT_POLL_TIMEOUT = 120_000;

export async function prepareTransfer(params: TransferParams): Promise<FeeEstimate> {
  const { tokenAddress, amount, network, publicClient, gasPrice } = params;
  const token = await getTokenMetadata(tokenAddress, publicClient);

  return estimateFees({
    amount,
    tokenAddress,
    tokenDecimals: token.decimals,
    network,
    publicClient,
    gasPrice,
  });
}

export async function* executeTransfer(
  params: TransferParams,
): AsyncGenerator<TransferStep> {
  const {
    tokenAddress,
    recipientAddress,
    amount,
    walletClient,
    publicClient,
    network,
    accessToken,
    gasPrice,
    abortSignal,
    pollTimeout = DEFAULT_POLL_TIMEOUT,
  } = params;

  if (network.enableCompliance && !accessToken) {
    throw new MirageError(
      "MISSING_ACCESS_TOKEN",
      "accessToken is required when network.enableCompliance is true",
    );
  }

  const account = getAccount(walletClient);
  const isNativeEth = isNativeToken(tokenAddress);
  const token = await getTokenMetadata(tokenAddress, publicClient);

  let escrowAddress = params.escrowAddress;
  let deployHash: Hash | undefined;
  let selectorMapping: Record<string, string> | undefined;
  const isResume = !!escrowAddress;

  if (!isResume) {
    // --- Obfuscation + Fee estimation ---
    checkAbort(abortSignal);

    const obfuscation = await fetchObfuscation(network.apiServer, isNativeEth);
    selectorMapping = obfuscation.selectorMapping;

    const fees = await estimateFees({
      amount,
      tokenAddress,
      tokenDecimals: token.decimals,
      network,
      publicClient,
      gasPrice,
    });

    yield { step: "fees", fees };

    // Compute reward = totalFee - networkFee (what the node gets)
    const rewardAmount = fees.nodeFee + fees.platformFee;

    // --- Approve + Deploy ---
    checkAbort(abortSignal);
    assertAccountUnchanged(walletClient, account);

    if (network.enableBatch) {
      // Tempo: deploy + approve + fund in single batched tx
      const result = await deployBatched({
        bytecode: obfuscation.obfuscatedBytecode,
        selectorMapping,
        tokenAddress,
        recipientAddress,
        transferAmount: amount,
        rewardAmount,
        totalAmount: fees.totalAmount,
        walletClient,
        publicClient,
        account,
      });

      escrowAddress = result.escrowAddress;
      deployHash = result.hash;
      yield { step: "deploy", hash: result.hash, escrowAddress };
    } else {
      // Ethereum: approve predicted address → deploy (constructor pulls via transferFrom)
      const result = await approveAndDeploy({
        bytecode: obfuscation.obfuscatedBytecode,
        selectorMapping,
        tokenAddress,
        recipientAddress,
        transferAmount: amount,
        rewardAmount,
        totalAmount: fees.totalAmount,
        isNativeEth,
        walletClient,
        publicClient,
        account,
      });

      if (result.approveHash) {
        yield { step: "approve", hash: result.approveHash };
      }

      escrowAddress = result.deployResult.escrowAddress;
      deployHash = result.deployResult.hash;
      yield { step: "deploy", hash: result.deployResult.hash, escrowAddress };
    }
  }

  const escrow = escrowAddress!;

  // --- Compliance ---
  let complianceSignature: string | undefined;
  let complianceTimestamp: number | undefined;

  if (network.enableCompliance) {
    checkAbort(abortSignal, { escrowAddress: escrow });
    assertAccountUnchanged(walletClient, account, escrow);

    const txHash = deployHash;
    if (!txHash && !isResume) {
      throw new MirageError("MISSING_DEPLOY_HASH", "Deploy tx hash required for compliance");
    }

    // For resume, compliance may have already been obtained — caller should
    // resume from signal step. But if they pass escrowAddress with compliance
    // enabled, we need the deploy hash. This is a limitation of the resume flow.
    if (txHash) {
      const approval = await fetchComplianceApproval(network.apiServer, {
        txHash,
        chainId: network.chainId,
        accessToken,
      });

      complianceSignature = approval.signature;
      complianceTimestamp = approval.timestamp;
      yield { step: "compliance", approval: { signature: approval.signature, timestamp: approval.timestamp } };
    }
  }

  // --- Signal ---
  checkAbort(abortSignal, { escrowAddress: escrow });
  assertAccountUnchanged(walletClient, account, escrow);

  const networkKey = await fetchNetworkKey(network.nomadUrl);

  // Compute reward for signal (same as during fee estimation)
  // For resume, caller must ensure amount matches original funding
  const fees = await estimateFees({
    amount,
    tokenAddress,
    tokenDecimals: token.decimals,
    network,
    publicClient,
    gasPrice,
  });
  const rewardAmount = fees.nodeFee + fees.platformFee;

  const signalResponse = await submitSignal({
    escrowAddress: escrow,
    recipientAddress,
    transferAmount: amount,
    rewardAmount,
    tokenAddress,
    selectorMapping,
    complianceSignature,
    complianceTimestamp,
    nomadUrl: network.nomadUrl,
    networkKey,
  });

  yield { step: "signal", hash: signalResponse as `0x${string}` };

  // --- Poll for completion ---
  const transfer = await pollTransferEvent({
    recipientAddress,
    tokenAddress,
    expectedAmount: amount,
    publicClient,
    isNativeEth,
    timeout: pollTimeout,
    signal: abortSignal,
  });

  yield { step: "complete", transfer };
}
