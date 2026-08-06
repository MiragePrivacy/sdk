import { isAddress, type Address, type PublicClient, type WalletClient } from "viem";
import type {
  ApprovalCheckpoint,
  FeeEstimate,
  FeeRefreshOverrides,
  GasPrice,
  NetworkConfig,
  NetworkKeyStatus,
  PreparedTransfer,
  TransferEvent,
  TransferRow,
  TransferSecrets,
  TransferStep,
} from "./types.js";
import {
  MirageError,
  MissingBlindingScalarError,
  WhitelistRequiredError,
} from "./errors.js";
import type {
  ObfuscationResult,
  PricingQuote,
  PricingSignalRequest,
} from "./internal/api.js";
import {
  fetchComplianceApproval,
  fetchNetworkKey,
  fetchObfuscation,
  fetchPricingQuote,
  whitelistRequirementFromError,
} from "./internal/api.js";
import type { VerifyAttestationOptions } from "./internal/attestation.js";
import {
  approveQuotedForDeployment,
  deployQuotedApproved,
  deployQuotedAtomic,
} from "./internal/escrow.js";
import { deriveBatchBlindedSigners } from "./internal/bond.js";
import { submitSignal } from "./internal/nomad.js";
import { pollTransfers } from "./internal/poll.js";
import { checkAbort } from "./internal/abort.js";
import { assertAccountUnchanged, getAccount } from "./internal/account.js";
import { isNativeToken } from "./token.js";

export interface TransferParams {
  /** Single-recipient form. Mutually exclusive with `transfers`. */
  tokenAddress?: Address;
  recipientAddress?: Address;
  amount?: bigint;
  /** Multi-recipient form. Every transfer uses EscrowBatch, including n = 1. */
  transfers?: TransferRow[];
  /**
   * Sender committed into the API quote. Required when walletClient is not
   * supplied during preparation.
   */
  senderAddress?: Address;
  walletClient?: WalletClient;
  publicClient: PublicClient;
  network: NetworkConfig;
  /** Exact pricing authorization and scalar retained after deployment. */
  resume?: TransferSecrets;
  accessToken?: string;
  /** @deprecated Pricing gas inputs are resolved by the API. */
  gasPrice?: GasPrice;
  abortSignal?: AbortSignal;
  pollTimeout?: number;
}

const DEFAULT_POLL_TIMEOUT = 120_000;

function resolveRows(params: TransferParams): TransferRow[] {
  const rows = params.transfers?.length
    ? params.transfers
    : params.tokenAddress && params.recipientAddress && params.amount !== undefined
      ? [
          {
            tokenAddress: params.tokenAddress,
            recipientAddress: params.recipientAddress,
            amount: params.amount,
          },
        ]
      : [];
  if (rows.length === 0) {
    throw new MirageError(
      "INVALID_PARAMS",
      "Provide either transfers[] or tokenAddress + recipientAddress + amount",
    );
  }
  return rows;
}

function resolveSender(params: TransferParams): Address {
  const walletSender = params.walletClient ? getAccount(params.walletClient) : undefined;
  const sender = params.resume?.senderAddress ?? params.senderAddress ?? walletSender;
  if (!sender) {
    throw new MirageError(
      "SENDER_REQUIRED",
      "senderAddress or walletClient is required to request a pricing quote",
    );
  }
  if (walletSender && walletSender.toLowerCase() !== sender.toLowerCase()) {
    throw new MirageError("ACCOUNT_CHANGED", "The active wallet does not match the quoted sender");
  }
  return sender;
}

function attestationOptions(network: NetworkConfig): { verify: VerifyAttestationOptions | false } {
  const policy = network.attestation;
  if (policy?.required === false) return { verify: false };
  return {
    verify: {
      expectedMrSigner: policy?.expectedMrSigner,
      allowedTcbStatus: policy?.allowedTcbStatus,
      allowedAdvisoryIds: policy?.allowedAdvisoryIds,
      minimumIsvSvn: policy?.minimumIsvSvn,
      allowDebug: policy?.allowDebug,
      maxAgeSecs: policy?.maxAgeSecs,
    },
  };
}

/**
 * One SDK transfer request becomes one Signal per asset. Asset groups preserve
 * first-appearance order, so the first transfer selects the reward asset.
 */
function buildPricingSignals(rows: TransferRow[]): PricingSignalRequest[] {
  const signals = new Map<string, PricingSignalRequest>();
  rows.forEach((row, rowIndex) => {
    const key = row.tokenAddress.toLowerCase();
    let signal = signals.get(key);
    if (!signal) {
      signal = {
        asset: row.tokenAddress,
        execution_mode: isNativeToken(row.tokenAddress) ? "native" : "private",
        items: [],
      };
      signals.set(key, signal);
    }
    signal.items.push({
      client_row_id: `row-${rowIndex}`,
      recipient: row.recipientAddress,
      amount: row.amount.toString(),
    });
  });
  return [...signals.values()];
}

function feeEstimate(rows: TransferRow[], quote: PricingQuote): FeeEstimate {
  const principal = new Map<string, bigint>();
  for (const row of rows) {
    const key = row.tokenAddress.toLowerCase();
    principal.set(key, (principal.get(key) ?? 0n) + row.amount);
  }
  return {
    serviceFee: quote.serviceFee,
    rewardAsset: quote.deployment.rewardAsset,
    rewardAmount: quote.deployment.rewardAmount,
    depositByAsset: { ...quote.deployment.depositByAsset },
    msgValue: quote.deployment.msgValue,
    assetRequirements: Object.entries(quote.deployment.depositByAsset).map(([asset, amount]) => ({
      tokenAddress: asset as Address,
      transferAmount: principal.get(asset.toLowerCase()) ?? 0n,
      escrowAmount: amount,
    })),
  };
}

interface TransferContext {
  rows: TransferRow[];
  sender: Address;
  networkKey: NetworkKeyStatus;
  blindedSigners: Address[];
  blindingScalar: `0x${string}`;
  quote: PricingQuote;
  fees: FeeEstimate;
  obfuscation?: ObfuscationResult;
}

function isValidFundingMap(value: unknown): value is Record<string, bigint> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.entries(value).every(
    ([asset, amount]) => isAddress(asset) && typeof amount === "bigint" && amount >= 0n,
  );
}

function quoteFromResume(params: TransferParams): PricingQuote {
  const resume = params.resume!;
  if (
    typeof resume.quoteCommitment !== "string" ||
    !resume.quoteCommitment ||
    typeof resume.sealedPricingAuthorization !== "string" ||
    !resume.sealedPricingAuthorization ||
    !isAddress(resume.rewardAsset) ||
    typeof resume.rewardAmount !== "bigint" ||
    resume.rewardAmount < 0n ||
    !resume.serviceFee ||
    !isAddress(resume.serviceFee.asset) ||
    typeof resume.serviceFee.amount !== "bigint" ||
    resume.serviceFee.amount < 0n ||
    !isValidFundingMap(resume.depositByAsset) ||
    typeof resume.msgValue !== "bigint" ||
    resume.msgValue < 0n
  ) {
    throw new MirageError(
      "INVALID_RESUME",
      "Resume data is missing or contains invalid pricing and funding values",
    );
  }
  return {
    chainId: params.network.chainId,
    serviceFee: resume.serviceFee,
    deployment: {
      escrowType: "batch",
      constructorArgs: "0x",
      quoteCommitment: resume.quoteCommitment,
      rewardAsset: resume.rewardAsset,
      rewardAmount: resume.rewardAmount,
      depositByAsset: resume.depositByAsset,
      msgValue: resume.msgValue,
    },
    sealedPricingAuthorization: resume.sealedPricingAuthorization,
  };
}

async function buildContext(params: TransferParams): Promise<TransferContext> {
  const rows = resolveRows(params);
  const sender = resolveSender(params);
  const networkKey = await fetchNetworkKey(
    params.network.nomadUrl,
    attestationOptions(params.network),
  );
  if (networkKey.chainId !== 0 && networkKey.chainId !== params.network.chainId) {
    throw new MirageError(
      "INVALID_NETWORK_KEY",
      `Nomad attested chain ${networkKey.chainId}, expected ${params.network.chainId}`,
    );
  }

  if (params.resume) {
    if (!params.resume.blindingScalar) {
      throw new MissingBlindingScalarError(params.resume.escrowAddress);
    }
    const quote = quoteFromResume(params);
    return {
      rows,
      sender,
      networkKey,
      blindedSigners: [],
      blindingScalar: params.resume.blindingScalar,
      quote,
      fees: feeEstimate(rows, quote),
    };
  }

  const blinded = deriveBatchBlindedSigners(networkKey.publicKey, rows.length);
  const [quote, obfuscation] = await Promise.all([
    fetchPricingQuote(params.network.apiServer, {
      chainId: params.network.chainId,
      sender,
      blindedSigners: blinded.blindedSigners,
      signals: buildPricingSignals(rows),
    }),
    fetchObfuscation(params.network.apiServer, "batch"),
  ]);
  return {
    rows,
    sender,
    networkKey,
    blindedSigners: blinded.blindedSigners,
    blindingScalar: blinded.blindingScalar,
    quote,
    fees: feeEstimate(rows, quote),
    obfuscation,
  };
}

function assertQuotedAccount(walletClient: WalletClient, sender: Address): Address {
  const account = getAccount(walletClient);
  if (account.toLowerCase() !== sender.toLowerCase()) {
    throw new MirageError("ACCOUNT_CHANGED", "The active wallet does not match the quoted sender");
  }
  return account;
}

export async function prepareTransfer(params: TransferParams): Promise<PreparedTransfer> {
  const context = await buildContext(params);
  let checkpoint: ApprovalCheckpoint | undefined;
  let deployedSecrets: TransferSecrets | undefined = params.resume;
  let approvalBroadcast = false;
  let approvalInProgress = false;

  async function* approve(
    walletClient: WalletClient,
  ): AsyncGenerator<TransferStep, ApprovalCheckpoint> {
    if (approvalInProgress) {
      throw new MirageError("INVALID_STAGE", "An approval sequence is already in progress");
    }
    approvalInProgress = true;
    try {
      const account = assertQuotedAccount(walletClient, context.sender);
      const iterator = approveQuotedForDeployment({
        depositByAsset: context.quote.deployment.depositByAsset,
        walletClient,
        publicClient: params.publicClient,
        account,
        onAbortCheck: () => {
          checkAbort(params.abortSignal);
          assertAccountUnchanged(walletClient, account);
        },
      });
      while (true) {
        const next = await iterator.next();
        if (next.done) {
          checkpoint = next.value;
          return next.value;
        }
        approvalBroadcast = true;
        yield {
          step: "approve",
          hash: next.value.hash,
          tokenAddress: next.value.tokenAddress,
          index: next.value.index,
          total: next.value.total,
        };
      }
    } finally {
      approvalInProgress = false;
    }
  }

  async function deploy(
    walletClient: WalletClient,
    suppliedCheckpoint?: ApprovalCheckpoint,
  ): Promise<Extract<TransferStep, { step: "deploy" }>> {
    if (deployedSecrets) {
      return {
        step: "deploy",
        hash: deployedSecrets.deployHash,
        escrowAddress: deployedSecrets.escrowAddress,
        escrowType: "batch",
        secrets: deployedSecrets,
      };
    }
    const account = assertQuotedAccount(walletClient, context.sender);
    checkAbort(params.abortSignal);
    assertAccountUnchanged(walletClient, account);
    if (!context.obfuscation) {
      throw new MirageError("MISSING_OBFUSCATION", "Escrow bytecode was not fetched");
    }

    const approved = suppliedCheckpoint ?? checkpoint;
    const deployParams = {
      bytecode: context.obfuscation.obfuscatedBytecode,
      constructorArgs: context.quote.deployment.constructorArgs,
      depositByAsset: context.quote.deployment.depositByAsset,
      msgValue: context.quote.deployment.msgValue,
      walletClient,
      publicClient: params.publicClient,
      account,
    };
    const result =
      params.network.enableAtomicBatch && !approved
        ? await deployQuotedAtomic(deployParams)
        : await deployQuotedApproved({ ...deployParams, checkpoint: approved });
    deployedSecrets = {
      escrowAddress: result.escrowAddress,
      escrowType: "batch",
      blindingScalar: context.blindingScalar,
      seed: context.obfuscation.seed,
      selectorMapping: context.obfuscation.selectorMapping,
      deployHash: result.hash,
      deployedAt: Date.now(),
      fromBlock: result.deployBlock,
      userApproveGas: approved?.approveGasUsed,
      userDeployGas: result.deployGasUsed,
      userGasPrice: result.deployEffectiveGasPrice,
      rewardAmount: context.quote.deployment.rewardAmount,
      rewardAsset: context.quote.deployment.rewardAsset,
      quoteCommitment: context.quote.deployment.quoteCommitment,
      sealedPricingAuthorization: context.quote.sealedPricingAuthorization,
      serviceFee: context.quote.serviceFee,
      depositByAsset: context.quote.deployment.depositByAsset,
      msgValue: context.quote.deployment.msgValue,
      senderAddress: context.sender,
    };
    return {
      step: "deploy",
      hash: result.hash,
      escrowAddress: result.escrowAddress,
      escrowType: "batch",
      secrets: deployedSecrets,
    };
  }

  async function* complete(
    walletClient: WalletClient,
    secrets?: TransferSecrets,
  ): AsyncGenerator<TransferStep> {
    const resume = secrets ?? deployedSecrets ?? params.resume;
    if (!resume) {
      throw new MirageError("INVALID_STAGE", "Deploy the transfer before completing it");
    }
    yield* completeTransfer({ ...params, walletClient, resume }, context);
  }

  async function* execute(walletClient = params.walletClient): AsyncGenerator<TransferStep> {
    if (!walletClient) {
      throw new MirageError("WALLET_REQUIRED", "A wallet client is required to execute a transfer");
    }
    yield { step: "fees", fees: context.fees };
    if (deployedSecrets) {
      yield* complete(walletClient, deployedSecrets);
      return;
    }

    let approved: ApprovalCheckpoint | undefined;
    if (!params.network.enableAtomicBatch) {
      const approvals = approve(walletClient);
      while (true) {
        const next = await approvals.next();
        if (next.done) {
          approved = next.value;
          break;
        }
        yield next.value;
      }
    }
    const deployed = await deploy(walletClient, approved);
    yield deployed;
    yield* complete(walletClient, deployed.secrets);
  }

  async function refreshFees(_overrides: FeeRefreshOverrides = {}): Promise<FeeEstimate> {
    if (approvalBroadcast || approvalInProgress || checkpoint || deployedSecrets) {
      throw new MirageError("INVALID_STAGE", "The quote is locked once approval has begun");
    }
    context.quote = await fetchPricingQuote(params.network.apiServer, {
      chainId: params.network.chainId,
      sender: context.sender,
      blindedSigners: context.blindedSigners,
      signals: buildPricingSignals(context.rows),
    });
    context.fees = feeEstimate(context.rows, context.quote);
    return context.fees;
  }

  async function updateTransfers(
    transfers: TransferRow[],
    overrides: FeeRefreshOverrides = {},
  ): Promise<FeeEstimate> {
    if (approvalBroadcast || approvalInProgress || checkpoint || deployedSecrets) {
      throw new MirageError("INVALID_STAGE", "Transfers are locked once approval has begun");
    }
    const layoutChanged =
      transfers.length !== context.rows.length ||
      transfers.some(
        (row, index) =>
          row.tokenAddress.toLowerCase() !== context.rows[index].tokenAddress.toLowerCase(),
      );
    if (layoutChanged) {
      throw new MirageError(
        "INVALID_PARAMS",
        "Token layout changed; prepare a new transfer to change tokens or row count",
      );
    }
    context.rows = transfers;
    return refreshFees(overrides);
  }

  return {
    get fees() {
      return context.fees;
    },
    approve,
    deploy,
    complete,
    execute,
    refreshFees,
    updateTransfers,
  };
}

async function* completeTransfer(
  params: TransferParams & { walletClient: WalletClient; resume: TransferSecrets },
  cached?: TransferContext,
): AsyncGenerator<TransferStep> {
  const context = cached ?? (await buildContext(params));
  const { walletClient, publicClient, network, resume } = params;
  const account = assertQuotedAccount(walletClient, context.sender);
  const escrow = resume.escrowAddress;
  if (!resume.blindingScalar) throw new MissingBlindingScalarError(escrow);

  checkAbort(params.abortSignal, { escrowAddress: escrow });
  assertAccountUnchanged(walletClient, account, escrow);
  let executionApproval;
  try {
    executionApproval = await fetchComplianceApproval(network.apiServer, {
      txHash: resume.deployHash,
      chainId: network.chainId,
      seed: resume.seed,
      escrowType: "batch",
      quoteCommitment: resume.quoteCommitment,
      accessToken: params.accessToken,
    });
  } catch (error) {
    const requirement = whitelistRequirementFromError(error);
    if (requirement) {
      throw new WhitelistRequiredError(requirement.amountUsd, requirement.thresholdUsd);
    }
    throw error;
  }
  if (
    executionApproval.chainId !== network.chainId ||
    executionApproval.escrowContract.toLowerCase() !== escrow.toLowerCase() ||
    executionApproval.deploymentTxHash.toLowerCase() !== resume.deployHash.toLowerCase() ||
    executionApproval.quoteCommitment.toLowerCase() !== resume.quoteCommitment.toLowerCase()
  ) {
    throw new MirageError("INVALID_APPROVAL", "API execution approval does not match deployment");
  }
  yield { step: "compliance", approval: executionApproval };

  checkAbort(params.abortSignal, { escrowAddress: escrow });
  assertAccountUnchanged(walletClient, account, escrow);
  const response = await submitSignal({
    escrowAddress: escrow,
    blindingScalar: resume.blindingScalar,
    sealedPricingAuthorization: resume.sealedPricingAuthorization,
    executionApproval,
    selectorMapping: resume.selectorMapping,
    deployedAt: resume.deployedAt,
    userApproveGas: resume.userApproveGas,
    userDeployGas: resume.userDeployGas,
    userGasPrice: resume.userGasPrice,
    nomadUrl: network.nomadUrl,
    networkKey: context.networkKey,
  });
  yield { step: "signal", response };

  const fromBlock =
    resume.fromBlock ??
    (await publicClient.getTransactionReceipt({ hash: resume.deployHash })).blockNumber;
  const completed: TransferEvent[] = [];
  for await (const delivered of pollTransfers({
    transfers: context.rows,
    publicClient,
    timeout: params.pollTimeout ?? DEFAULT_POLL_TIMEOUT,
    fromBlock,
    signal: params.abortSignal,
  })) {
    completed.push(delivered.transfer);
    yield {
      step: "transfer",
      transfer: delivered.transfer,
      row: delivered.row,
      index: delivered.index,
      total: context.rows.length,
    };
  }
  yield { step: "complete", transfers: completed };
}

/** Prepare and execute a transfer in one call. */
export async function* executeTransfer(params: TransferParams): AsyncGenerator<TransferStep> {
  const prepared = await prepareTransfer(params);
  yield* prepared.execute(params.walletClient);
}
