import {
  isAddress,
  type Address,
  type Hash,
  type PublicClient,
  type WalletClient,
} from "viem";
import type {
  ApprovalCheckpoint,
  ApprovalCallbacks,
  AssetRequirement,
  DeploymentHooks,
  PendingDeployment,
  EscrowKind,
  FeeEstimate,
  FeeRefreshOverrides,
  GasPrice,
  NetworkConfig,
  NetworkKeyStatus,
  PreparedTransfer,
  TransferEvent,
  TransferPreview,
  TransferRow,
  TransferSecrets,
  TransferStep,
} from "./types.js";
import {
  MirageError,
  MissingBlindingScalarError,
} from "./errors.js";
import type {
  ObfuscationResult,
  AddressScreeningReceipt,
  PricingQuote,
  PricingSignalRequest,
  ZkIntentRequest,
} from "./internal/api.js";
import {
  fetchComplianceApproval,
  screenAddresses,
  fetchNetworkKey,
  fetchObfuscation,
  fetchPricingPreview,
  fetchPricingQuote,
} from "./internal/api.js";
import type { VerifyAttestationOptions } from "./internal/attestation.js";
import {
  approveQuotedForDeployment,
  buildQuotedApprovalBuckets,
  submitQuotedDeployment,
  estimateQuotedApprovalGas,
  predictContractAddress,
} from "./internal/escrow.js";
import { recoverDeployment } from "./recoverDeployment.js";
import { deriveBlindedSigners } from "./internal/bond.js";
import { deriveSalt, intentCommitment, randomBytes32 } from "./internal/zk.js";
import type { IntentOpening as ZkIntentOpening } from "./internal/zk.js";
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
  /** Multi-recipient form. Two or more rows use EscrowBatch. */
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
  /** Recommended EIP-1559 fees for wallet approval and deployment transactions. */
  gasPrice?: GasPrice;
  abortSignal?: AbortSignal;
  pollTimeout?: number;
  /**
   * Largest block span one eth_getLogs may cover. Lower it for providers with
   * a cap below the 10k default; a transfer resumed further back than this is
   * scanned in windows.
   */
  maxBlockRange?: bigint;
}

function isUserRejection(error: unknown): boolean {
  const seen = new Set<unknown>();
  while (error && typeof error === "object" && !seen.has(error)) {
    seen.add(error);
    if ("code" in error && error.code === 4001) return true;
    error = "cause" in error ? error.cause : undefined;
  }
  return false;
}

const DEFAULT_POLL_TIMEOUT = 120_000;

function resolveRows(params: {
  transfers?: TransferRow[];
  tokenAddress?: Address;
  recipientAddress?: Address;
  amount?: bigint;
}): TransferRow[] {
  const rows = params.transfers?.length
    ? params.transfers
    : params.tokenAddress &&
        params.recipientAddress &&
        params.amount !== undefined
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
  const intents = new Set<string>();
  for (const row of rows) {
    const key = `${row.tokenAddress.toLowerCase()}:${row.recipientAddress.toLowerCase()}:${row.amount}`;
    if (intents.has(key)) {
      throw new MirageError("INVALID_PARAMS", "Identical transfer rows are not supported");
    }
    intents.add(key);
  }
  return rows;
}

/** Select the contract variant before requesting its quote and bytecode. */
function selectEscrowType(rows: TransferRow[]): EscrowKind {
  if (rows.length > 1) return "batch";
  return isNativeToken(rows[0].tokenAddress) ? "native" : "erc20";
}

function resolveSender(params: TransferParams): Address {
  const walletSender = params.walletClient
    ? getAccount(params.walletClient)
    : undefined;
  const sender =
    params.resume?.senderAddress ?? params.senderAddress ?? walletSender;
  if (!sender) {
    throw new MirageError(
      "SENDER_REQUIRED",
      "senderAddress or walletClient is required to request a pricing quote",
    );
  }
  if (walletSender && walletSender.toLowerCase() !== sender.toLowerCase()) {
    throw new MirageError(
      "ACCOUNT_CHANGED",
      "The active wallet does not match the quoted sender",
    );
  }
  return sender;
}

function attestationOptions(network: NetworkConfig): {
  verify: VerifyAttestationOptions | false;
} {
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
 * Builds commitments in the signed quote's asset-grouped row order.
 *
 * The commitment binds the escrow address, so the deployment nonce is read here
 * and the resulting address must be the one the deployment actually takes. The
 * salt is derived from the blinding scalar rather than transmitted: the enclave
 * already receives the scalar inside the Signal and recovers the same value.
 */
async function buildZkIntent(params: {
  network: NetworkConfig;
  sender: Address;
  rows: TransferRow[];
  blindingScalar: `0x${string}`;
  publicClient: PublicClient;
}): Promise<{ request: ZkIntentRequest; opening: ZkIntentOpening }> {
  const instanceDomain = randomBytes32();
  const requestId = randomBytes32();
  // Funding consists of the positive transfer principals plus a reward in
  // the first signal's asset. The signed response must contain those exact assets.
  const signals = buildPricingSignals(params.rows);
  const nonceOffset = signals.filter(signal => !isNativeToken(signal.asset as Address)).length;
  const escrow = predictContractAddress(
    params.sender,
    (await params.publicClient.getTransactionCount({
      address: params.sender,
      blockTag: "pending",
    })) + nonceOffset,
  );
  const orderedRows = signals.flatMap((signal) =>
    signal.items.map((item) => params.rows[Number(item.client_row_id.slice(4))]),
  );
  const openings = orderedRows.map((row, rowIndex) => ({
    instanceDomain,
    chainId: params.network.chainId,
    escrow,
    requestId,
    rowIndex,
    asset: row.tokenAddress,
    recipient: row.recipientAddress,
    amount: row.amount,
    salt: deriveSalt(params.blindingScalar, instanceDomain, requestId, rowIndex),
  }));
  const opening = openings[0];
  return {
    request: {
      commitment: intentCommitment(opening),
      ...(openings.length > 1 ? { commitments: openings.map(intentCommitment) } : {}),
      instance_domain: instanceDomain,
      request_id: requestId,
    },
    opening,
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

/** Pairs each API-required deposit with the principal the caller requested. */
function assetRequirements(
  rows: TransferRow[],
  depositByAsset: Record<string, bigint>,
): AssetRequirement[] {
  const principal = new Map<string, bigint>();
  for (const row of rows) {
    const key = row.tokenAddress.toLowerCase();
    principal.set(key, (principal.get(key) ?? 0n) + row.amount);
  }
  return Object.entries(depositByAsset).map(([asset, amount]) => ({
    tokenAddress: asset as Address,
    transferAmount: principal.get(asset.toLowerCase()) ?? 0n,
    escrowAmount: amount,
  }));
}

function feeEstimate(
  rows: TransferRow[],
  quote: PricingQuote,
  approvalGasEstimate?: bigint,
  deploymentGasEstimate?: bigint,
): FeeEstimate {
  const totalWalletGasEstimate =
    approvalGasEstimate !== undefined && deploymentGasEstimate !== undefined
      ? approvalGasEstimate + deploymentGasEstimate
      : undefined;
  return {
    serviceFee: quote.serviceFee,
    approvalGasEstimate,
    deploymentGasEstimate,
    totalWalletGasEstimate,
    rewardAsset: quote.deployment.rewardAsset,
    rewardAmount: quote.deployment.rewardAmount,
    depositByAsset: { ...quote.deployment.depositByAsset },
    msgValue: quote.deployment.msgValue,
    assetRequirements: assetRequirements(rows, quote.deployment.depositByAsset),
  };
}

interface TransferContext {
  expectedEscrowAddress?: Address;
  rows: TransferRow[];
  escrowType: EscrowKind;
  sender: Address;
  networkKey: NetworkKeyStatus;
  blindedSigners: Address[];
  blindingScalar: `0x${string}`;
  quote: PricingQuote;
  fees: FeeEstimate;
  obfuscation?: ObfuscationResult;
  screeningReceipts?: AddressScreeningReceipt[];
}

function isValidFundingMap(value: unknown): value is Record<string, bigint> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.entries(value).every(
    ([asset, amount]) =>
      isAddress(asset) && typeof amount === "bigint" && amount >= 0n,
  );
}

function quoteFromResume(params: TransferParams): PricingQuote {
  const resume = params.resume!;
  const rows = resolveRows(params);
  const escrowMatchesRows =
    (resume.escrowType === "batch" && rows.length > 1) ||
    (rows.length === 1 &&
      ((resume.escrowType === "native" &&
        isNativeToken(rows[0].tokenAddress)) ||
        (resume.escrowType === "erc20" &&
          !isNativeToken(rows[0].tokenAddress))));
  if (
    !["erc20", "native", "batch"].includes(resume.escrowType) ||
    !escrowMatchesRows ||
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
      escrowType: resume.escrowType,
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
  const escrowType = params.resume?.escrowType ?? selectEscrowType(rows);
  const sender = resolveSender(params);
  const networkKey = await fetchNetworkKey(
    params.network.apiServer,
    params.network.chainId,
    attestationOptions(params.network),
  );
  if (
    networkKey.chainId !== 0 &&
    networkKey.chainId !== params.network.chainId
  ) {
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
      escrowType,
      sender,
      networkKey,
      blindedSigners: [],
      blindingScalar: params.resume.blindingScalar,
      quote,
      fees: feeEstimate(rows, quote),
    };
  }

  const screeningReceipts = await screenAddresses(params.network.apiServer, params.network.chainId, [sender, ...rows.map(row => row.recipientAddress)]);
  const blinded = deriveBlindedSigners(networkKey.publicKey, rows.length);
  // An ERC-20 escrow settles against a commitment rather than stored transfer
  // details, and the commitment binds the escrow address, so it must be
  // predicted before the constructor is priced.
  const intent = await buildZkIntent({
    network: params.network,
    sender,
    rows,
    blindingScalar: blinded.blindingScalar,
    publicClient: params.publicClient,
  });
  const [quote, obfuscation] = await Promise.all([
    fetchPricingQuote(params.network.apiServer, {
      chainId: params.network.chainId,
      sender,
      escrowType,
      blindedSigners: blinded.blindedSigners,
      intent: intent?.request,
      signals: buildPricingSignals(rows),
    }),
    fetchObfuscation(params.network.apiServer, escrowType),
  ]);
  if (quote.deployment.escrowType !== escrowType) {
    throw new MirageError(
      "INVALID_PRICING_QUOTE",
      "Pricing quote returned a different escrow type than the requested artifact",
    );
  }
  const approvalGasEstimate = await estimateQuotedApprovalGas({
    depositByAsset: quote.deployment.depositByAsset,
    publicClient: params.publicClient,
    account: sender,
    predictedEscrowAddress: intent.opening.escrow,
  }).catch(() => undefined);

  return {
    rows,
    escrowType,
    sender,
    networkKey,
    screeningReceipts,
    expectedEscrowAddress: intent.opening.escrow,
    blindedSigners: blinded.blindedSigners,
    blindingScalar: blinded.blindingScalar,
    quote,
    fees: feeEstimate(
      rows,
      quote,
      approvalGasEstimate,
      obfuscation.deploymentGasEstimate,
    ),
    obfuscation,
  };
}

function assertQuotedAccount(
  walletClient: WalletClient,
  sender: Address,
): Address {
  const account = getAccount(walletClient);
  if (account.toLowerCase() !== sender.toLowerCase()) {
    throw new MirageError(
      "ACCOUNT_CHANGED",
      "The active wallet does not match the quoted sender",
    );
  }
  return account;
}

/**
 * Stand-in sender for preview gas simulation. ERC-20 `approve` writes an
 * allowance slot without reading the caller's balance, so its gas is the same
 * for any address; only the allowance slot's prior value matters, and a fresh
 * address matches the zero-to-nonzero cost a first-time approver pays.
 */
const PREVIEW_SENDER = "0x0000000000000000000000000000000000000001" as const;

export interface PreviewParams {
  tokenAddress?: Address;
  recipientAddress?: Address;
  amount?: bigint;
  transfers?: TransferRow[];
  network: NetworkConfig;
  /** Enables approval gas simulation. Omit to return fees without wallet gas. */
  publicClient?: PublicClient;
  abortSignal?: AbortSignal;
}

/**
 * Quote fees before a wallet is connected. Requires no sender, wallet, or
 * attestation fetch, and the API returns nothing deployable. Supply a
 * `publicClient` to include wallet gas, simulated against a stand-in sender.
 * Call `prepareTransfer` once the wallet connects for the real sender-bound
 * quote; the two agree on fees for identical rows.
 */
export async function previewTransfer(
  params: PreviewParams,
): Promise<TransferPreview> {
  const rows = resolveRows(params);
  const escrowType = selectEscrowType(rows);
  const [preview, obfuscation] = await Promise.all([
    fetchPricingPreview(params.network.apiServer, {
      chainId: params.network.chainId,
      escrowType,
      signals: buildPricingSignals(rows),
    }),
    fetchObfuscation(params.network.apiServer, escrowType).catch(
      () => undefined,
    ),
  ]);
  checkAbort(params.abortSignal);

  const approvalGasEstimate = params.publicClient
    ? await estimateQuotedApprovalGas({
        depositByAsset: preview.depositByAsset,
        publicClient: params.publicClient,
        account: PREVIEW_SENDER,
      }).catch(() => undefined)
    : undefined;

  const deploymentGasEstimate = obfuscation?.deploymentGasEstimate;
  return {
    serviceFee: preview.serviceFee,
    approvalGasEstimate,
    deploymentGasEstimate,
    totalWalletGasEstimate:
      approvalGasEstimate !== undefined && deploymentGasEstimate !== undefined
        ? approvalGasEstimate + deploymentGasEstimate
        : undefined,
    rewardAsset: preview.rewardAsset,
    rewardAmount: preview.rewardAmount,
    depositByAsset: { ...preview.depositByAsset },
    msgValue: preview.msgValue,
    assetRequirements: assetRequirements(rows, preview.depositByAsset),
  };
}

export async function prepareTransfer(
  params: TransferParams,
): Promise<PreparedTransfer> {
  const context = await buildContext(params);
  let transactionGasPrice = params.gasPrice;
  let checkpoint: ApprovalCheckpoint | undefined;
  let deployedSecrets: TransferSecrets | undefined = params.resume;
  let pending: PendingDeployment | undefined;
  let broadcastHash: Hash | undefined;
  let deployment: Promise<Extract<TransferStep, { step: "deploy" }>> | undefined;
  let approvalBroadcast = false;
  let approvalInProgress = false;

  function timeRemaining(reserveSeconds: number) {
    const minimumExpiry = Date.now() / 1000 + reserveSeconds;
    return (context.quote.expiresAt ?? 0) > minimumExpiry
      && context.screeningReceipts?.every(receipt => receipt.expires_at > minimumExpiry) === true;
  }

  async function canReuseForApproval(): Promise<boolean> {
    if (approvalInProgress || approvalBroadcast || checkpoint || pending || deployment || deployedSecrets || !timeRemaining(15)) return false;
    const nonce = await params.publicClient.getTransactionCount({ address: context.sender, blockTag: "pending" });
    const offset = buildQuotedApprovalBuckets(context.quote.deployment.depositByAsset).length;
    return predictContractAddress(context.sender, nonce + offset) === context.expectedEscrowAddress && timeRemaining(15);
  }

  async function* approve(
    walletClient: WalletClient,
    callbacks?: ApprovalCallbacks,
  ): AsyncGenerator<TransferStep, ApprovalCheckpoint> {
    if (pending || deployment || deployedSecrets) throw new MirageError("INVALID_STAGE", "This deployment has already started.");
    if (approvalInProgress) {
      throw new MirageError(
        "INVALID_STAGE",
        "An approval sequence is already in progress",
      );
    }
    approvalInProgress = true;
    try {
      const account = assertQuotedAccount(walletClient, context.sender);
      const iterator = approveQuotedForDeployment({
        depositByAsset: context.quote.deployment.depositByAsset,
        walletClient,
        publicClient: params.publicClient,
        account,
        gasPrice: transactionGasPrice,
        expectedEscrowAddress: context.expectedEscrowAddress,
        onWalletRequest: callbacks?.onWalletRequest,
        onBroadcast: hash => {
          approvalBroadcast = true;
          callbacks?.onBroadcast?.(hash);
        },
        onAbortCheck: () => {
          if (!approvalBroadcast && context.quote.expiresAt !== undefined && !timeRemaining(0)) {
            throw new MirageError("STALE_PREPARATION", "This quote is expiring. Review a fresh quote before approving.");
          }
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

  function deploy(walletClient: WalletClient, approved?: ApprovalCheckpoint, hooks?: DeploymentHooks) {
    deployment ??= runDeployment(walletClient, approved, hooks).finally(() => { deployment = undefined; });
    return deployment;
  }

  async function runDeployment(
    walletClient: WalletClient,
    suppliedCheckpoint?: ApprovalCheckpoint,
    hooks?: DeploymentHooks,
  ): Promise<Extract<TransferStep, { step: "deploy" }>> {
    if (deployedSecrets) {
      return {
        step: "deploy",
        hash: deployedSecrets.deployHash,
        escrowAddress: deployedSecrets.escrowAddress,
        escrowType: deployedSecrets.escrowType,
        secrets: deployedSecrets,
      };
    }
    const account = assertQuotedAccount(walletClient, context.sender);
    checkAbort(params.abortSignal);
    assertAccountUnchanged(walletClient, account);
    if (!context.obfuscation) {
      throw new MirageError(
        "MISSING_OBFUSCATION",
        "Escrow bytecode was not fetched",
      );
    }

    if (!pending) {
      const approved = suppliedCheckpoint ?? checkpoint;
      const artifact = context.obfuscation;
      const quote = context.quote;
      try {
        broadcastHash = await submitQuotedDeployment({
          bytecode: artifact.obfuscatedBytecode,
          constructorArgs: quote.deployment.constructorArgs,
          depositByAsset: quote.deployment.depositByAsset,
          msgValue: quote.deployment.msgValue,
          walletClient,
          publicClient: params.publicClient,
          account,
          gasEstimate: artifact.deploymentGasEstimate,
          gasPrice: transactionGasPrice,
          checkpoint: approved,
          expectedEscrowAddress: context.expectedEscrowAddress,
          chainId: params.network.chainId,
          beforeSend: async ({ nonce, escrowAddress, inputHash, fromBlock }) => {
            checkAbort(params.abortSignal);
            assertAccountUnchanged(walletClient, account);
            if (quote.expiresAt !== undefined && quote.expiresAt <= Date.now() / 1000 + 15) {
              throw new MirageError("STALE_PREPARATION", "Review a fresh quote before deploying the escrow.");
            }
            const recovery: PendingDeployment = {
              version: 1, chainId: params.network.chainId, nonce, fromBlock, inputHash, createdAt: Date.now(),
              secrets: {
                escrowAddress,
                escrowType: context.escrowType,
                blindingScalar: context.blindingScalar,
                seed: artifact.seed,
                selectorMapping: artifact.selectorMapping,
                userApproveGas: approved?.approveGasUsed,
                rewardAmount: quote.deployment.rewardAmount,
                rewardAsset: quote.deployment.rewardAsset,
                quoteCommitment: quote.deployment.quoteCommitment,
                sealedPricingAuthorization: quote.sealedPricingAuthorization,
                serviceFee: quote.serviceFee,
                depositByAsset: quote.deployment.depositByAsset,
                msgValue: quote.deployment.msgValue,
                senderAddress: account,
              },
            };
            await hooks?.onPrepared?.(recovery);
            pending = recovery;
            checkAbort(params.abortSignal);
            assertAccountUnchanged(walletClient, account);
          },
        });
      } catch (error) {
        // Only an explicit EIP-1193 user rejection permits another wallet submission.
        if (isUserRejection(error)) pending = undefined;
        throw error;
      }
      await hooks?.onBroadcast?.(broadcastHash);
    }
    if (!pending) throw new MirageError("INVALID_DEPLOYMENT", "Deployment checkpoint unavailable.");
    const step = await recoverDeployment({ publicClient: params.publicClient, pending, hash: broadcastHash });
    deployedSecrets = step.secrets;
    return step;
  }

  async function* complete(
    walletClient: WalletClient,
    secrets?: TransferSecrets,
  ): AsyncGenerator<TransferStep> {
    const resume = secrets ?? deployedSecrets ?? params.resume;
    if (!resume) {
      throw new MirageError(
        "INVALID_STAGE",
        "Deploy the transfer before completing it",
      );
    }
    yield* completeTransfer({ ...params, walletClient, resume }, context);
  }

  async function* execute(
    walletClient = params.walletClient,
  ): AsyncGenerator<TransferStep> {
    if (!walletClient) {
      throw new MirageError(
        "WALLET_REQUIRED",
        "A wallet client is required to execute a transfer",
      );
    }
    yield { step: "fees", fees: context.fees };
    if (deployedSecrets) {
      yield* complete(walletClient, deployedSecrets);
      return;
    }

    let approved: ApprovalCheckpoint | undefined;
    if (!pending && !deployment) {
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

  async function refreshFees(
    overrides: FeeRefreshOverrides = {},
  ): Promise<FeeEstimate> {
    if (
      approvalBroadcast ||
      approvalInProgress ||
      pending ||
      deployment ||
      checkpoint ||
      deployedSecrets
    ) {
      throw new MirageError(
        "INVALID_STAGE",
        "The quote is locked once approval has begun",
      );
    }
    if (overrides.gasPrice) transactionGasPrice = overrides.gasPrice;
    if (!context.screeningReceipts?.every(receipt => receipt.expires_at > Date.now()/1000 + 15)) {
      context.screeningReceipts = await screenAddresses(params.network.apiServer, params.network.chainId,
        [context.sender, ...context.rows.map(row => row.recipientAddress)]);
    }
    const intent = await buildZkIntent({
      network: params.network,
      sender: context.sender,
      rows: context.rows,
      blindingScalar: context.blindingScalar,
      publicClient: params.publicClient,
    });
    const refreshedQuote = await fetchPricingQuote(params.network.apiServer, {
      chainId: params.network.chainId,
      sender: context.sender,
      escrowType: context.escrowType,
      blindedSigners: context.blindedSigners,
      intent: intent.request,
      signals: buildPricingSignals(context.rows),
    });
    if (refreshedQuote.deployment.escrowType !== context.escrowType) {
      throw new MirageError(
        "INVALID_PRICING_QUOTE",
        "Pricing quote returned a different escrow type than the requested artifact",
      );
    }
    context.quote = refreshedQuote;
    context.expectedEscrowAddress = intent.opening.escrow;
    const approvalGasEstimate = await estimateQuotedApprovalGas({
      depositByAsset: context.quote.deployment.depositByAsset,
      publicClient: params.publicClient,
      account: context.sender,
      predictedEscrowAddress: intent.opening.escrow,
    }).catch(() => undefined);
    context.fees = feeEstimate(
      context.rows,
      context.quote,
      approvalGasEstimate,
      context.obfuscation?.deploymentGasEstimate,
    );
    return context.fees;
  }

  async function updateTransfers(
    transfers: TransferRow[],
    overrides: FeeRefreshOverrides = {},
  ): Promise<FeeEstimate> {
    if (
      approvalBroadcast ||
      approvalInProgress ||
      pending ||
      deployment ||
      checkpoint ||
      deployedSecrets
    ) {
      throw new MirageError(
        "INVALID_STAGE",
        "Transfers are locked once approval has begun",
      );
    }
    const layoutChanged =
      transfers.length !== context.rows.length ||
      transfers.some(
        (row, index) =>
          row.tokenAddress.toLowerCase() !==
          context.rows[index].tokenAddress.toLowerCase(),
      );
    if (layoutChanged) {
      throw new MirageError(
        "INVALID_PARAMS",
        "Token layout changed; prepare a new transfer to change tokens or row count",
      );
    }
    const previousRows = context.rows;
    const previousReceipts = context.screeningReceipts;
    if (transfers.some((row, index) => row.recipientAddress.toLowerCase() !== previousRows[index].recipientAddress.toLowerCase())) {
      context.screeningReceipts = undefined;
    }
    context.rows = transfers;
    try {
      return await refreshFees(overrides);
    } catch (error) {
      context.rows = previousRows;
      context.screeningReceipts = previousReceipts;
      throw error;
    }
  }

  return {
    get fees() {
      return context.fees;
    },
    canReuseForApproval,
    approve,
    deploy,
    complete,
    execute,
    refreshFees,
    updateTransfers,
  };
}

async function* completeTransfer(
  params: TransferParams & {
    walletClient: WalletClient;
    resume: TransferSecrets;
  },
  cached?: TransferContext,
): AsyncGenerator<TransferStep> {
  const context = cached ?? (await buildContext(params));
  const { walletClient, publicClient, network, resume } = params;
  const account = assertQuotedAccount(walletClient, context.sender);
  const escrow = resume.escrowAddress;
  if (!resume.blindingScalar) throw new MissingBlindingScalarError(escrow);

  checkAbort(params.abortSignal, { escrowAddress: escrow });
  assertAccountUnchanged(walletClient, account, escrow);
  const screeningReceipts = context.screeningReceipts?.every(receipt => receipt.expires_at > Date.now()/1000 + 15)
    ? context.screeningReceipts
    : await screenAddresses(network.apiServer, network.chainId,
        [context.sender, ...context.rows.map(row => row.recipientAddress)]);
  const executionApproval = await fetchComplianceApproval(network.apiServer, {
    txHash: resume.deployHash,
    chainId: network.chainId,
    seed: resume.seed,
    escrowType: resume.escrowType,
    quoteCommitment: resume.quoteCommitment,
    screeningReceipts,
  });
  if (
    executionApproval.chainId !== network.chainId ||
    executionApproval.escrowContract.toLowerCase() !== escrow.toLowerCase() ||
    executionApproval.deploymentTxHash.toLowerCase() !==
      resume.deployHash.toLowerCase() ||
    executionApproval.quoteCommitment.toLowerCase() !==
      resume.quoteCommitment.toLowerCase()
  ) {
    throw new MirageError(
      "INVALID_APPROVAL",
      "API execution approval does not match deployment",
    );
  }
  yield { step: "compliance", approval: executionApproval };

  checkAbort(params.abortSignal, { escrowAddress: escrow });
  assertAccountUnchanged(walletClient, account, escrow);
  const response = await submitSignal({
    escrowType: resume.escrowType,
    escrowAddress: escrow,
    blindingScalar: resume.blindingScalar,
    sealedPricingAuthorization: resume.sealedPricingAuthorization,
    executionApproval,
    selectorMapping: resume.selectorMapping,
    deployedAt: resume.deployedAt,
    userApproveGas: resume.userApproveGas,
    userDeployGas: resume.userDeployGas,
    userGasPrice: resume.userGasPrice,
    apiServer: network.apiServer,
    chainId: network.chainId,
    networkKey: context.networkKey,
  });
  yield { step: "signal", response };

  const fromBlock =
    resume.fromBlock ??
    (await publicClient.getTransactionReceipt({ hash: resume.deployHash }))
      .blockNumber;
  const completed: TransferEvent[] = [];
  for await (const delivered of pollTransfers({
    transfers: context.rows,
    publicClient,
    timeout: params.pollTimeout ?? DEFAULT_POLL_TIMEOUT,
    fromBlock,
    maxBlockRange: params.maxBlockRange,
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
export async function* executeTransfer(
  params: TransferParams,
): AsyncGenerator<TransferStep> {
  const prepared = await prepareTransfer(params);
  yield* prepared.execute(params.walletClient);
}

