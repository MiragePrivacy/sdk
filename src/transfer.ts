import type { Address, Hash, PublicClient, WalletClient } from "viem";
import type {
  EscrowKind,
  ApprovalCheckpoint,
  FeeEstimate,
  FeeRefreshOverrides,
  GasConstants,
  GasPrice,
  NetworkConfig,
  PreparedTransfer,
  TransferEvent,
  TransferRow,
  TransferSecrets,
  TransferStep,
} from "./types.js";
import {
  MirageError,
  MissingBlindingScalarError,
  TransferLimitError,
  WhitelistRequiredError,
} from "./errors.js";
import { isNativeToken, getTokenMetadata } from "./token.js";
import { estimateFees, resolveEthPrice } from "./internal/fees.js";
import type { ApiHealth, ObfuscationResult } from "./internal/api.js";
import {
  fetchObfuscation,
  fetchComplianceApproval,
  fetchNetworkKey,
  fetchLimits,
  isWhitelistRejection,
} from "./internal/api.js";
import type { VerifyAttestationOptions } from "./internal/attestation.js";
import {
  approveAndDeploy,
  approveForDeployment,
  deployApproved,
  deployAtomicBatch,
  deriveEscrowKind,
  pickRewardToken,
} from "./internal/escrow.js";
import { deriveBlindedSigner } from "./internal/bond.js";
import { submitSignal } from "./internal/nomad.js";
import { pollTransfers } from "./internal/poll.js";
import { checkAbort } from "./internal/abort.js";
import { getAccount, assertAccountUnchanged } from "./internal/account.js";

export interface TransferParams {
  /** Single-recipient form. Mutually exclusive with `transfers`. */
  tokenAddress?: Address;
  recipientAddress?: Address;
  amount?: bigint;
  /** Multi-recipient form. Deploys one batch escrow for all rows. */
  transfers?: TransferRow[];
  /** Optional while preparing a quote; stage methods receive the active wallet. */
  walletClient?: WalletClient;
  publicClient: PublicClient;
  network: NetworkConfig;
  /**
   * Resume a transfer whose escrow is already deployed. Must carry the
   * blinding scalar for non-batch escrows, which only the deploying device
   * holds.
   */
  resume?: TransferSecrets;
  accessToken?: string;
  gasPrice?: GasPrice;
  abortSignal?: AbortSignal;
  pollTimeout?: number;
}

const DEFAULT_POLL_TIMEOUT = 120_000;

/** Normalize either input form into rows. */
function resolveRows(params: TransferParams): TransferRow[] {
  if (params.transfers?.length) return params.transfers;

  const { tokenAddress, recipientAddress, amount } = params;
  if (!tokenAddress || !recipientAddress || amount === undefined) {
    throw new MirageError(
      "INVALID_PARAMS",
      "Provide either transfers[] or tokenAddress + recipientAddress + amount",
    );
  }
  return [{ tokenAddress, recipientAddress, amount }];
}

/** USD value of a row. ERC20 stablecoins are treated as 1:1. */
function rowValueUsd(row: TransferRow, decimals: number, ethPriceUsd: number): number {
  const tokenAmount = Number(row.amount) / 10 ** decimals;
  return isNativeToken(row.tokenAddress) ? tokenAmount * ethPriceUsd : tokenAmount;
}

/** Restate an amount in another token's decimals without losing precision. */
function scaleAmount(amount: bigint, from: number, to: number): bigint {
  if (from === to) return amount;
  return from < to
    ? amount * 10n ** BigInt(to - from)
    : amount / 10n ** BigInt(from - to);
}

/** Convert a native ETH amount to its USD-equivalent stablecoin units. */
function applyEthPrice(amount: bigint, ethPriceUsd: number): bigint {
  // Carry the price at 6 decimals so fractional dollars survive the bigint math.
  return (amount * BigInt(Math.round(ethPriceUsd * 1e6))) / 1_000_000n;
}

/**
 * Batch total normalized to the reward asset's units, for the percentage fee.
 *
 * Native rows are only price-converted when the reward asset is an ERC20, where
 * the fee is charged in stablecoin units. When the reward asset is ETH the fee
 * is charged in wei, so converting to USD there would overcharge by the ETH
 * price.
 */
function computePlatformFeeBase(
  rows: TransferRow[],
  decimals: number[],
  rewardToken: Address,
  rewardDecimals: number,
  ethPriceUsd: number,
): bigint {
  const rewardIsNative = isNativeToken(rewardToken);
  return rows.reduce((sum, row, i) => {
    const scaled = scaleAmount(row.amount, decimals[i], rewardDecimals);
    const convert = !rewardIsNative && isNativeToken(row.tokenAddress);
    return sum + (convert ? applyEthPrice(scaled, ethPriceUsd) : scaled);
  }, 0n);
}

/**
 * Limits and whitelist thresholds apply per transfer, not to the batch total:
 * ten transfers under the limit are allowed even if their sum exceeds it.
 */
function checkLimits(params: {
  health: ApiHealth;
  chainId: number;
  rows: TransferRow[];
  decimals: number[];
  ethPriceUsd: number;
  hasAccessToken: boolean;
}): void {
  const { health, chainId, rows, decimals, ethPriceUsd, hasAccessToken } = params;
  const key = String(chainId);
  const limit = health.maxTransferUsd?.[key];
  const threshold = health.whitelistRequiredUsd?.[key];

  rows.forEach((row, i) => {
    const isNative = isNativeToken(row.tokenAddress);
    // A native row cannot be evaluated without a price; block rather than
    // silently letting it through.
    if (isNative && (!ethPriceUsd || ethPriceUsd <= 0)) {
      throw new MirageError(
        "MISSING_ETH_PRICE",
        "ETH price unavailable; cannot evaluate transfer limits for native ETH",
        { meta: { rowIndex: i } },
      );
    }

    const amountUsd = rowValueUsd(row, decimals[i], ethPriceUsd);

    if (limit != null && amountUsd > Number(limit)) {
      throw new TransferLimitError(amountUsd, Number(limit), i);
    }

    if (threshold != null && amountUsd > Number(threshold) && !hasAccessToken) {
      throw new WhitelistRequiredError(amountUsd, Number(threshold));
    }
  });
}

/**
 * Translate the network's attestation policy into fetch options. Verification
 * is on unless the network explicitly opts out.
 */
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

/** Build gas overrides from API gas analysis, falling back to network defaults. */
function buildGasOverrides(
  gasAnalysis: ObfuscationResult["gasAnalysis"] | undefined,
  networkKind: NetworkConfig["kind"],
): Partial<GasConstants> | undefined {
  if (!gasAnalysis) return undefined;
  const overrides: Partial<GasConstants> = {};
  if (gasAnalysis.deploy !== undefined) overrides.deploy = gasAnalysis.deploy;
  if (gasAnalysis.bond !== undefined) overrides.bond = gasAnalysis.bond;
  if (gasAnalysis.fund !== undefined) overrides.fund = gasAnalysis.fund;
  const collect =
    networkKind === "tempo"
      ? (gasAnalysis.collectTempo ?? gasAnalysis.collect)
      : (gasAnalysis.collectStandard ?? gasAnalysis.collect);
  if (collect !== undefined) overrides.collect = collect;
  return Object.keys(overrides).length > 0 ? overrides : undefined;
}

interface TransferContext {
  rows: TransferRow[];
  escrowType: EscrowKind;
  rewardToken: Address;
  rewardDecimals: number;
  decimals: number[];
  ethPriceUsd: number;
  fees: FeeEstimate;
  platformFeeBase: bigint;
  health: ApiHealth;
  obfuscation?: ObfuscationResult;
  /** Largest single row in USD, for reporting a server-side whitelist refusal. */
  maxRowUsd: number;
  whitelistThresholdUsd?: number;
}

async function buildContext(
  params: TransferParams,
  options: { skipObfuscation?: boolean } = {},
): Promise<TransferContext> {
  const { network, publicClient, gasPrice, accessToken } = params;
  const rows = resolveRows(params);
  const escrowType = params.resume?.escrowType ?? deriveEscrowKind(rows);
  const rewardToken = pickRewardToken(rows);

  const rewardDecimalsOf = (meta: Awaited<ReturnType<typeof getTokenMetadata>>[]) =>
    meta.find((m) => m.address.toLowerCase() === rewardToken.toLowerCase())?.decimals ??
    meta[0].decimals;

  // The price lookup needs the reward decimals, so it chains on metadata; the
  // API fetches are independent and run alongside both. Rows sharing a token
  // share one lookup.
  const uniqueMetadata = new Map<string, ReturnType<typeof getTokenMetadata>>();
  const metadataPromise = Promise.all(
    rows.map((row) => {
      const key = row.tokenAddress.toLowerCase();
      let promise = uniqueMetadata.get(key);
      if (!promise) {
        promise = getTokenMetadata(row.tokenAddress, publicClient);
        uniqueMetadata.set(key, promise);
      }
      return promise;
    }),
  );
  const [metadata, ethPriceUsd, health, obfuscation] = await Promise.all([
    metadataPromise,
    metadataPromise.then((meta) =>
      resolveEthPrice(network, publicClient, rewardToken, rewardDecimalsOf(meta)),
    ),
    fetchLimits(network.apiServer),
    options.skipObfuscation ? undefined : fetchObfuscation(network.apiServer, escrowType),
  ]);
  const decimals = metadata.map((m) => m.decimals);
  const rewardDecimals = rewardDecimalsOf(metadata);

  checkLimits({
    health,
    chainId: network.chainId,
    rows,
    decimals,
    ethPriceUsd,
    hasAccessToken: !!accessToken,
  });

  // Platform fee is charged on the whole batch, normalized to the reward asset.
  // Scale in bigint: converting via float loses precision at 18 decimals.
  const platformFeeBase = computePlatformFeeBase(
    rows,
    decimals,
    rewardToken,
    rewardDecimals,
    ethPriceUsd,
  );

  const fees = await estimateFees({
    transfers: rows,
    escrowType,
    tokenDecimals: rewardDecimals,
    network,
    publicClient,
    gasPrice,
    gasOverrides: buildGasOverrides(obfuscation?.gasAnalysis, network.kind),
    ethToTokenRate: isNativeToken(rewardToken) ? undefined : ethPriceUsd,
    platformFeeBase,
  });

  const threshold = health.whitelistRequiredUsd?.[String(network.chainId)];

  return {
    rows,
    escrowType,
    rewardToken,
    rewardDecimals,
    decimals,
    ethPriceUsd,
    fees,
    platformFeeBase,
    health,
    obfuscation,
    maxRowUsd: Math.max(...rows.map((row, i) => rowValueUsd(row, decimals[i], ethPriceUsd))),
    whitelistThresholdUsd: threshold != null ? Number(threshold) : undefined,
  };
}

export async function prepareTransfer(params: TransferParams): Promise<PreparedTransfer> {
  const context = await buildContext(params);
  let checkpoint: ApprovalCheckpoint | undefined;
  let deployedSecrets: TransferSecrets | undefined = params.resume;
  // Latched once an approval is actually broadcast: from that point the
  // allowances commit to the reward amount, so the transfer must stop being
  // mutable. Kept separate from the in-progress guard below so a rejected
  // wallet prompt, which submits nothing, stays retryable.
  let approvalBroadcast = false;
  let approvalInProgress = false;

  async function* approve(
    walletClient: WalletClient,
  ): AsyncGenerator<TransferStep, ApprovalCheckpoint> {
    if (approvalInProgress) {
      throw new MirageError(
        "INVALID_STAGE",
        "An approval sequence is already in progress for this transfer",
      );
    }
    approvalInProgress = true;
    try {
      return yield* runApprovals(walletClient);
    } finally {
      // Released even on failure; nothing was committed unless a transaction
      // was broadcast, which approvalBroadcast records independently.
      approvalInProgress = false;
    }
  }

  async function* runApprovals(
    walletClient: WalletClient,
  ): AsyncGenerator<TransferStep, ApprovalCheckpoint> {
    const account = getAccount(walletClient);
    const iterator = approveForDeployment({
      transfers: context.rows,
      rewardAmount: context.fees.rewardAmount,
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
      // A yielded step carries a transaction hash, so the allowance is live.
      approvalBroadcast = true;
      yield {
        step: "approve",
        hash: next.value.hash,
        tokenAddress: next.value.tokenAddress,
        index: next.value.index,
        total: next.value.total,
      };
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
        escrowType: deployedSecrets.escrowType,
        secrets: deployedSecrets,
      };
    }
    const account = getAccount(walletClient);
    checkAbort(params.abortSignal);
    assertAccountUnchanged(walletClient, account);
    const obfuscation = context.obfuscation;
    if (!obfuscation) {
      throw new MirageError("MISSING_OBFUSCATION", "Escrow bytecode was not fetched");
    }

    let blindedSigner: Address | undefined;
    let blindingScalar: `0x${string}` | undefined;
    if (context.escrowType !== "batch") {
      const networkKey = await fetchNetworkKey(
        params.network.nomadUrl,
        attestationOptions(params.network),
      );
      const blinded = deriveBlindedSigner(networkKey.publicKey);
      blindedSigner = blinded.blindedSigner;
      blindingScalar = blinded.blindingScalar;
    }

    const deployArgs = {
      bytecode: obfuscation.obfuscatedBytecode,
      escrowType: context.escrowType,
      transfers: context.rows,
      rewardAmount: context.fees.rewardAmount,
      blindedSigner,
      bondPot: context.fees.bondPot,
      walletClient,
      publicClient: params.publicClient,
      account,
    };
    const approval = suppliedCheckpoint ?? checkpoint;
    const result = params.network.enableAtomicBatch
      ? await deployAtomicBatch({ ...deployArgs, selectorMapping: obfuscation.selectorMapping })
      : await deployApproved({ ...deployArgs, checkpoint: approval });
    const receipt = await params.publicClient.getTransactionReceipt({ hash: result.hash });
    deployedSecrets = {
      escrowAddress: result.escrowAddress,
      escrowType: context.escrowType,
      blindingScalar,
      seed: obfuscation.seed,
      selectorMapping: obfuscation.selectorMapping,
      deployHash: result.hash,
      deployedAt: Date.now(),
      fromBlock: receipt.blockNumber,
      userApproveGas: approval?.approveGasUsed,
      userDeployGas: result.deployGasUsed,
      userGasPrice: result.deployEffectiveGasPrice,
      rewardAmount: context.fees.rewardAmount,
    };
    return {
      step: "deploy",
      hash: result.hash,
      escrowAddress: result.escrowAddress,
      escrowType: context.escrowType,
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
    yield* executeTransfer({ ...params, walletClient, resume }, context);
  }

  async function* execute(walletClient = params.walletClient): AsyncGenerator<TransferStep> {
    if (!walletClient) {
      throw new MirageError("WALLET_REQUIRED", "A wallet client is required to execute a transfer");
    }
    yield { step: "fees", fees: context.fees };
    if (deployedSecrets) {
      for await (const step of complete(walletClient, deployedSecrets)) {
        if (step.step !== "fees") yield step;
      }
      return;
    }
    let approved: ApprovalCheckpoint | undefined;
    // On atomic-batch networks deploy() approves inside the batched
    // transaction. Running the standalone pass first would send redundant
    // approvals, break atomicity, and exceed the deploy-only gas the fee
    // estimate assumes.
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
    for await (const step of complete(walletClient, deployed.secrets)) {
      if (step.step !== "fees") yield step;
    }
  }

  async function refreshFees(overrides: FeeRefreshOverrides = {}): Promise<FeeEstimate> {
    if (approvalBroadcast || approvalInProgress || checkpoint || deployedSecrets) {
      throw new MirageError(
        "INVALID_STAGE",
        "Fees are locked once approval has begun; the reward amount is baked into the allowances",
      );
    }
    if (overrides.ethToTokenRate !== undefined) {
      context.ethPriceUsd = overrides.ethToTokenRate;
      // The base values native rows at the ETH price, so a new rate invalidates
      // it. Without this the fee would keep using the old valuation.
      context.platformFeeBase = computePlatformFeeBase(
        context.rows,
        context.decimals,
        context.rewardToken,
        context.rewardDecimals,
        context.ethPriceUsd,
      );
    }
    context.fees = await estimateFees({
      transfers: context.rows,
      escrowType: context.escrowType,
      tokenDecimals: context.rewardDecimals,
      network: params.network,
      publicClient: params.publicClient,
      gasPrice: overrides.gasPrice ?? params.gasPrice,
      gasOverrides: buildGasOverrides(context.obfuscation?.gasAnalysis, params.network.kind),
      ethToTokenRate: isNativeToken(context.rewardToken) ? undefined : context.ethPriceUsd,
      platformFeeBase: context.platformFeeBase,
    });
    return context.fees;
  }

  async function updateTransfers(
    transfers: TransferRow[],
    overrides: FeeRefreshOverrides = {},
  ): Promise<FeeEstimate> {
    if (approvalBroadcast || approvalInProgress || checkpoint || deployedSecrets) {
      throw new MirageError(
        "INVALID_STAGE",
        "Transfers are locked once approval has begun; prepare a new transfer instead",
      );
    }
    // The cached metadata, escrow kind, reward asset, and bytecode are all
    // derived from the token layout, so it is fixed at preparation time.
    const layoutChanged =
      transfers.length !== context.rows.length ||
      transfers.some(
        (row, i) => row.tokenAddress.toLowerCase() !== context.rows[i].tokenAddress.toLowerCase(),
      );
    if (layoutChanged) {
      throw new MirageError(
        "INVALID_PARAMS",
        "Token layout changed; prepare a new transfer to change tokens or row count",
      );
    }
    if (overrides.ethToTokenRate !== undefined) {
      context.ethPriceUsd = overrides.ethToTokenRate;
    }
    checkLimits({
      health: context.health,
      chainId: params.network.chainId,
      rows: transfers,
      decimals: context.decimals,
      ethPriceUsd: context.ethPriceUsd,
      hasAccessToken: !!params.accessToken,
    });
    context.rows = transfers;
    // Recomputed from the new rows here because refreshFees only rebuilds the
    // base when the caller overrides the rate.
    context.platformFeeBase = computePlatformFeeBase(
      transfers,
      context.decimals,
      context.rewardToken,
      context.rewardDecimals,
      context.ethPriceUsd,
    );
    context.maxRowUsd = Math.max(
      ...transfers.map((row, i) => rowValueUsd(row, context.decimals[i], context.ethPriceUsd)),
    );
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

async function* executeTransfer(
  params: TransferParams,
  cached?: TransferContext,
): AsyncGenerator<TransferStep> {
  const {
    walletClient: maybeWalletClient,
    publicClient,
    network,
    accessToken,
    abortSignal,
    resume,
    pollTimeout = DEFAULT_POLL_TIMEOUT,
  } = params;
  if (!maybeWalletClient) {
    throw new MirageError("WALLET_REQUIRED", "A wallet client is required to execute a transfer");
  }
  const walletClient = maybeWalletClient;

  const account = getAccount(walletClient);
  const context = cached ?? (await buildContext(params, { skipObfuscation: !!resume }));
  const { rows, escrowType, rewardToken, fees } = context;
  const rewardAmount = resume?.rewardAmount ?? fees.rewardAmount;

  // Without the scalar the node cannot be authorized to bond, so fail before
  // touching the chain rather than after funds are committed.
  if (resume && escrowType !== "batch" && !resume.blindingScalar) {
    throw new MissingBlindingScalarError(resume.escrowAddress);
  }

  yield { step: "fees", fees };

  let escrowAddress = resume?.escrowAddress;
  let deployHash = resume?.deployHash;
  let selectorMapping = resume?.selectorMapping;
  let seed = resume?.seed;
  let blindingScalar = resume?.blindingScalar;
  let deployedAt = resume?.deployedAt;
  let userApproveGas: bigint | undefined = resume?.userApproveGas;
  let userDeployGas: bigint | undefined = resume?.userDeployGas;
  let userGasPrice: bigint | undefined = resume?.userGasPrice;
  let deployBlock: bigint | undefined = resume?.fromBlock;

  if (!resume) {
    checkAbort(abortSignal);
    assertAccountUnchanged(walletClient, account);

    const obfuscation = context.obfuscation;
    if (!obfuscation) {
      throw new MirageError("MISSING_OBFUSCATION", "Escrow bytecode was not fetched");
    }
    selectorMapping = obfuscation.selectorMapping;
    seed = obfuscation.seed;

    // Batch escrows have no bond pot and no blinded signer.
    let blindedSigner: Address | undefined;
    if (escrowType !== "batch") {
      // The blinded signer is derived from this key and burned into the
      // escrow, so a substituted key would hand bonding rights to an attacker.
      const networkKey = await fetchNetworkKey(network.nomadUrl, attestationOptions(network));
      const blinded = deriveBlindedSigner(networkKey.publicKey);
      blindedSigner = blinded.blindedSigner;
      blindingScalar = blinded.blindingScalar;
    }

    const deployArgs = {
      bytecode: obfuscation.obfuscatedBytecode,
      escrowType,
      transfers: rows,
      rewardAmount: fees.rewardAmount,
      blindedSigner,
      bondPot: fees.bondPot,
      walletClient,
      publicClient,
      account,
    };

    if (network.enableAtomicBatch) {
      const result = await deployAtomicBatch({ ...deployArgs, selectorMapping });
      escrowAddress = result.escrowAddress;
      deployHash = result.hash;
      userDeployGas = result.deployGasUsed;
      userGasPrice = result.deployEffectiveGasPrice;
      deployBlock = result.deployBlock;
    } else {
      const approvalSteps: TransferStep[] = [];
      const result = await approveAndDeploy({
        ...deployArgs,
        onApproval: ({ hash, tokenAddress, index, total }) => {
          approvalSteps.push({ step: "approve", hash, tokenAddress, index, total });
        },
        // Honor a cancel between approvals rather than signing the whole
        // sequence once started.
        onAbortCheck: () => {
          checkAbort(abortSignal);
          assertAccountUnchanged(walletClient, account);
        },
      });

      for (const approval of approvalSteps) {
        yield approval;
      }

      escrowAddress = result.deployResult.escrowAddress;
      deployHash = result.deployResult.hash;
      userApproveGas = result.approveGasUsed || undefined;
      userDeployGas = result.deployResult.deployGasUsed;
      userGasPrice = result.deployResult.deployEffectiveGasPrice;
      deployBlock = result.deployResult.deployBlock;
    }

    deployedAt = Date.now();

    yield {
      step: "deploy",
      hash: deployHash,
      escrowAddress,
      escrowType,
      // Mirror the staged path's secrets exactly. Omitting the reward would
      // make a resume re-estimate it, and a different value than the one
      // committed in the funded escrow gets the signal rejected.
      secrets: {
        escrowAddress,
        escrowType,
        blindingScalar,
        seed: seed!,
        selectorMapping,
        deployHash,
        deployedAt,
        fromBlock: deployBlock,
        userApproveGas,
        userDeployGas,
        userGasPrice,
        rewardAmount: fees.rewardAmount,
      },
    };
  }

  const escrow = escrowAddress!;

  // --- Compliance ---
  let complianceSignature: string | undefined;
  let complianceTimestamp: number | undefined;

  if (network.enableCompliance) {
    if (!deployHash || !seed) {
      // Both come from the deploy step or from resume.secrets. Without them
      // the signal would go out unapproved on a compliance-required network.
      throw new MirageError(
        "MISSING_COMPLIANCE_INPUTS",
        "Compliance requires the deploy tx hash and obfuscation seed",
        { meta: { escrowAddress: escrow } },
      );
    }

    checkAbort(abortSignal, { escrowAddress: escrow });
    assertAccountUnchanged(walletClient, account, escrow);

    try {
      const approval = await fetchComplianceApproval(network.apiServer, {
        txHash: deployHash,
        chainId: network.chainId,
        seed,
        escrowType,
        accessToken,
      });

      complianceSignature = approval.signature;
      complianceTimestamp = approval.timestamp;
      yield {
        step: "compliance",
        approval: { signature: approval.signature, timestamp: approval.timestamp },
      };
    } catch (error) {
      if (isWhitelistRejection(error)) {
        // The escrow is already funded at this point, so report the real
        // figures rather than placeholders.
        throw new WhitelistRequiredError(
          context.maxRowUsd,
          context.whitelistThresholdUsd ?? context.maxRowUsd,
        );
      }
      throw error;
    }
  }

  // --- Signal ---
  checkAbort(abortSignal, { escrowAddress: escrow });
  assertAccountUnchanged(walletClient, account, escrow);

  // The signal is encrypted to this key, so verification here is what keeps
  // the recipient and amounts from being readable by a substituted key.
  const networkKey = await fetchNetworkKey(network.nomadUrl, attestationOptions(network));
  const fromBlock =
    deployBlock ??
    (deployHash
      ? (await publicClient.getTransactionReceipt({ hash: deployHash })).blockNumber
      : await publicClient.getBlockNumber());

  const signalResponse = await submitSignal({
    escrowAddress: escrow,
    escrowType,
    tokenAddress: rewardToken,
    transfers: rows,
    rewardAmount,
    blindingScalar,
    selectorMapping,
    complianceSignature,
    complianceTimestamp,
    deployedAt,
    userApproveGas,
    userDeployGas,
    userGasPrice,
    nomadUrl: network.nomadUrl,
    networkKey,
  });

  yield { step: "signal", response: signalResponse };

  // --- Poll for delivery, emitting each recipient as it lands ---
  const completed: TransferEvent[] = [];

  for await (const delivered of pollTransfers({
    transfers: rows,
    publicClient,
    timeout: pollTimeout,
    fromBlock,
    signal: abortSignal,
  })) {
    completed.push(delivered.transfer);
    yield {
      step: "transfer",
      transfer: delivered.transfer,
      row: delivered.row,
      index: delivered.index,
      total: rows.length,
    };
  }

  yield { step: "complete", transfers: completed };
}

export { executeTransfer };
