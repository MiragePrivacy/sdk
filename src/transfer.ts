import type { Address, Hash, PublicClient, WalletClient } from "viem";
import type {
  EscrowKind,
  FeeEstimate,
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
  walletClient: WalletClient;
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

/** Translate the network's attestation policy into fetch options. */
function attestationOptions(network: NetworkConfig): { verify?: VerifyAttestationOptions | false } {
  const policy = network.attestation;
  if (!policy?.required) return {};
  return {
    verify: {
      expectedMrEnclave: policy.expectedMrEnclave,
      expectedMrSigner: policy.expectedMrSigner,
      allowedTcbStatus: policy.allowedTcbStatus,
      allowDebug: policy.allowDebug,
      maxAgeSecs: policy.maxAgeSecs,
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

  const metadata = await Promise.all(
    rows.map((row) => getTokenMetadata(row.tokenAddress, publicClient)),
  );
  const decimals = metadata.map((m) => m.decimals);
  const rewardDecimals =
    metadata.find((m) => m.address.toLowerCase() === rewardToken.toLowerCase())?.decimals ??
    decimals[0];

  const ethPriceUsd = await resolveEthPrice(network, publicClient, rewardToken, rewardDecimals);

  const health = await fetchLimits(network.apiServer);
  checkLimits({
    health,
    chainId: network.chainId,
    rows,
    decimals,
    ethPriceUsd,
    hasAccessToken: !!accessToken,
  });

  const obfuscation = options.skipObfuscation
    ? undefined
    : await fetchObfuscation(network.apiServer, escrowType);

  // Platform fee is charged on the whole batch, normalized to the reward asset.
  // Scale in bigint: converting via float loses precision at 18 decimals.
  const platformFeeBase = rows.reduce((sum, row, i) => {
    const scaled = scaleAmount(row.amount, decimals[i], rewardDecimals);
    return sum + (isNativeToken(row.tokenAddress) ? applyEthPrice(scaled, ethPriceUsd) : scaled);
  }, 0n);

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
    obfuscation,
    maxRowUsd: Math.max(...rows.map((row, i) => rowValueUsd(row, decimals[i], ethPriceUsd))),
    whitelistThresholdUsd: threshold != null ? Number(threshold) : undefined,
  };
}

export async function prepareTransfer(params: TransferParams): Promise<PreparedTransfer> {
  const context = await buildContext(params);
  return {
    fees: context.fees,
    execute: () => executeTransfer(params, context),
  };
}

async function* executeTransfer(
  params: TransferParams,
  cached?: TransferContext,
): AsyncGenerator<TransferStep> {
  const {
    walletClient,
    publicClient,
    network,
    accessToken,
    abortSignal,
    resume,
    pollTimeout = DEFAULT_POLL_TIMEOUT,
  } = params;

  const account = getAccount(walletClient);
  const context = cached ?? (await buildContext(params, { skipObfuscation: !!resume }));
  const { rows, escrowType, rewardToken, fees } = context;

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
  let userApproveGas: bigint | undefined;
  let userDeployGas: bigint | undefined;
  let userGasPrice: bigint | undefined;

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
    }

    deployedAt = Date.now();

    yield {
      step: "deploy",
      hash: deployHash,
      escrowAddress,
      escrowType,
      secrets: {
        escrowAddress,
        escrowType,
        blindingScalar,
        seed: seed!,
        selectorMapping,
        deployHash,
        deployedAt,
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
  const fromBlock = await publicClient.getBlockNumber();

  const signalResponse = await submitSignal({
    escrowAddress: escrow,
    escrowType,
    tokenAddress: rewardToken,
    transfers: rows,
    rewardAmount: fees.rewardAmount,
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
