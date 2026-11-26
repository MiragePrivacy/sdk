import type { Address } from "viem";
import { isErc3009Asset } from "./erc3009.js";
import { ApiError, MirageError } from "../errors.js";
import type {
  EscrowKind,
  FundingMode,
  ExecutionApproval,
  NetworkConfig,
  NetworkKeyStatus,
} from "../types.js";
import { verifyAttestation, type VerifyAttestationOptions } from "./attestation.js";

import { request } from "./request.js";

export interface CamouflageResult {
  camouflagedBytecode: `0x${string}`;
  selectorMapping?: Record<string, string>;
  originalSize: number;
  camouflagedSize: number;
  /** API-simulated gas units for deploying the camouflaged escrow. */
  deploymentGasEstimate?: bigint;
  seed: string;
}

export async function fetchCamouflage(
  apiServer: string,
  escrowType: EscrowKind,
  fundingMode?: FundingMode,
): Promise<CamouflageResult> {
  // Generate random 32-byte seed
  const seedBytes = new Uint8Array(32);
  crypto.getRandomValues(seedBytes);
  const seed = Array.from(seedBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const init: RequestInit = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ options: { seed }, escrow_type: escrowType, ...fundingFields(fundingMode) }),
  };
  type EscrowCamouflageResponse = {
    funding_mode?: unknown;
    camouflaged_bytecode?: string;
    obfuscated_bytecode?: string;
    selector_mapping?: Record<string, string>;
    original_size: number;
    camouflaged_size?: number;
    obfuscated_size?: number;
    gas_analysis?: {
      camouflaged_gas_estimate?: number | null;
      obfuscated_gas_estimate?: number | null;
    } | null;
  };

  let res: EscrowCamouflageResponse;
  try {
    res = await request<EscrowCamouflageResponse>(`${apiServer}/camouflage_escrow`, init);
  } catch (error) {
    if (!(error instanceof ApiError) || error.statusCode !== 404) throw error;
    res = await request<EscrowCamouflageResponse>(`${apiServer}/obfuscate_escrow`, init);
  }

  assertFundingMode(fundingMode, res.funding_mode);
  const bytecode = (res.camouflaged_bytecode ?? res.obfuscated_bytecode)?.trim();
  const size = res.camouflaged_size ?? res.obfuscated_size;
  if (!bytecode || size == null) {
    throw new ApiError(502, "Escrow camouflage response is missing bytecode or size");
  }
  const gas = res.gas_analysis?.camouflaged_gas_estimate ?? res.gas_analysis?.obfuscated_gas_estimate;
  return {
    camouflagedBytecode: (bytecode.startsWith("0x") ? bytecode : `0x${bytecode}`) as `0x${string}`,
    selectorMapping: res.selector_mapping,
    originalSize: res.original_size,
    camouflagedSize: size,
    deploymentGasEstimate: gas == null ? undefined : BigInt(gas),
    seed,
  };
}

function fundingFields(mode?: FundingMode) {
  return mode === "erc3009" ? { funding_mode: mode } : {};
}

function readFundingMode(value: unknown): FundingMode {
  if (value === undefined || value === "allowance") return "allowance";
  if (value === "erc3009") return value;
  throw new MirageError("INVALID_PRICING_QUOTE", "Unknown funding mode returned by the API.");
}

function assertFundingMode(requested: FundingMode | undefined, actual: unknown) {
  if (readFundingMode(actual) !== (requested ?? "allowance")) {
    throw new MirageError("FUNDING_MODE_MISMATCH", "The funding mode returned by the API differs from the request.");
  }
}

export type ComplianceApproval = ExecutionApproval;

/**
 * Fresh approvals are required for first admission. Once admitted, resume
 * uses the immutable signed receipt without refreshing this approval.
 */
export const APPROVAL_MAX_AGE_SECS = 300;

export function isApprovalStale(approvedAt: number, nowSecs = Date.now() / 1000): boolean {
  return nowSecs - approvedAt >= APPROVAL_MAX_AGE_SECS;
}

export type ExecutionMode = "private" | "native";

/**
 * The ZK intent an ERC-20 escrow settles against. The commitment hides the
 * recipient and amount, so the API cannot derive it: the client computes it and
 * the API encodes it verbatim into the constructor.
 */
export interface ZkIntentRequest {
  commitments?: `0x${string}`[];
  commitment: `0x${string}`;
  instance_domain: `0x${string}`;
  request_id: `0x${string}`;
}

export interface PricingSignalRequest {
  asset: string;
  execution_mode: ExecutionMode;
  items: Array<{ client_row_id: string; recipient?: string; amount: string }>;
}

export interface PricingQuote {
  fundingMode?: FundingMode;
  chainId: number;
  expiresAt?: number;
  serviceFee: { asset: Address; amount: bigint };
  deployment: {
    escrowType: EscrowKind;
    constructorArgs: `0x${string}`;
    quoteCommitment: `0x${string}`;
    rewardAsset: Address;
    rewardAmount: bigint;
    depositByAsset: Record<string, bigint>;
    msgValue: bigint;
  };
  sealedPricingAuthorization: `0x${string}`;
}

/**
 * Unsigned quote returned when no sender is supplied. Carries the same fees and
 * funding as a signed quote but omits every deployable field.
 */
export interface PricingPreviewQuote {
  fundingMode: FundingMode;
  chainId: number;
  serviceFee: { asset: Address; amount: bigint };
  rewardAsset: Address;
  rewardAmount: bigint;
  depositByAsset: Record<string, bigint>;
  msgValue: bigint;
}

interface PricingQuoteResponse {
  chain_id: number;
  expires_at?: number;
  service_fee: { asset: Address; amount: string };
  deployment: {
    escrow_type: EscrowKind;
    funding_mode?: FundingMode;
    constructor_args: `0x${string}` | null;
    quote_commitment: `0x${string}` | null;
    reward_asset: Address;
    reward_amount: string;
    deposit_by_asset: Record<string, string>;
    msg_value: string;
  };
  sealed_pricing_authorization: `0x${string}` | null;
}

function parseDepositByAsset(depositByAsset: Record<string, string>): Record<string, bigint> {
  return Object.fromEntries(
    Object.entries(depositByAsset).map(([asset, amount]) => [asset, BigInt(amount)]),
  );
}

function postPricingQuote(
  apiServer: string,
  body: Record<string, unknown>,
): Promise<PricingQuoteResponse> {
  return request<PricingQuoteResponse>(`${apiServer}/pricing/quote`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/**
 * Request unsigned fees and funding for a transfer with no committed sender.
 * The result is display-only: the API returns no commitment, constructor, or
 * pricing authorization, so it can never be deployed.
 */
export async function fetchPricingPreview(
  apiServer: string,
  params: {
    chainId: number;
    escrowType: EscrowKind;
    fundingMode?: FundingMode;
    signals: PricingSignalRequest[];
  },
): Promise<PricingPreviewQuote> {
  const res = await postPricingQuote(apiServer, {
    chain_id: params.chainId,
    escrow_type: params.escrowType,
    ...fundingFields(params.fundingMode),
    // Copy only priced fields: full transfer rows cannot leak recipients.
    signals: params.signals.map(signal => ({
      asset: signal.asset, execution_mode: signal.execution_mode,
      items: signal.items.map(item => ({ client_row_id: item.client_row_id, amount: item.amount })),
    })),
  });

  const fundingMode = readFundingMode(res.deployment.funding_mode);
  if (fundingMode === "erc3009") assertFundingMode(params.fundingMode, fundingMode);
  return {
    fundingMode,
    chainId: res.chain_id,
    serviceFee: { asset: res.service_fee.asset, amount: BigInt(res.service_fee.amount) },
    rewardAsset: res.deployment.reward_asset,
    rewardAmount: BigInt(res.deployment.reward_amount),
    depositByAsset: parseDepositByAsset(res.deployment.deposit_by_asset),
    msgValue: BigInt(res.deployment.msg_value),
  };
}

/** Request the API-authored economics and exact escrow constructor. */
export async function fetchPricingQuote(
  apiServer: string,
  params: {
    chainId: number;
    sender: Address;
    escrowType: EscrowKind;
    fundingMode?: FundingMode;
    blindedSigners: Address[];
    /** Required for ERC-20 escrows and rejected for every other kind. */
    intent?: ZkIntentRequest;
    signals: PricingSignalRequest[];
  },
): Promise<PricingQuote> {
  const res = await postPricingQuote(apiServer, {
    chain_id: params.chainId,
    sender: params.sender,
    escrow_type: params.escrowType,
    ...fundingFields(params.fundingMode),
    blinded_signers: params.blindedSigners,
    ...(params.intent ? { intent: params.intent } : {}),
    signals: params.signals,
  });
  // A signed request must never yield preview fields. Reject rather than
  // deploying against a partial quote.
  if (
    !res.sealed_pricing_authorization ||
    !res.deployment.constructor_args ||
    !res.deployment.quote_commitment
  ) {
    throw new MirageError(
      "INVALID_PRICING_QUOTE",
      "Pricing returned an unsigned preview quote for a committed sender",
    );
  }

  assertFundingMode(params.fundingMode, res.deployment.funding_mode);
  if (params.fundingMode === "erc3009" && (!Number.isSafeInteger(res.expires_at) || (res.expires_at ?? 0) <= Date.now() / 1000)) {
    throw new MirageError("INVALID_PRICING_QUOTE", "Receipt funding requires an unexpired quote.");
  }
  const depositByAsset = parseDepositByAsset(res.deployment.deposit_by_asset);
  const expectedAssets = new Set(params.signals.map(signal => signal.asset.toLowerCase()));
  if (res.deployment.reward_asset.toLowerCase() !== params.signals[0]?.asset.toLowerCase()
    || Object.entries(depositByAsset).some(([asset, amount]) => amount <= 0n || !expectedAssets.delete(asset.toLowerCase()))
    || expectedAssets.size !== 0) {
    throw new MirageError("INVALID_PRICING_QUOTE", "Signed funding assets do not match the requested transfer.");
  }
  if (params.fundingMode === "erc3009") {
    const authorized = params.signals.find(signal => isErc3009Asset(params.chainId, signal.asset));
    const bucket = Object.entries(depositByAsset).find(([asset]) => isErc3009Asset(params.chainId, asset));
    const principal = authorized?.items.reduce((total, item) => total + BigInt(item.amount), 0n);
    const reward = isErc3009Asset(params.chainId, res.deployment.reward_asset) ? BigInt(res.deployment.reward_amount) : 0n;
    if (res.chain_id !== params.chainId || principal === undefined || bucket?.[1] !== principal + reward) {
      throw new MirageError("INVALID_PRICING_QUOTE", "USDC authorization does not match the quoted chain, principal, and reward.");
    }
  }
  return {
    fundingMode: readFundingMode(res.deployment.funding_mode),
    chainId: res.chain_id,
    serviceFee: { asset: res.service_fee.asset, amount: BigInt(res.service_fee.amount) },
    deployment: {
      escrowType: res.deployment.escrow_type,
      constructorArgs: res.deployment.constructor_args,
      quoteCommitment: res.deployment.quote_commitment,
      rewardAsset: res.deployment.reward_asset,
      rewardAmount: BigInt(res.deployment.reward_amount),
      depositByAsset,
      msgValue: BigInt(res.deployment.msg_value),
    },
    sealedPricingAuthorization: res.sealed_pricing_authorization,
    expiresAt: res.expires_at,
  };
}

export interface AddressScreeningReceipt {
  version: number;
  chain_id: number;
  address_hash: `0x${string}`;
  policy_hash: `0x${string}`;
  screened: boolean;
  issued_at: number;
  expires_at: number;
  signature: string;
}

/** Independent requests in random order, without participant roles or plan IDs. */
export async function screenAddresses(
  apiServer: string, chainId: number, addresses: readonly Address[],
): Promise<AddressScreeningReceipt[]> {
  const unique = [...new Map(addresses.map(address => [address.toLowerCase(), address])).values()];
  // Rejection sampling avoids bias; do not preserve sender-first or row order.
  for (let i = unique.length - 1; i > 0; i--) {
    const range = i + 1;
    const ceiling = Math.floor(0x100000000 / range) * range;
    let sample: number;
    do { sample = crypto.getRandomValues(new Uint32Array(1))[0]; } while (sample >= ceiling);
    const j = sample % range;
    [unique[i], unique[j]] = [unique[j], unique[i]];
  }
  const receipts: AddressScreeningReceipt[] = [];
  let next = 0;
  await Promise.all(Array.from({length: Math.min(4, unique.length)}, async () => {
    while (next < unique.length) {
      const address = unique[next++];
      const receipt = await request<AddressScreeningReceipt>(`${apiServer}/compliance/screen`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chain_id: chainId, address }),
      });
      if (receipt.chain_id !== chainId || receipt.version !== 1 || receipt.expires_at <= Date.now() / 1000) {
        throw new MirageError("INVALID_SCREENING_RECEIPT", "Invalid or expired address screening receipt");
      }
      receipts.push(receipt);
    }
  }));
  return receipts;
}

export interface TransferAdmission {
  policy_version: number;
  per_payment_limit_usd: number | null;
  request_limit_usd: number | null;
  single_payment_capacity_usd: number | null;
  funded_total_usd_cents: string;
  capacity: { solvable: boolean | null } | null;
}

/** Amount-only advisory assessment; signed pricing repeats admission internally. */
export function fetchTransferPreflight(apiServer: string, params: {
  chainId: number; escrowType: EscrowKind;
  signals: Array<{ asset: Address; execution_mode: ExecutionMode; amounts: string[] }>;
}): Promise<TransferAdmission> {
  return request(`${apiServer}/transfers/preflight`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chain_id: params.chainId, escrow_type: params.escrowType,
      signals: params.signals.map(signal => ({asset: signal.asset, execution_mode: signal.execution_mode, amounts: [...signal.amounts]})),
    }),
  });
}

export async function fetchComplianceApproval(
  apiServer: string,
  params: {
    txHash: string;
    chainId: number;
    seed: string;
    escrowType: EscrowKind;
    fundingMode?: FundingMode;
    quoteCommitment: `0x${string}`;
    screeningReceipts: AddressScreeningReceipt[];
  },
): Promise<ComplianceApproval> {
  const body: Record<string, unknown> = {
    tx_hash: params.txHash,
    chain_id: params.chainId,
    seed: params.seed,
    escrow_type: params.escrowType,
    ...fundingFields(params.fundingMode),
    quote_commitment: params.quoteCommitment,
    screening_receipts: params.screeningReceipts,
  };

  return request<ComplianceApproval>(`${apiServer}/execution/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export interface AttestResponse {
  // Current nodes nest the key and chain id inside a hash-committed payload.
  payload?: {
    publicKey?: string;
    chainId?: number;
    maxBalanceUsd?: number;
    complianceKeys?: string[];
    pricingKeys?: string[];
  } | null;
  publicKey?: string;
  public_key?: string;
  attestation?: { quote: string; collateral: unknown } | null;
  isDebug?: boolean;
  is_debug?: boolean;
  chainId?: number;
  chain_id?: number;
  mrenclave?: string;
  mrsigner?: string;
}

export interface FetchNetworkKeyOptions {
  /**
   * Verify the SGX quote and bind it to the served payload. Defaults to true:
   * without it the public key is only asserted by whatever host answered the
   * request. Pass false only for local chains and non-SGX test nodes.
   */
  verify?: boolean | VerifyAttestationOptions;
}

/**
 * Nomad proxy base for a chain. The API server forwards to a node it has
 * indexed; nodes are not addressed directly, so there is no per-node URL.
 */
export function nomadProxyUrl(apiServer: string, chainId: number): string {
  return `${apiServer.replace(/\/+$/, "")}/nomad/${chainId}`;
}

export async function fetchNetworkKey(
  apiServer: string,
  chainId: number,
  options: FetchNetworkKeyOptions = {},
): Promise<NetworkKeyStatus> {
  const res = await request<AttestResponse>(`${nomadProxyUrl(apiServer, chainId)}/attest`);

  const publicKey = res.payload?.publicKey ?? res.publicKey ?? res.public_key ?? "";
  if (!publicKey) {
    throw new ApiError(200, "Attestation response missing enclave public key", res);
  }

  const status: NetworkKeyStatus = {
    publicKey,
    complianceKeys: res.payload?.complianceKeys,
    attested: res.attestation !== null && res.attestation !== undefined,
    debug: res.isDebug ?? res.is_debug ?? false,
    chainId: Number(res.payload?.chainId ?? res.chainId ?? res.chain_id ?? 0),
    mrenclave: res.mrenclave,
    mrsigner: res.mrsigner,
  };

  const verify = options.verify ?? true;
  if (verify === false) return status;

  if (!res.attestation) {
    throw new MirageError(
      "ATTESTATION_MISSING",
      "Node served no attestation quote; it is not running in SGX",
    );
  }

  // Only the payload is committed to by the quote, so the top-level fields
  // cannot be trusted once verification is requested.
  if (!res.payload?.publicKey) {
    throw new MirageError(
      "ATTESTATION_MISSING",
      "Node served no attestation payload to verify the quote against",
    );
  }

  const verification = await verifyAttestation(
    res.attestation,
    {
      publicKey: res.payload.publicKey,
      chainId: Number(res.payload.chainId ?? 0),
      maxBalanceUsd: res.payload.maxBalanceUsd,
      complianceKeys: res.payload.complianceKeys,
      pricingKeys: res.payload.pricingKeys,
    },
    typeof verify === "object" ? verify : {},
  );

  return {
    ...status,
    // Report the measurements from the quote rather than the node's own claim.
    publicKey: res.payload.publicKey,
    chainId: Number(res.payload.chainId ?? 0),
    debug: verification.debug,
    mrenclave: verification.mrenclave,
    mrsigner: verification.mrsigner,
    verification,
  };
}

/** Fetch and verify the node key using a network's declared trust policy. */
export function fetchNetworkStatus(network: NetworkConfig): Promise<NetworkKeyStatus> {
  const policy = network.attestation;
  return fetchNetworkKey(network.apiServer, network.chainId, {
    verify:
      policy?.required === false
        ? false
        : {
            expectedMrSigner: policy?.expectedMrSigner,
            allowedTcbStatus: policy?.allowedTcbStatus,
            allowedAdvisoryIds: policy?.allowedAdvisoryIds,
            minimumIsvSvn: policy?.minimumIsvSvn,
            allowDebug: policy?.allowDebug,
            maxAgeSecs: policy?.maxAgeSecs,
          },
  });
}

export interface ApiHealth {
  status: string;
  version?: string;
  /** Per-chain maximum transfer size in USD, keyed by chain id. */
  maxTransferUsd?: Record<string, string | null>;
}

function parseUsdByChain(
  raw: Record<string, number | null> | undefined,
): Record<string, string | null> | undefined {
  if (!raw) return undefined;
  const out: Record<string, string | null> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (!/^\d+$/.test(key)) continue;
    out[key] = typeof value === "number" ? String(value) : null;
  }
  return out;
}

export async function fetchApiHealth(apiServer: string): Promise<ApiHealth> {
  const res = await request<{
    status: string;
    version?: string;
    max_tx_usd?: Record<string, number | null>;
  }>(`${apiServer}/`);

  return {
    status: res.status,
    version: res.version,
    maxTransferUsd: parseUsdByChain(res.max_tx_usd),
  };
}

/**
 * Fetch informational transfer limits with retries. The API remains the
 * authority for enforcing transfer limits.
 */
export async function fetchLimits(apiServer: string, retries = 3): Promise<ApiHealth> {
  let lastError: unknown;
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      return await fetchApiHealth(apiServer);
    } catch (error) {
      lastError = error;
      if (attempt < retries - 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000 * (attempt + 1)));
      }
    }
  }
  throw lastError;
}

/**
 * Fetch the maximum transfer limit (USD) for a specific network.
 * Returns null if no limit is set, undefined if limits are unavailable.
 */
export async function fetchTransferLimit(
  apiServer: string,
  chainId: number,
): Promise<string | null | undefined> {
  const health = await fetchApiHealth(apiServer);
  return health.maxTransferUsd?.[String(chainId)];
}

export interface GasHistoryAverages {
  /** Mean of the daily average max fee per gas, one vote per day. */
  maxFeePerGas: bigint;
  /** Days with a usable sample. */
  sampledDays: number;
  /** Window the server aggregated over. */
  windowDays: number;
}

/**
 * Historical gas averages, for callers surfacing an "elevated gas" indicator.
 * Not used for execution pricing, which reads live gas from the chain.
 */
export async function fetchGasHistoryAverages(
  apiServer: string,
  chainId: number,
): Promise<GasHistoryAverages | null> {
  let res: {
    window_days: number;
    buckets: Array<{ max_fee_per_gas_wei: string | null }>;
  };

  try {
    res = await request(`${apiServer}/gas/history/averages?chain_id=${chainId}`);
  } catch {
    return null;
  }

  let sum = 0n;
  let sampledDays = 0;
  for (const bucket of res.buckets ?? []) {
    if (!bucket.max_fee_per_gas_wei) continue;
    sum += BigInt(bucket.max_fee_per_gas_wei);
    sampledDays += 1;
  }

  if (sampledDays === 0) return null;

  return {
    maxFeePerGas: sum / BigInt(sampledDays),
    sampledDays,
    windowDays: res.window_days,
  };
}
