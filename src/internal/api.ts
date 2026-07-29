import { ApiError, MirageError } from "../errors.js";
import type { EscrowKind, NetworkKeyStatus } from "../types.js";
import { verifyAttestation, type VerifyAttestationOptions } from "./attestation.js";

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);

  if (!res.ok) {
    const raw = await res.text().catch(() => "");
    let body: unknown = raw || undefined;
    let detail = "";
    try {
      const parsed = JSON.parse(raw) as { error?: string; details?: string };
      body = parsed;
      detail = parsed.error ?? parsed.details ?? "";
    } catch {
      detail = raw;
    }
    throw new ApiError(
      res.status,
      detail || `API request failed: ${res.status} ${res.statusText}`,
      body,
    );
  }

  return res.json() as Promise<T>;
}

export interface GasAnalysis {
  /** Estimated gas for deploying the obfuscated escrow contract. */
  deploy?: bigint;
  /** Estimated gas for the bond function. */
  bond?: bigint;
  /** Estimated gas for the collect function (fallback when no variant matches). */
  collect?: bigint;
  /** Collect gas for standard EVM networks. */
  collectStandard?: bigint;
  /** Collect gas for tempo. */
  collectTempo?: bigint;
  /** Estimated gas for the fund function. */
  fund?: bigint;
}

export interface ObfuscationResult {
  obfuscatedBytecode: `0x${string}`;
  selectorMapping?: Record<string, string>;
  originalSize: number;
  obfuscatedSize: number;
  gasAnalysis?: GasAnalysis;
  seed: string;
}

export async function fetchObfuscation(
  apiServer: string,
  escrowType: EscrowKind,
): Promise<ObfuscationResult> {
  // Generate random 32-byte seed
  const seedBytes = new Uint8Array(32);
  crypto.getRandomValues(seedBytes);
  const seed = Array.from(seedBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const res = await request<{
    obfuscated_bytecode: string;
    selector_mapping?: Record<string, string>;
    original_size: number;
    obfuscated_size: number;
    gas_analysis?: {
      obfuscated_gas_estimate?: number | null;
      original_gas_estimate?: number | null;
      gas_overhead_percentage?: number | null;
      function_gas?: {
        bond?: number | null;
        collect?: number | null;
        fund?: number | null;
        collect_variants?: {
          standard?: number | null;
          tempo?: number | null;
        } | null;
      } | null;
    } | null;
  }>(`${apiServer}/obfuscate_escrow`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      options: { shuffle: false, seed },
      escrow_type: escrowType,
    }),
  });

  const bytecode = res.obfuscated_bytecode.trim();

  let gasAnalysis: GasAnalysis | undefined;
  if (res.gas_analysis) {
    const ga = res.gas_analysis;
    const fg = ga.function_gas;
    gasAnalysis = {};
    if (ga.obfuscated_gas_estimate != null) gasAnalysis.deploy = BigInt(ga.obfuscated_gas_estimate);
    if (fg?.bond != null) gasAnalysis.bond = BigInt(fg.bond);
    if (fg?.collect != null) gasAnalysis.collect = BigInt(fg.collect);
    if (fg?.fund != null) gasAnalysis.fund = BigInt(fg.fund);
    if (fg?.collect_variants?.standard != null)
      gasAnalysis.collectStandard = BigInt(fg.collect_variants.standard);
    if (fg?.collect_variants?.tempo != null)
      gasAnalysis.collectTempo = BigInt(fg.collect_variants.tempo);
  }

  return {
    obfuscatedBytecode: (bytecode.startsWith("0x") ? bytecode : `0x${bytecode}`) as `0x${string}`,
    selectorMapping: res.selector_mapping,
    originalSize: res.original_size,
    obfuscatedSize: res.obfuscated_size,
    gasAnalysis,
    seed,
  };
}

export interface ComplianceApproval {
  signature: string;
  timestamp: number;
  escrowAddress: string;
}

/**
 * Compliance approvals are rejected by the node once stale, so a resumed or
 * retried signal must re-request one.
 */
export const APPROVAL_MAX_AGE_SECS = 300;

export function isApprovalStale(timestamp: number, nowSecs = Date.now() / 1000): boolean {
  return nowSecs - timestamp >= APPROVAL_MAX_AGE_SECS;
}

export async function fetchComplianceApproval(
  apiServer: string,
  params: {
    txHash: string;
    chainId: number;
    seed: string;
    escrowType: EscrowKind;
    accessToken?: string;
  },
): Promise<ComplianceApproval> {
  const body: Record<string, unknown> = {
    tx_hash: params.txHash,
    chain_id: params.chainId,
    seed: params.seed,
    escrow_type: params.escrowType,
  };
  if (params.accessToken) {
    body.access_token = params.accessToken;
  }

  const res = await request<{
    signature: string;
    timestamp: number;
    escrow_address: string;
  }>(`${apiServer}/compliance`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  return {
    signature: res.signature,
    timestamp: res.timestamp,
    escrowAddress: res.escrow_address,
  };
}

/** True when a compliance rejection indicates whitelist verification is needed. */
export function isWhitelistRejection(error: unknown): boolean {
  return error instanceof ApiError && error.statusCode === 403 && /whitelist/i.test(error.message);
}

export interface AttestResponse {
  // Current nodes nest the key and chain id inside a hash-committed payload.
  payload?: {
    publicKey?: string;
    chainId?: number;
    maxBalanceUsd?: number;
    complianceKeys?: string[];
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

export async function fetchNetworkKey(
  nomadUrl: string,
  options: FetchNetworkKeyOptions = {},
): Promise<NetworkKeyStatus> {
  const res = await request<AttestResponse>(`${nomadUrl}/attest`);

  const publicKey = res.payload?.publicKey ?? res.publicKey ?? res.public_key ?? "";
  if (!publicKey) {
    throw new ApiError(200, "Attestation response missing enclave public key", res);
  }

  const status: NetworkKeyStatus = {
    publicKey,
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

export interface ApiHealth {
  status: string;
  version?: string;
  /** Per-chain maximum transfer size in USD, keyed by chain id. */
  maxTransferUsd?: Record<string, string | null>;
  /** Per-chain USD threshold above which whitelist verification is required. */
  whitelistRequiredUsd?: Record<string, string | null>;
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
    whitelist_required_usd?: Record<string, number | null>;
  }>(`${apiServer}/`);

  return {
    status: res.status,
    version: res.version,
    maxTransferUsd: parseUsdByChain(res.max_tx_usd),
    whitelistRequiredUsd: parseUsdByChain(res.whitelist_required_usd),
  };
}

/**
 * Fetch limits with retries. A transient failure would otherwise leave both
 * thresholds empty, which fails open: the whitelist gate cannot trigger and
 * transfers proceed until the backend rejects them.
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

/**
 * Check whether an identifier is whitelisted. The value is hashed client-side
 * and the hash itself becomes the access token passed to compliance.
 */
export async function checkWhitelist(
  apiServer: string,
  email: string,
): Promise<{ whitelisted: boolean; accessToken?: string }> {
  // The backend stores normalized values, so normalize before hashing.
  const normalized = email.trim().toLowerCase();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized));
  const hash = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const res = await request<{ whitelisted: boolean }>(`${apiServer}/whitelist`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value: hash, hashed: true }),
  });

  return {
    whitelisted: res.whitelisted,
    accessToken: res.whitelisted ? hash : undefined,
  };
}
