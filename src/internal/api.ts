import type { Address } from "viem";
import { ApiError } from "../errors.js";
import type { NetworkKeyStatus } from "../types.js";

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);

  if (!res.ok) {
    const body = await res.json().catch(() => res.text().catch(() => undefined));
    throw new ApiError(res.status, `API request failed: ${res.status} ${res.statusText}`, body);
  }

  return res.json() as Promise<T>;
}

export interface GasAnalysis {
  /** Estimated gas for deploying the obfuscated escrow contract. */
  deploy?: bigint;
  /** Estimated gas for the bond function. */
  bond?: bigint;
  /** Estimated gas for the collect function. */
  collect?: bigint;
  /** Estimated gas for the fund function (batched flow). */
  fund?: bigint;
}

export interface ObfuscationResult {
  obfuscatedBytecode: `0x${string}`;
  selectorMapping?: Record<string, string>;
  originalSize: number;
  obfuscatedSize: number;
  gasAnalysis?: GasAnalysis;
}

export async function fetchObfuscation(
  apiServer: string,
  nativeEth: boolean,
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
      } | null;
    } | null;
  }>(`${apiServer}/obfuscate_escrow`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      options: { shuffle: false, seed },
      native_eth: nativeEth,
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
  }

  return {
    obfuscatedBytecode: (bytecode.startsWith("0x") ? bytecode : `0x${bytecode}`) as `0x${string}`,
    selectorMapping: res.selector_mapping,
    originalSize: res.original_size,
    obfuscatedSize: res.obfuscated_size,
    gasAnalysis,
  };
}

export interface ComplianceApproval {
  signature: string;
  timestamp: number;
  escrowAddress: string;
}

export async function fetchComplianceApproval(
  apiServer: string,
  params: {
    txHash: string;
    chainId: number;
    accessToken?: string;
  },
): Promise<ComplianceApproval> {
  const body: Record<string, unknown> = {
    tx_hash: params.txHash,
    chain_id: params.chainId,
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

export async function fetchNetworkKey(nomadUrl: string): Promise<NetworkKeyStatus> {
  const res = await request<{
    publicKey: string;
    public_key?: string;
    attestation: unknown | null;
    isDebug?: boolean;
    is_debug?: boolean;
    chainId?: number;
    chain_id?: number;
    mrenclave?: string;
    mrsigner?: string;
  }>(`${nomadUrl}/attest`);

  return {
    publicKey: res.publicKey ?? res.public_key ?? "",
    attested: res.attestation !== null && res.attestation !== undefined,
    debug: res.isDebug ?? res.is_debug ?? false,
    chainId: Number(res.chainId ?? res.chain_id ?? 0),
    mrenclave: res.mrenclave,
    mrsigner: res.mrsigner,
  };
}

export async function fetchApiHealth(
  apiServer: string,
): Promise<{
  status: string;
  version?: string;
  maxTransferUsd?: Record<string, string | null>;
}> {
  const res = await request<{
    status: string;
    version?: string;
    max_tx_usd?: Record<string, number | null>;
  }>(`${apiServer}/`);

  // Convert numeric values to strings for JSON serialization safety
  let maxTransferUsd: Record<string, string | null> | undefined;
  if (res.max_tx_usd) {
    maxTransferUsd = {};
    for (const [key, value] of Object.entries(res.max_tx_usd)) {
      maxTransferUsd[key] = value !== null ? String(value) : null;
    }
  }

  return {
    status: res.status,
    version: res.version,
    maxTransferUsd,
  };
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
