import type { NetworkConfig, NetworkId, TcbStatus } from "./types.js";

type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

// Merged field-by-field rather than replaced, so a partial override cannot
// silently drop sibling fields (e.g. attestation.required).
const NESTED_KEYS = ["attestation"] as const;

/**
 * Mirage's enclave signing identity. Stable across enclave releases, unlike
 * MRENCLAVE, which changes on every rebuild.
 */
export const MIRAGE_MRSIGNER =
  "0xeb81f8f64bf9d8e4bba26943a1161e7ca4e878b0775c33637e60516badfb52c3";

/**
 * TCB states and Intel advisories accepted on every network. All Mirage nodes
 * run on the same SGX platform, so the platform risk assessment is shared.
 * Rust's Fortanix SGX target has mitigated INTEL-SA-00615 since 1.62.1; the
 * remaining INTEL-SA-00289 platform risk is accepted explicitly here.
 */
const ALLOWED_TCB_STATUS: TcbStatus[] = [
  "UpToDate",
  "SWHardeningNeeded",
  "ConfigurationAndSWHardeningNeeded",
];
const ALLOWED_ADVISORY_IDS = ["INTEL-SA-00289", "INTEL-SA-00615"];

/**
 * Built-in network configs. Only `ethereum` is a production network; sepolia
 * and tempo are testnets.
 */
export const networks: Record<NetworkId, NetworkConfig> = {
  ethereum: {
    id: "ethereum",
    kind: "ethereum",
    chainId: 1,
    rpcUrl: "https://ethereum-rpc.publicnode.com",
    apiServer: "https://api.mirageprivacy.com",
    enableAtomicBatch: false,
    // Production: verified quotes only, no debug enclaves, and the enclave
    // must be signed by Mirage. MRENCLAVE is not pinned, since it changes on
    // every enclave release.
    attestation: {
      required: true,
      allowDebug: false,
      expectedMrSigner: [MIRAGE_MRSIGNER],
      allowedTcbStatus: ALLOWED_TCB_STATUS,
      allowedAdvisoryIds: ALLOWED_ADVISORY_IDS,
      // ISVSVN 2 identifies the deployed hardened Mirage enclave.
      minimumIsvSvn: 2,
    },
  },
  sepolia: {
    id: "sepolia",
    kind: "ethereum",
    chainId: 11155111,
    rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
    apiServer: "https://api.mirageprivacy.com",
    enableAtomicBatch: false,
    // Testnet nodes may run debug-mode enclaves depending on how they were
    // built. If this node does, set allowDebug via createNetworkConfig rather
    // than turning verification off; the signer check still applies.
    attestation: {
      required: true,
      expectedMrSigner: [MIRAGE_MRSIGNER],
      allowedTcbStatus: ALLOWED_TCB_STATUS,
      allowedAdvisoryIds: ALLOWED_ADVISORY_IDS,
    },
  },
  tempo: {
    id: "tempo",
    kind: "tempo",
    chainId: 42431,
    rpcUrl: "https://rpc.moderato.tempo.xyz",
    apiServer: "https://api.mirageprivacy.com",
    // The pricing-aware compliance endpoint currently verifies a top-level
    // creation transaction. Keep separate approvals + exact deployment until
    // it can inspect Tempo call-vector creation receipts.
    enableAtomicBatch: false,
    // Testnet nodes may run debug-mode enclaves depending on how they were
    // built. If this node does, set allowDebug via createNetworkConfig rather
    // than turning verification off; the signer check still applies.
    attestation: {
      required: true,
      expectedMrSigner: [MIRAGE_MRSIGNER],
      allowedTcbStatus: ALLOWED_TCB_STATUS,
      allowedAdvisoryIds: ALLOWED_ADVISORY_IDS,
    },
  },
};

export function createNetworkConfig(
  base: NetworkId | NetworkConfig,
  overrides?: DeepPartial<NetworkConfig>,
): NetworkConfig {
  const result = typeof base === "string" ? { ...networks[base] } : { ...base };
  // Deep-copy nested objects to prevent mutation of the source config.
  if (result.attestation) result.attestation = { ...result.attestation };

  if (!overrides) return result;

  for (const key of Object.keys(overrides) as (keyof NetworkConfig)[]) {
    const value = overrides[key];
    if (value === undefined) continue;

    if ((NESTED_KEYS as readonly string[]).includes(key) && typeof value === "object") {
      const target = result[key as "attestation"];
      (result as Record<string, unknown>)[key] = { ...target, ...value };
    } else {
      (result as Record<string, unknown>)[key] = value;
    }
  }

  return result;
}
