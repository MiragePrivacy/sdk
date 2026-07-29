import type { NetworkConfig, NetworkId } from "./types.js";

type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

// Merged field-by-field rather than replaced, so a partial override cannot
// silently drop sibling fields (e.g. attestation.required).
const NESTED_KEYS = ["gas", "nativeGas", "attestation"] as const;

/**
 * Mirage's enclave signing identity. Stable across enclave releases, unlike
 * MRENCLAVE, which changes on every rebuild.
 */
export const MIRAGE_MRSIGNER =
  "0xeb81f8f64bf9d8e4bba26943a1161e7ca4e878b0775c33637e60516badfb52c3";

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
    nomadUrl: "https://sgx1.mirageprivacy.com",
    apiServer: "https://api.mirageprivacy.com",
    enableCompliance: true,
    enableAtomicBatch: false,
    nodeFeeUsd: 2_000000n, // $2.00 (6 decimals)
    nodeFeeWei: 500_000_000_000_000n, // 0.0005 ETH
    platformFeeRate: 50n, // 0.50%
    gas: {
      approve: 46_686n,
      deploy: 2_167_182n,
      bond: 109_816n,
      fund: 120_000n,
      collect: 250_000n,
    },
    nativeGas: {
      deploy: 1_924_115n,
      bond: 92_366n,
      fund: 120_000n,
      collect: 250_000n,
    },
    bondPotMarginBps: 150n,
    // Production: verified quotes only, no debug enclaves, and the enclave
    // must be signed by Mirage. MRENCLAVE is not pinned, since it changes on
    // every enclave release.
    attestation: {
      required: true,
      allowDebug: false,
      expectedMrSigner: [MIRAGE_MRSIGNER],
    },
    uniswapRouter: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    priceChainId: 1,
    priceTokenContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    priceUniswapRouter: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
  },
  sepolia: {
    id: "sepolia",
    kind: "ethereum",
    chainId: 11155111,
    rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
    nomadUrl: "https://sgx1.mirageprivacy.com:8443",
    apiServer: "https://api.mirageprivacy.com",
    enableCompliance: true,
    enableAtomicBatch: false,
    nodeFeeUsd: 2_000000n,
    nodeFeeWei: 500_000_000_000_000n,
    platformFeeRate: 50n,
    gas: {
      approve: 46_686n,
      deploy: 2_167_182n,
      bond: 109_816n,
      fund: 120_000n,
      collect: 250_000n,
    },
    nativeGas: {
      deploy: 1_924_115n,
      bond: 92_366n,
      fund: 120_000n,
      collect: 250_000n,
    },
    bondPotMarginBps: 150n,
    // Testnet nodes may run debug-mode enclaves depending on how they were
    // built. If this node does, set allowDebug via createNetworkConfig rather
    // than turning verification off; the signer check still applies.
    attestation: { required: true, expectedMrSigner: [MIRAGE_MRSIGNER] },
    uniswapRouter: "0xeE567Fe1712Faf6149d80dA1E6934E354124CfE3",
    // Testnet has no liquid market; price from mainnet.
    priceChainId: 1,
    priceRpcUrl: "https://ethereum-rpc.publicnode.com",
    priceTokenContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    priceUniswapRouter: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
  },
  tempo: {
    id: "tempo",
    kind: "tempo",
    chainId: 42431,
    rpcUrl: "https://rpc.moderato.tempo.xyz",
    nomadUrl: "https://sgx1.mirageprivacy.com:8444",
    apiServer: "https://api.mirageprivacy.com",
    enableCompliance: false,
    enableAtomicBatch: true,
    nodeFeeUsd: 200000n, // $0.20 (6 decimals)
    nodeFeeWei: 0n,
    platformFeeRate: 50n,
    gas: {
      approve: 279_126n,
      deploy: 11_748_263n,
      bond: 825_039n,
      fund: 310_574n,
      collect: 932_363n,
    },
    nativeGas: {
      deploy: 11_748_263n,
      bond: 825_039n,
      fund: 310_574n,
      collect: 932_363n,
    },
    bondPotMarginBps: 150n,
    // Testnet nodes may run debug-mode enclaves depending on how they were
    // built. If this node does, set allowDebug via createNetworkConfig rather
    // than turning verification off; the signer check still applies.
    attestation: { required: true, expectedMrSigner: [MIRAGE_MRSIGNER] },
  },
};

export function createNetworkConfig(
  base: NetworkId | NetworkConfig,
  overrides?: DeepPartial<NetworkConfig>,
): NetworkConfig {
  const result = typeof base === "string" ? { ...networks[base] } : { ...base };
  // Deep-copy nested objects to prevent mutation of the source config.
  result.gas = { ...result.gas };
  result.nativeGas = { ...result.nativeGas };
  if (result.attestation) result.attestation = { ...result.attestation };

  if (!overrides) return result;

  for (const key of Object.keys(overrides) as (keyof NetworkConfig)[]) {
    const value = overrides[key];
    if (value === undefined) continue;

    if ((NESTED_KEYS as readonly string[]).includes(key) && typeof value === "object") {
      const target = result[key as "gas" | "nativeGas" | "attestation"];
      (result as Record<string, unknown>)[key] = { ...target, ...value };
    } else {
      (result as Record<string, unknown>)[key] = value;
    }
  }

  return result;
}
