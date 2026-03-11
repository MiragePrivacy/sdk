import type { NetworkConfig, NetworkId } from "./types.js";

type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export const networks: Record<NetworkId, NetworkConfig> = {
  ethereum: {
    id: "ethereum",
    kind: "ethereum",
    chainId: 1,
    rpcUrl: "https://ethereum-rpc.publicnode.com",
    nomadUrl: "https://sgx1.mirageprivacy.com",
    apiServer: "https://api.mirageprivacy.com",
    enableCompliance: true,
    enableBatch: false,
    nodeFeeUsd: 2_000000n, // $2.00 (6 decimals)
    platformFeeRate: 50n, // 0.50%
    gas: {
      approve: 46_686n,
      deploy: 2_167_182n,
      bond: 109_816n,
      transfer: 34_836n,
      collect: 862_813n,
    },
  },
  sepolia: {
    id: "sepolia",
    kind: "ethereum",
    chainId: 11155111,
    rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
    nomadUrl: "https://sgx1.mirageprivacy.com:8443",
    apiServer: "https://api.mirageprivacy.com",
    enableCompliance: true,
    enableBatch: false,
    nodeFeeUsd: 2_000000n,
    platformFeeRate: 50n,
    gas: {
      approve: 46_686n,
      deploy: 2_167_182n,
      bond: 109_816n,
      transfer: 34_836n,
      collect: 862_813n,
    },
  },
  tempo: {
    id: "tempo",
    kind: "tempo",
    chainId: 42431,
    rpcUrl: "https://rpc.moderato.tempo.xyz",
    nomadUrl: "https://sgx1.mirageprivacy.com:8444",
    apiServer: "https://api.mirageprivacy.com",
    enableCompliance: false,
    enableBatch: true,
    nodeFeeUsd: 200000n, // $0.20 (6 decimals)
    platformFeeRate: 50n,
    gas: {
      approve: 279_126n,
      deploy: 11_748_263n,
      bond: 825_039n,
      transfer: 310_574n,
      collect: 932_363n,
    },
  },
};

export function createNetworkConfig(
  base: NetworkId | NetworkConfig,
  overrides?: DeepPartial<NetworkConfig>,
): NetworkConfig {
  const baseConfig = typeof base === "string" ? { ...networks[base] } : { ...base };
  // Always deep-copy gas to prevent mutation of the source object
  baseConfig.gas = { ...baseConfig.gas };

  if (!overrides) return baseConfig;

  const result = baseConfig;

  for (const key of Object.keys(overrides) as (keyof NetworkConfig)[]) {
    const value = overrides[key];
    if (value === undefined) continue;

    if (key === "gas" && typeof value === "object") {
      result.gas = { ...result.gas, ...(value as Partial<NetworkConfig["gas"]>) };
    } else {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (result as any)[key] = value;
    }
  }

  return result;
}
