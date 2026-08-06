import http from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import {
  createPublicClient,
  createWalletClient,
  http as viemHttp,
  type Address,
  type Chain,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { tempoModerato } from "viem/chains";
import { createNetworkConfig, networks } from "../../src/networks.js";
import type { NetworkConfig, NetworkId } from "../../src/types.js";
import { createServer as createMockNomad } from "./mock-nomad.js";
import { createServer as createMockApi } from "./mock-api.js";

// --- Testnet mode ---
// Set TESTNET=tempo (or sepolia, ethereum) to run against a live network.
// Required env vars: SENDER_KEY, RECIPIENT_ADDRESS
// Optional: TOKEN_ADDRESS (defaults to native), API_URL, NOMAD_URL, RPC_URL

export const TESTNET = process.env.TESTNET as NetworkId | undefined;
export const isTestnet = !!TESTNET;

// --- Local (anvil) chain ---

export const anvilChain: Chain = {
  id: 31337,
  name: "Anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: {
    default: { http: ["http://127.0.0.1:8545"] },
  },
};

// --- Accounts ---

const ANVIL_ACCOUNTS = {
  deployer: {
    key: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as `0x${string}`,
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as Address,
  },
  sender: {
    key: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as `0x${string}`,
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as Address,
  },
  recipient: {
    key: "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6" as `0x${string}`,
    address: "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720" as Address,
  },
} as const;

function getTestnetAccounts() {
  const senderKey = process.env.SENDER_KEY;
  if (!senderKey) throw new Error("SENDER_KEY env var required for testnet mode");
  const recipientAddress = process.env.RECIPIENT_ADDRESS;
  if (!recipientAddress) throw new Error("RECIPIENT_ADDRESS env var required for testnet mode");

  const senderAccount = privateKeyToAccount(senderKey as `0x${string}`);
  return {
    sender: { key: senderKey as `0x${string}`, address: senderAccount.address },
    recipient: { address: recipientAddress as Address },
  };
}

export const ACCOUNTS = isTestnet
  ? {
      deployer: { key: "" as `0x${string}`, address: "0x" as Address },
      ...getTestnetAccounts(),
    }
  : ANVIL_ACCOUNTS;

// --- Ports and URLs ---

export const ANVIL_PORT = parseInt(process.env.ANVIL_PORT || "8545", 10);
export const API_PORT = parseInt(process.env.API_PORT || "3111", 10);
export const NOMAD_PORT = parseInt(process.env.NOMAD_PORT || "8111", 10);

function resolveUrls() {
  if (isTestnet) {
    const base = networks[TESTNET!];
    return {
      rpcUrl: process.env.RPC_URL || base.rpcUrl,
      apiUrl: process.env.API_URL || base.apiServer,
      nomadUrl: process.env.NOMAD_URL || base.nomadUrl,
    };
  }
  return {
    rpcUrl: process.env.RPC_URL || `http://127.0.0.1:${ANVIL_PORT}`,
    apiUrl: process.env.API_URL || `http://127.0.0.1:${API_PORT}`,
    nomadUrl: process.env.NOMAD_URL || `http://127.0.0.1:${NOMAD_PORT}`,
  };
}

const urls = resolveUrls();
export const RPC_URL = urls.rpcUrl;
export const API_URL = urls.apiUrl;
export const NOMAD_URL = urls.nomadUrl;

// --- Token address ---

export const TOKEN_ADDRESS = process.env.TOKEN_ADDRESS as Address | undefined;

// Set after deployTusdc runs (local only)
let _tusdcAddress: Address | null = null;

export function getTusdcAddress(): Address {
  if (isTestnet) {
    if (!TOKEN_ADDRESS) throw new Error("TOKEN_ADDRESS env var required for testnet ERC20 tests");
    return TOKEN_ADDRESS;
  }
  if (!_tusdcAddress) throw new Error("TUSDC not deployed yet — call startAll() first");
  return _tusdcAddress;
}

// --- Network config ---

// Map of testnet IDs to viem chain definitions with proper serializers/formatters.
const TESTNET_CHAINS: Partial<Record<NetworkId, Chain>> = {
  tempo: tempoModerato,
};

function getTestnetChain(): Chain {
  const known = TESTNET_CHAINS[TESTNET!];
  if (known) return known;

  const base = networks[TESTNET!];
  return {
    id: base.chainId,
    name: TESTNET!,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: {
      default: { http: [RPC_URL] },
    },
  };
}

export function getNetwork(): NetworkConfig {
  if (isTestnet) {
    return createNetworkConfig(TESTNET!, {
      rpcUrl: RPC_URL,
      nomadUrl: NOMAD_URL,
      apiServer: API_URL,
      // Testnet enclaves are typically debug builds. Verification stays on;
      // only the debug-mode rejection is relaxed.
      attestation: { allowDebug: true },
    });
  }
  return createNetworkConfig("ethereum", {
    id: "ethereum",
    chainId: 31337,
    rpcUrl: RPC_URL,
    nomadUrl: NOMAD_URL,
    apiServer: API_URL,
    enableAtomicBatch: false,
    // The mock nomad runs outside SGX and serves no quote to verify.
    attestation: { required: false },
  });
}

// Keep old name as alias
export const getLocalNetwork = getNetwork;

export function getPublicClient() {
  const chain = isTestnet ? getTestnetChain() : anvilChain;
  return createPublicClient({
    chain,
    transport: viemHttp(RPC_URL),
  });
}

export function getWalletClient(
  account: { key: `0x${string}` } = ACCOUNTS.sender,
) {
  const chain = isTestnet ? getTestnetChain() : anvilChain;
  return createWalletClient({
    account: privateKeyToAccount(account.key),
    chain,
    transport: viemHttp(RPC_URL),
  });
}

// --- Health check ---

export async function isServiceReady(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1 }),
      signal: AbortSignal.timeout(2000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// --- Anvil process ---

let anvilProcess: ChildProcess | null = null;

let _faucetFunded = false;

async function ensureFaucetFunded(): Promise<void> {
  if (_faucetFunded || !isTestnet || TESTNET !== "tempo") return;
  await fundViaFaucet(ACCOUNTS.sender.address);
  _faucetFunded = true;
}

export async function startAnvil(): Promise<void> {
  if (isTestnet) {
    await ensureFaucetFunded();
    return;
  }

  if (await isServiceReady(RPC_URL)) {
    // Already running — still deploy TUSDC if needed
    if (!_tusdcAddress) {
      const { deployTusdc } = await import("./deploy-tusdc.js");
      _tusdcAddress = await deployTusdc();
    }
    return;
  }

  await new Promise<void>((resolve, reject) => {
    anvilProcess = spawn(process.env.ANVIL_BINARY || "anvil", [
      "--chain-id", "31337",
      "--host", "0.0.0.0",
      "--port", String(ANVIL_PORT),
      "--accounts", "10",
      "--balance", "10000",
      "--gas-limit", "30000000",
      "--code-size-limit", "50000",
      "--silent",
    ], { stdio: ["ignore", "pipe", "pipe"] });

    anvilProcess.on("error", reject);

    const check = async () => {
      for (let i = 0; i < 120; i++) {
        if (await isServiceReady(RPC_URL)) {
          console.log("[setup] Anvil started");
          resolve();
          return;
        }
        await new Promise((r) => setTimeout(r, 500));
      }
      reject(new Error("Anvil failed to start in 60s"));
    };
    check();
  });

  // Deploy TUSDC
  const { deployTusdc } = await import("./deploy-tusdc.js");
  _tusdcAddress = await deployTusdc();
}

export function stopAnvil(): void {
  if (anvilProcess) {
    anvilProcess.kill();
    anvilProcess = null;
  }
}

// --- Mock API ---

let mockApiServer: http.Server | null = null;

export function startMockApi(): Promise<void> {
  if (isTestnet) return Promise.resolve(); // Use real API
  if (mockApiServer) return Promise.resolve();
  mockApiServer = createMockApi(API_PORT);
  return new Promise((resolve) => {
    mockApiServer!.listen(API_PORT, () => {
      console.log(`[setup] Mock API started on port ${API_PORT}`);
      resolve();
    });
  });
}

export function stopMockApi(): Promise<void> {
  if (!mockApiServer) return Promise.resolve();
  return new Promise((resolve) => {
    mockApiServer!.close(() => {
      mockApiServer = null;
      resolve();
    });
  });
}

// --- Mock Nomad ---

let mockNomadServer: http.Server | null = null;

export function startMockNomad(): Promise<void> {
  if (isTestnet) return Promise.resolve(); // Use real nomad
  if (mockNomadServer) return Promise.resolve();
  mockNomadServer = createMockNomad(NOMAD_PORT);
  return new Promise((resolve) => {
    mockNomadServer!.listen(NOMAD_PORT, () => {
      console.log(`[setup] Mock nomad started on port ${NOMAD_PORT}`);
      resolve();
    });
  });
}

export function stopMockNomad(): Promise<void> {
  if (!mockNomadServer) return Promise.resolve();
  return new Promise((resolve) => {
    mockNomadServer!.close(() => {
      mockNomadServer = null;
      resolve();
    });
  });
}

// --- Tempo faucet ---

export async function fundViaFaucet(address: Address): Promise<string[]> {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "tempo_fundAddress",
      params: [address],
      id: 1,
    }),
  });
  const json = await res.json();
  if (json.error) {
    // Nonce replay = already funded recently, safe to ignore
    if (json.error.message?.includes("nonce") || json.error.message?.includes("replay")) {
      console.log(`[setup] Faucet: already funded (${json.error.message})`);
      return [];
    }
    throw new Error(`Faucet failed: ${json.error.message}`);
  }
  console.log(`[setup] Faucet funded ${address}: ${json.result}`);
  return json.result as string[];
}

// --- All services ---

export async function startAll(): Promise<void> {
  await startAnvil();
  await Promise.all([startMockApi(), startMockNomad()]);
}

export async function stopAll(): Promise<void> {
  await Promise.all([stopMockApi(), stopMockNomad()]);
  stopAnvil();
}
