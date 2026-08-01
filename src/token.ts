import {
  type Address,
  type PublicClient,
  erc20Abi,
  getAddress,
  zeroAddress,
} from "viem";
import type { TokenMetadata } from "./types.js";

export const NATIVE_TOKEN_ADDRESS: Address = zeroAddress;

export function isNativeToken(address: Address): boolean {
  return getAddress(address) === getAddress(NATIVE_TOKEN_ADDRESS);
}

// ERC20 metadata is immutable, so cache it per chain. Storing the in-flight
// promise also collapses concurrent lookups (e.g. batch rows sharing a token)
// into one set of reads; failures are evicted so they retry.
const metadataCache = new Map<string, Promise<TokenMetadata>>();

export function getTokenMetadata(
  tokenAddress: Address,
  publicClient: PublicClient,
): Promise<TokenMetadata> {
  if (isNativeToken(tokenAddress)) {
    return Promise.resolve({
      address: NATIVE_TOKEN_ADDRESS,
      name: "Ether",
      symbol: "ETH",
      decimals: 18,
    });
  }

  const chainId = publicClient.chain?.id;
  const key = chainId !== undefined ? `${chainId}:${tokenAddress.toLowerCase()}` : undefined;
  if (key) {
    const cached = metadataCache.get(key);
    if (cached) return cached;
  }

  const promise = fetchTokenMetadata(tokenAddress, publicClient);
  if (key) {
    metadataCache.set(key, promise);
    promise.catch(() => metadataCache.delete(key));
  }
  return promise;
}

async function fetchTokenMetadata(
  tokenAddress: Address,
  publicClient: PublicClient,
): Promise<TokenMetadata> {
  const [name, symbol, decimals] = await Promise.all([
    publicClient.readContract({
      address: tokenAddress,
      abi: erc20Abi,
      functionName: "name",
    }),
    publicClient.readContract({
      address: tokenAddress,
      abi: erc20Abi,
      functionName: "symbol",
    }),
    publicClient.readContract({
      address: tokenAddress,
      abi: erc20Abi,
      functionName: "decimals",
    }),
  ]);

  return { address: tokenAddress, name, symbol, decimals };
}

export async function getTokenBalance(
  tokenAddress: Address,
  owner: Address,
  publicClient: PublicClient,
): Promise<bigint> {
  if (isNativeToken(tokenAddress)) {
    return publicClient.getBalance({ address: owner });
  }

  return publicClient.readContract({
    address: tokenAddress,
    abi: erc20Abi,
    functionName: "balanceOf",
    args: [owner],
  });
}

export async function getTokenAllowance(
  tokenAddress: Address,
  owner: Address,
  spender: Address,
  publicClient: PublicClient,
): Promise<bigint> {
  if (isNativeToken(tokenAddress)) {
    return 0n; // native token doesn't need approval
  }

  return publicClient.readContract({
    address: tokenAddress,
    abi: erc20Abi,
    functionName: "allowance",
    args: [owner, spender],
  });
}
