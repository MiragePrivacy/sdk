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

export async function getTokenMetadata(
  tokenAddress: Address,
  publicClient: PublicClient,
): Promise<TokenMetadata> {
  if (isNativeToken(tokenAddress)) {
    return {
      address: NATIVE_TOKEN_ADDRESS,
      name: "Ether",
      symbol: "ETH",
      decimals: 18,
    };
  }

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
