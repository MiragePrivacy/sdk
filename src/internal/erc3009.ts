import {
  encodeAbiParameters, getAddress, hashDomain, parseAbi, parseAbiParameters, parseSignature, recoverTypedDataAddress,
  type Address, type Hex, type PublicClient, type WalletClient,
} from "viem";
import { MirageError } from "../errors.js";
import type { FundingAuthorizationRequest } from "../types.js";
import { randomBytes32 } from "./zk.js";

/** Circle's native USDC proxies. Symbol matches and bridged tokens are ineligible. */
const circleUsdc: Record<number, string | undefined> = {
  1: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
  11155111: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238",
};

export function isErc3009Asset(chainId: number, asset: string): boolean {
  return circleUsdc[chainId] === asset.toLowerCase();
}

const domainAbi = parseAbi([
  "function name() view returns (string)",
  "function DOMAIN_SEPARATOR() view returns (bytes32)",
]);
const domainTypes = {
  EIP712Domain: [
    { name: "name", type: "string" }, { name: "version", type: "string" },
    { name: "chainId", type: "uint256" }, { name: "verifyingContract", type: "address" },
  ],
} as const;
const receiveTypes = {
  ReceiveWithAuthorization: [
    { name: "from", type: "address" }, { name: "to", type: "address" },
    { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
  ],
} as const;

export async function authorizeReceipt(
  wallet: WalletClient, publicClient: PublicClient, chainId: number, account: Address,
  request: FundingAuthorizationRequest, beforeSign: () => void,
): Promise<Hex> {
  if (!isErc3009Asset(chainId, request.tokenAddress)) {
    throw new MirageError("INVALID_FUNDING_MODE", "This asset does not support Mirage receipt authorization.");
  }
  const token = getAddress(request.tokenAddress);
  const [name, separator] = await Promise.all([
    publicClient.readContract({ address: token, abi: domainAbi, functionName: "name" }),
    publicClient.readContract({ address: token, abi: domainAbi, functionName: "DOMAIN_SEPARATOR" }),
  ]);
  const domain = { name, version: "2", chainId, verifyingContract: token };
  const expected = hashDomain({ domain: { ...domain, chainId: BigInt(chainId) }, types: domainTypes });
  if (expected.toLowerCase() !== separator.toLowerCase()) {
    throw new MirageError("UNSUPPORTED_AUTHORIZATION", "The token's current signing domain does not match its contract.");
  }
  const nonce = randomBytes32();
  const validBefore = BigInt(request.validBefore);
  const typed = {
    domain, types: receiveTypes, primaryType: "ReceiveWithAuthorization" as const,
    message: { from: account, to: request.escrowAddress, value: request.amount, validAfter: 0n, validBefore, nonce },
  };
  beforeSign();
  const signature = await wallet.signTypedData({ account: wallet.account!, ...typed });
  // A malformed or contract-wallet signature can appear in viem decoder errors.
  // Return a public reason without embedding the user's authorization.
  const signer = await recoverTypedDataAddress({ ...typed, signature }).catch(() => undefined);
  if (signer?.toLowerCase() !== account.toLowerCase()) {
    throw new MirageError("INVALID_AUTHORIZATION", "The token authorization was not signed by the quoted sender.");
  }
  const { r, s, yParity } = parseSignature(signature);
  return encodeAbiParameters(parseAbiParameters("address, uint256, uint256, bytes32, uint8, bytes32, bytes32"), [
    token, 0n, validBefore, nonce, 27 + Number(yParity), r, s,
  ]);
}
