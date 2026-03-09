/**
 * Deploy TUSDC token to anvil and mint tokens for test accounts.
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvilChain, ACCOUNTS, RPC_URL } from "./setup.js";

// Compiled TUSDC bytecode (solc 0.8.30, optimizer 200 runs)
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const TUSDC_BYTECODE = readFileSync(
  resolve(import.meta.dirname, "tusdc.hex"),
  "utf-8",
).trim() as `0x${string}`;

const mintAbi = parseAbi(["function mint() external"]);

export async function deployTusdc(): Promise<Address> {
  const publicClient = createPublicClient({
    chain: anvilChain,
    transport: http(RPC_URL),
  });

  const deployerWallet = createWalletClient({
    account: privateKeyToAccount(ACCOUNTS.deployer.key),
    chain: anvilChain,
    transport: http(RPC_URL),
  });

  // Deploy
  const hash = await deployerWallet.sendTransaction({
    data: TUSDC_BYTECODE,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const address = receipt.contractAddress!;
  console.log(`[deploy] TUSDC deployed at ${address}`);

  // Mint for sender, deployer, and node account (account[8])
  const mintKeys = [
    ACCOUNTS.deployer.key,
    ACCOUNTS.sender.key,
    // Node account (used by mock-nomad to send tokens)
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97" as `0x${string}`,
  ];

  for (const key of mintKeys) {
    const wallet = createWalletClient({
      account: privateKeyToAccount(key),
      chain: anvilChain,
      transport: http(RPC_URL),
    });
    const mintHash = await wallet.writeContract({
      address,
      abi: mintAbi,
      functionName: "mint",
    });
    await publicClient.waitForTransactionReceipt({ hash: mintHash });
  }
  console.log(`[deploy] Minted TUSDC for ${mintKeys.length} accounts`);

  return address;
}
