import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import { once } from "node:events";
import { promisify } from "node:util";
import {
  createPublicClient,
  createTestClient,
  createWalletClient,
  erc20Abi,
  getAddress,
  getContractAddress,
  http,
  parseAbi,
  parseEventLogs,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { mainnet } from "viem/chains";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createNetworkConfig } from "../../src/networks.js";
import { prepareTransfer } from "../../src/transfer.js";
import { createServer as mockApi } from "./mock-api.js";
import { createServer as mockNomad } from "./mock-nomad.js";
import { ACCOUNTS, isTestnet } from "./setup.js";

const usdc = getAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const escrowAbi = parseAbi(["function funded() view returns (bool)"]);
const fixtureAbi = parseAbi([
  "function mint(address to,uint256 value)",
  "function authorizationState(address,bytes32) view returns (bool)",
  "event AuthorizationUsed(address indexed authorizer,bytes32 indexed nonce)",
]);

async function listen(server: Server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected a local TCP server");
  return `http://127.0.0.1:${address.port}`;
}

// Use the real chain ID and token address on a private, ephemeral Anvil, so the
// SDK's production asset and domain checks run without contacting public RPCs.
async function startLocalChain() {
  const child = spawn(
    process.env.ANVIL_BINARY || "anvil",
    ["--chain-id", "1", "--host", "127.0.0.1", "--port", "0"],
    { stdio: ["ignore", "pipe", "ignore"] },
  );
  const url = await new Promise<string>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`Anvil exited with code ${code}`)));
    let startup = "";
    child.stdout.on("data", (chunk) => {
      startup += chunk.toString();
      const match = /Listening on 127\.0\.0\.1:(\d+)/.exec(startup);
      if (match) {
        child.stdout.removeAllListeners("data");
        child.stdout.resume();
        resolve(`http://127.0.0.1:${match[1]}`);
      }
    });
  });
  return { child, url };
}

function clients(url: string) {
  const transport = http(url);
  return {
    rpc: createPublicClient({ chain: mainnet, transport, cacheTime: 0, pollingInterval: 50 }),
    test: createTestClient({ chain: mainnet, transport, mode: "anvil" }),
    wallet: createWalletClient({
      account: privateKeyToAccount(ACCOUNTS.sender.key),
      chain: mainnet,
      transport,
    }),
  };
}

describe.skipIf(isTestnet)("USDC receipt funding on a local EVM", () => {
  let anvil: ChildProcess;
  let api: Server;
  let nomad: Server;
  let rpcUrl: string;
  let apiUrl: string;
  let otherToken: Address;
  let local: ReturnType<typeof clients>;

  beforeAll(async () => {
    const { child, url } = await startLocalChain();
    anvil = child;
    rpcUrl = url;
    local = clients(rpcUrl);
    nomad = mockNomad(0);
    api = mockApi(0, await listen(nomad));
    apiUrl = await listen(api);

    // Built from escrow/test/helpers/USDC3009Mock.sol using its Foundry profile.
    // Run its initialization code at the proxy address on this local chain so
    // the token's name in storage and its EIP-712 immutables both match.
    const bytecode = readFileSync(new URL("./usdc3009-mock.hex", import.meta.url), "utf8").trim() as Hex;
    const deployed = await local.wallet.sendTransaction({ data: bytecode });
    const { contractAddress } = await local.rpc.waitForTransactionReceipt({ hash: deployed });
    if (!contractAddress) throw new Error("Test token deployment failed");
    otherToken = getAddress(contractAddress);
    await local.test.setCode({ address: usdc, bytecode });
    const { data: runtime } = await local.rpc.call({ to: usdc, account: local.wallet.account.address });
    if (!runtime) throw new Error("Test token constructor returned no runtime");
    const initialize = await local.wallet.sendTransaction({ to: usdc });
    await local.rpc.waitForTransactionReceipt({ hash: initialize });
    await local.test.setCode({ address: usdc, bytecode: runtime });
    for (const address of [usdc, otherToken]) {
      const hash = await local.wallet.writeContract({
        address,
        abi: fixtureAbi,
        functionName: "mint",
        args: [local.wallet.account.address, 100_000_000n],
      });
      await local.rpc.waitForTransactionReceipt({ hash });
    }
  });

  afterAll(async () => {
    anvil?.kill();
    for (const server of [api, nomad]) {
      if (server?.listening) await promisify(server.close.bind(server))();
    }
  });

  it.each([false, true])(
    "collects the quoted deposit via one USDC authorization (mixed batch = %s)",
    async (mixed) => {
      const { rpc, wallet } = local;
      const payer = wallet.account.address;
      const recipient = ACCOUNTS.recipient.address;
      const initialNonce = await rpc.getTransactionCount({ address: payer });
      const predicted = getContractAddress({
        from: payer,
        nonce: BigInt(initialNonce + (mixed ? 1 : 0)),
      });
      const transactions = [{ tokenAddress: usdc, recipientAddress: recipient, amount: 1_000_000n }];
      if (mixed) {
        transactions.push(
          { tokenAddress: usdc, recipientAddress: payer, amount: 2_000_000n },
          { tokenAddress: otherToken, recipientAddress: recipient, amount: 500_000n },
        );
      }
      const prepared = await prepareTransfer({
        transfers: transactions,
        fundingMode: "erc3009",
        walletClient: wallet,
        publicClient: rpc,
        network: createNetworkConfig("ethereum", {
          rpcUrl,
          apiServer: apiUrl,
          attestation: { required: false },
        }),
      });
      expect(prepared.fees.fundingMode).toBe("erc3009");
      const expected = (mixed ? 3_000_000n : 1_000_000n) + prepared.fees.serviceFee.amount;
      const startBlock = await rpc.getBlockNumber();
      const steps = [];
      for await (const step of prepared.approve(wallet)) steps.push(step);
      expect(steps.map((step) => step.step)).toEqual(mixed ? ["authorize", "approve"] : ["authorize"]);
      expect(steps[0]).toMatchObject({ tokenAddress: usdc, escrowAddress: predicted, amount: expected });
      if (mixed) expect(steps[1]).toMatchObject({ tokenAddress: otherToken });
      const deployment = await prepared.deploy(wallet);
      expect(deployment.escrowAddress).toBe(predicted);
      const receipt = await rpc.getTransactionReceipt({ hash: deployment.hash });
      expect(receipt.status).toBe("success");
      expect(
        await rpc.readContract({ address: predicted, abi: escrowAbi, functionName: "funded" }),
      ).toBe(true);
      expect(await rpc.getTransactionCount({ address: payer })).toBe(initialNonce + (mixed ? 2 : 1));

      const usdcLogs = receipt.logs.filter((log) => getAddress(log.address) === usdc);
      expect(
        await rpc.readContract({
          address: usdc, abi: erc20Abi, functionName: "balanceOf", args: [predicted],
        }),
      ).toBe(expected);
      const transfers = parseEventLogs({ abi: erc20Abi, eventName: "Transfer", logs: usdcLogs });
      expect(transfers.map((log) => log.args)).toEqual([
        { from: payer, to: predicted, value: expected },
      ]);
      const authorizations = parseEventLogs({
        abi: fixtureAbi,
        eventName: "AuthorizationUsed",
        logs: usdcLogs,
      });
      expect(authorizations).toHaveLength(1);
      expect(authorizations[0].args.authorizer).toBe(payer);
      expect(
        await rpc.readContract({
          address: usdc,
          abi: fixtureAbi,
          functionName: "authorizationState",
          args: [payer, authorizations[0].args.nonce],
        }),
      ).toBe(true);
      expect(
        await rpc.readContract({
          address: usdc,
          abi: erc20Abi,
          functionName: "allowance",
          args: [payer, predicted],
        }),
      ).toBe(0n);
      expect(
        await rpc.getContractEvents({
          address: usdc,
          abi: erc20Abi,
          eventName: "Approval",
          fromBlock: startBlock + 1n,
          toBlock: receipt.blockNumber,
        }),
      ).toHaveLength(0);
      if (mixed) {
        expect(
          await rpc.readContract({
            address: otherToken,
            abi: erc20Abi,
            functionName: "balanceOf",
            args: [predicted],
          }),
        ).toBe(500_000n);
      }
    },
    30_000,
  );
});
