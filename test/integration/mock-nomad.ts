/**
 * Mock nomad node for integration testing.
 *
 * Implements:
 *   GET  /attest  — returns a fixed ECIES public key
 *   POST /signal  — decrypts the signal, then transfers tokens to the recipient
 *
 * Instead of bond/transfer/collect on the escrow, the mock simply sends tokens
 * (or ETH) directly from a funded anvil account to the recipient. The SDK's
 * pollTransferEvent will pick up the resulting Transfer event.
 */

import http from "node:http";
import { PrivateKey, decrypt } from "eciesjs";
import {
  createPublicClient,
  createWalletClient,
  http as viemHttp,
  erc20Abi,
  zeroAddress,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvilChain } from "./setup.js";

// Fixed key pair — deterministic so tests can rely on the public key
const MOCK_PRIVATE_KEY_HEX =
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const mockKey = PrivateKey.fromHex(MOCK_PRIVATE_KEY_HEX);
const mockPublicKeyHex = mockKey.publicKey.toHex();

// Use anvil account[8] as the mock node's execution wallet
// (not used by sender or recipient in tests)
const NODE_PRIVATE_KEY =
  "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97" as const;
const nodeAccount = privateKeyToAccount(NODE_PRIVATE_KEY);

interface AuthorizationTransfer {
  asset: string;
  recipient: string;
  amount: string;
}

interface SignalEnvelope {
  escrowContract: string;
  blindingScalar: string;
  sealedPricingAuthorization: string;
  executionApproval: { quoteCommitment: string };
  selectorMapping: Record<string, string> | null;
}

function getRpcUrl(): string {
  return process.env.RPC_URL || "http://127.0.0.1:8545";
}

async function executeTransfer(rows: AuthorizationTransfer[]): Promise<void> {
  const rpcUrl = getRpcUrl();
  const publicClient = createPublicClient({
    chain: anvilChain,
    transport: viemHttp(rpcUrl),
  });
  const walletClient = createWalletClient({
    account: nodeAccount,
    chain: anvilChain,
    transport: viemHttp(rpcUrl),
  });

  // The node delivers one transaction per recipient, so a batch lands
  // incrementally rather than all at once.
  for (const row of rows) {
    const recipient = row.recipient as Address;
    const amount = BigInt(row.amount);
    const isNative = row.asset === zeroAddress;

    if (isNative) {
      const hash = await walletClient.sendTransaction({ to: recipient, value: amount });
      await publicClient.waitForTransactionReceipt({ hash });
      console.log(`[mock-nomad] ETH transfer: ${amount} wei -> ${recipient} (${hash})`);
    } else {
      const hash = await walletClient.writeContract({
        address: row.asset as Address,
        abi: erc20Abi,
        functionName: "transfer",
        args: [recipient, amount],
      });
      await publicClient.waitForTransactionReceipt({ hash });
      console.log(`[mock-nomad] ERC20 transfer: ${amount} ${row.asset} -> ${recipient} (${hash})`);
    }
  }
}

function createServer(port: number): http.Server {
  const server = http.createServer(async (req, res) => {
    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === "GET" && req.url === "/attest") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          // Current nodes nest these in a hash-committed payload.
          payload: { publicKey: mockPublicKeyHex, chainId: 31337 },
          attestation: null,
          isDebug: true,
        }),
      );
      return;
    }

    if (req.method === "POST" && req.url === "/signal") {
      let body = "";
      req.on("data", (chunk: Buffer) => {
        body += chunk.toString();
      });
      req.on("end", async () => {
        try {
          // SDK sends JSON-encoded hex string: "\"0xabcdef...\""
          const hexStr: string = JSON.parse(body);
          const encryptedBytes = Buffer.from(hexStr.replace(/^0x/, ""), "hex");

          // Decrypt with our private key
          const decrypted = decrypt(MOCK_PRIVATE_KEY_HEX, encryptedBytes);
          const signalJson = new TextDecoder().decode(decrypted);
          const signal: SignalEnvelope = JSON.parse(signalJson);
          if (!signal.blindingScalar) throw new Error("missing field blindingScalar");
          const sealed = Buffer.from(signal.sealedPricingAuthorization.replace(/^0x/, ""), "hex");
          const authorization = JSON.parse(
            new TextDecoder().decode(decrypt(MOCK_PRIVATE_KEY_HEX, sealed)),
          ) as { quoteCommitment: string; rows: AuthorizationTransfer[] };
          if (authorization.quoteCommitment !== signal.executionApproval.quoteCommitment) {
            throw new Error("pricing and execution approval commitments differ");
          }

          console.log("[mock-nomad] Received signal:", {
            escrow: signal.escrowContract,
            rows: authorization.rows.length,
          });

          // Execute the transfer
          await executeTransfer(authorization.rows);

          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end('"ok"');
        } catch (err) {
          console.error("[mock-nomad] Signal processing error:", err);
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: String(err) }));
        }
      });
      return;
    }

    res.writeHead(404);
    res.end("Not found");
  });

  return server;
}

// Export for programmatic use in tests
export { mockPublicKeyHex, MOCK_PRIVATE_KEY_HEX, createServer };

// Run standalone if executed directly
const isMain = process.argv[1]?.endsWith("mock-nomad.ts") ||
  process.argv[1]?.endsWith("mock-nomad.js");

if (isMain) {
  const port = parseInt(process.env.NOMAD_PORT || "8000", 10);
  const server = createServer(port);
  server.listen(port, () => {
    console.log(`[mock-nomad] Listening on http://127.0.0.1:${port}`);
    console.log(`[mock-nomad] Public key: ${mockPublicKeyHex}`);
  });
}
