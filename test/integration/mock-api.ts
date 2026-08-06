/**
 * Mock API server for integration testing.
 *
 * Implements:
 *   GET  /           — health check
 *   POST /obfuscate_escrow — returns real escrow bytecode (unobfuscated)
 *   POST /pricing/quote — returns an exact EscrowBatch deployment quote
 *   POST /compliance — returns a quote-bound mock execution approval
 *   ANY  /nomad/{chainId}/* — forwarded to the mock nomad, mirroring the
 *                            real API's nomad proxy
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { encrypt } from "eciesjs";
import { encodeAbiParameters, keccak256, stringToHex, zeroAddress } from "viem";
import { mockPublicKeyHex } from "./mock-nomad.js";

const ESCROW_DIR = path.resolve(import.meta.dirname, "../../../escrow/artifacts");

function readBytecode(filename: string): string {
  return fs.readFileSync(path.join(ESCROW_DIR, filename), "utf-8").trim();
}

/** Forward a proxied nomad request to the mock nomad and pipe the response back. */
async function proxyToNomad(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  nomadUrl: string,
  path: string,
): Promise<void> {
  try {
    const body =
      req.method === "GET" || req.method === "HEAD"
        ? undefined
        : await new Promise<string>((resolve, reject) => {
            let buf = "";
            req.on("data", (chunk: Buffer) => {
              buf += chunk.toString();
            });
            req.on("end", () => resolve(buf));
            // Without this the promise never settles on a client abort,
            // leaving the handler hung and the response never written.
            req.on("error", reject);
          });

    const upstream = await fetch(`${nomadUrl}${path}`, {
      method: req.method,
      headers: { "Content-Type": "application/json" },
      body,
    });
    const text = await upstream.text();
    res.writeHead(upstream.status, { "Content-Type": "application/json" });
    res.end(text);
  } catch (err) {
    res.writeHead(502, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: String(err) }));
  }
}

function createServer(port: number, nomadUrl?: string): http.Server {
  // Lazy-load bytecode on first request
  let erc20Deployment: string | null = null;
  let erc20Runtime: string | null = null;
  let nativeDeployment: string | null = null;
  let nativeRuntime: string | null = null;
  let batchDeployment: string | null = null;

  function loadBytecode() {
    if (!erc20Deployment) {
      erc20Deployment = readBytecode("erc20_deployment.hex");
      erc20Runtime = readBytecode("erc20_runtime.hex");
      nativeDeployment = readBytecode("native_deployment.hex");
      nativeRuntime = readBytecode("native_runtime.hex");
      batchDeployment = readBytecode("batch_deployment.hex");
    }
  }

  const server = http.createServer(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // Forward the full /nomad/{chainId}/... path so the node sees which chain
    // was requested, as it would behind the real proxy.
    if (/^\/nomad\/\d+\//.test(req.url ?? "")) {
      const target = nomadUrl ?? `http://127.0.0.1:${process.env.NOMAD_PORT || "8111"}`;
      await proxyToNomad(req, res, target, req.url!);
      return;
    }

    if (req.method === "GET" && req.url === "/") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          version: "mock",
          max_tx_usd: {},
          whitelist_required_usd: {},
        }),
      );
      return;
    }

    if (req.method === "POST" && req.url === "/obfuscate_escrow") {
      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        try {
          loadBytecode();
          const request = JSON.parse(body);
          const bytecode =
            request.escrow_type === "native"
              ? nativeDeployment!
              : request.escrow_type === "batch"
                ? batchDeployment!
                : erc20Deployment!;
          const size = (bytecode.length - 2) / 2; // minus 0x prefix, hex->bytes

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            obfuscated_bytecode: bytecode,
            original_size: size,
            obfuscated_size: size,
            size_increase_percentage: 0,
            gas_analysis: null,
            metadata: {
              transforms_applied: [],
              execution_time_ms: 0,
              blocks_created: 0,
              instructions_added: 0,
              unknown_opcodes_count: 0,
              size_limit_exceeded: false,
            },
            selector_mapping: null,
          }));
        } catch (err) {
          console.error("[mock-api] obfuscate_escrow error:", err);
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: String(err) }));
        }
      });
      return;
    }

    if (req.method === "POST" && req.url === "/pricing/quote") {
      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        try {
          const request = JSON.parse(body) as {
            chain_id: number;
            sender: string;
            blinded_signers: string[];
            signals: Array<{
              asset: string;
              execution_mode: "private" | "native";
              items: Array<{ client_row_id: string; recipient: string; amount: string }>;
            }>;
          };
          const rows = request.signals.flatMap((signal, signalIndex) =>
            signal.items.map((item, itemIndex) => ({
              signalIndex,
              clientRowId: item.client_row_id,
              executionMode: signal.execution_mode,
              asset: signal.asset,
              recipient: item.recipient,
              amount: item.amount,
              valueWeight: item.amount,
              rowIndex: itemIndex,
            })),
          );
          if (rows.length === 0 || request.blinded_signers.length !== rows.length) {
            throw new Error("pricing requires one blinded signer per row");
          }
          const rewardAsset = request.signals[0].asset;
          const rewardAmount = 25n;
          const deposits = new Map<string, bigint>();
          for (const row of rows) {
            const key = row.asset.toLowerCase();
            deposits.set(key, (deposits.get(key) ?? 0n) + BigInt(row.amount));
          }
          const rewardKey = rewardAsset.toLowerCase();
          deposits.set(rewardKey, (deposits.get(rewardKey) ?? 0n) + rewardAmount);
          const constructorArgs = encodeAbiParameters(
            [
              { type: "address" },
              {
                type: "tuple[]",
                components: [
                  { type: "address", name: "asset" },
                  { type: "address", name: "recipient" },
                  { type: "uint256", name: "amount" },
                  { type: "uint256", name: "valueWeight" },
                ],
              },
              { type: "uint256" },
              { type: "address[]" },
            ],
            [
              rewardAsset as `0x${string}`,
              rows.map((row) => ({
                asset: row.asset as `0x${string}`,
                recipient: row.recipient as `0x${string}`,
                amount: BigInt(row.amount),
                valueWeight: BigInt(row.valueWeight),
              })),
              rewardAmount,
              request.blinded_signers as `0x${string}`[],
            ],
          );
          const quoteCommitment = keccak256(
            stringToHex(`${body}:${crypto.randomUUID()}`),
          );
          const authorization = {
            version: 1,
            chainId: request.chain_id,
            sender: request.sender,
            rewardAsset,
            rewardAmount: rewardAmount.toString(),
            rows: rows.map((row, rowIndex) => ({ ...row, rowIndex })),
            quoteCommitment,
          };
          const sealed = encrypt(
            mockPublicKeyHex,
            new TextEncoder().encode(JSON.stringify(authorization)),
          );
          const depositByAsset = Object.fromEntries(
            [...deposits.entries()].map(([asset, amount]) => [asset, amount.toString()]),
          );

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            chain_id: request.chain_id,
            service_fee: { asset: rewardAsset, amount: rewardAmount.toString() },
            deployment: {
              escrow_type: "batch",
              constructor_args: constructorArgs,
              quote_commitment: quoteCommitment,
              reward_asset: rewardAsset,
              reward_amount: rewardAmount.toString(),
              deposit_by_asset: depositByAsset,
              msg_value: (deposits.get(zeroAddress) ?? 0n).toString(),
            },
            sealed_pricing_authorization: `0x${Buffer.from(sealed).toString("hex")}`,
          }));
        } catch (error) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: String(error) }));
        }
      });
      return;
    }

    if (req.method === "POST" && req.url === "/compliance") {
      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", async () => {
        const request = JSON.parse(body) as {
          tx_hash: `0x${string}`;
          chain_id: number;
          quote_commitment: `0x${string}`;
        };
        const rpc = process.env.RPC_URL || "http://127.0.0.1:8545";
        const receiptResponse = await fetch(rpc, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "eth_getTransactionReceipt",
            params: [request.tx_hash],
          }),
        });
        const receipt = (await receiptResponse.json()) as {
          result?: { contractAddress?: string };
        };
        const escrowContract = receipt.result?.contractAddress;
        if (!escrowContract) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "deployment receipt not found" }));
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          version: 1,
          chainId: request.chain_id,
          escrowContract,
          deploymentTxHash: request.tx_hash,
          runtimeCodeHash: `0x${"aa".repeat(32)}`,
          quoteCommitment: request.quote_commitment,
          approvedAt: Math.floor(Date.now() / 1000),
          signature: `0x${"ab".repeat(64)}`,
        }));
      });
      return;
    }

    res.writeHead(404);
    res.end("Not found");
  });

  return server;
}

export { createServer };

// Run standalone
const isMain = process.argv[1]?.endsWith("mock-api.ts") ||
  process.argv[1]?.endsWith("mock-api.js");

if (isMain) {
  const port = parseInt(process.env.API_PORT || "3000", 10);
  const server = createServer(port);
  server.listen(port, () => {
    console.log(`[mock-api] Listening on http://127.0.0.1:${port}`);
  });
}
