/**
 * Mock API server for integration testing.
 *
 * Implements:
 *   GET  /           — health check
 *   POST /obfuscate_escrow — returns real escrow bytecode (unobfuscated)
 *   POST /compliance — returns a mock compliance approval
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const ESCROW_DIR = path.resolve(import.meta.dirname, "../../../escrow/artifacts");

function readBytecode(filename: string): string {
  return fs.readFileSync(path.join(ESCROW_DIR, filename), "utf-8").trim();
}

function createServer(port: number): http.Server {
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

    if (req.method === "POST" && req.url === "/compliance") {
      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        const now = Math.floor(Date.now() / 1000);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          signature: "0x" + "ab".repeat(64),
          timestamp: now,
          escrow_address: "0x0000000000000000000000000000000000000000",
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
