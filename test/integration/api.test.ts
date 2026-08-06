import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fetchObfuscation, fetchApiHealth } from "../../src/internal/api.js";
import { API_URL, startMockApi, stopMockApi, isTestnet } from "./setup.js";

describe("API server", () => {
  beforeAll(async () => {
    await startMockApi();
  });

  afterAll(async () => {
    await stopMockApi();
  });

  it("health check returns status", async () => {
    const health = await fetchApiHealth(API_URL);
    expect(health.status).toBeTruthy();
  });

  it("obfuscates ERC20 escrow bytecode", async () => {
    const result = await fetchObfuscation(API_URL, "erc20");
    expect(result.obfuscatedBytecode).toMatch(/^0x[0-9a-fA-F]+$/);
    expect(result.originalSize).toBeGreaterThan(0);
    expect(result.obfuscatedSize).toBeGreaterThanOrEqual(result.originalSize);
  });

  it("obfuscates native escrow bytecode", async () => {
    const result = await fetchObfuscation(API_URL, "native");
    expect(result.obfuscatedBytecode).toMatch(/^0x[0-9a-fA-F]+$/);
  });

  it("obfuscates batch escrow bytecode", async () => {
    const result = await fetchObfuscation(API_URL, "batch");
    expect(result.obfuscatedBytecode).toMatch(/^0x[0-9a-fA-F]+$/);
    expect(result.deploymentGasEstimate).toBe(1_234_567n);
  });

  it("returns a fresh seed per request", async () => {
    const a = await fetchObfuscation(API_URL, "erc20");
    const b = await fetchObfuscation(API_URL, "erc20");
    expect(a.seed).toMatch(/^[0-9a-f]{64}$/);
    expect(a.seed).not.toBe(b.seed);
  });

  it.skipIf(isTestnet)("returns no selector mapping for unobfuscated bytecode", async () => {
    const result = await fetchObfuscation(API_URL, "erc20");
    // Mock returns null since bytecode is not actually obfuscated
    expect(result.selectorMapping).toBeFalsy();
  });
});
