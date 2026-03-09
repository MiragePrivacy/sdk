import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fetchNetworkKey } from "../../src/internal/api.js";
import { NOMAD_URL, startMockNomad, stopMockNomad, isTestnet } from "./setup.js";

describe("Nomad node", () => {
  beforeAll(async () => {
    await startMockNomad();
  });

  afterAll(async () => {
    await stopMockNomad();
  });

  it("returns network key via /attest", async () => {
    const key = await fetchNetworkKey(NOMAD_URL);
    expect(key.publicKey).toBeTruthy();
    expect(key.publicKey.length).toBeGreaterThan(0);
    if (!isTestnet) {
      expect(key.debug).toBe(true);
    }
  });

  it("public key is a valid compressed secp256k1 key", async () => {
    const key = await fetchNetworkKey(NOMAD_URL);
    const keyHex = key.publicKey.replace(/^0x/, "");
    expect(keyHex).toMatch(/^[0-9a-fA-F]+$/);
    // Compressed secp256k1: 33 bytes = 66 hex chars
    expect(keyHex.length).toBe(66);
  });
});
