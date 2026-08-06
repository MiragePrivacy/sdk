import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fetchNetworkKey } from "../../src/internal/api.js";
import { NOMAD_URL, getNetwork, startMockNomad, stopMockNomad, isTestnet } from "./setup.js";

const CHAIN_ID = getNetwork().chainId;

describe("Nomad node", () => {
  beforeAll(async () => {
    await startMockNomad();
  });

  afterAll(async () => {
    await stopMockNomad();
  });

  it("returns network key via /attest", async () => {
    const key = await fetchNetworkKey(NOMAD_URL, CHAIN_ID, { verify: false });
    expect(key.publicKey).toBeTruthy();
    expect(key.publicKey.length).toBeGreaterThan(0);
    if (!isTestnet) {
      expect(key.debug).toBe(true);
    }
  });

  it("public key is a valid compressed secp256k1 key", async () => {
    const key = await fetchNetworkKey(NOMAD_URL, CHAIN_ID, { verify: false });
    const keyHex = key.publicKey.replace(/^0x/, "");
    expect(keyHex).toMatch(/^[0-9a-fA-F]+$/);
    // Compressed secp256k1: 33 bytes = 66 hex chars
    expect(keyHex.length).toBe(66);
  });

  it("reports no verification when it was skipped", async () => {
    const key = await fetchNetworkKey(NOMAD_URL, CHAIN_ID, { verify: false });
    expect(key.verification).toBeUndefined();
  });

  it.skipIf(isTestnet)("verifies by default, refusing a node serving no quote", async () => {
    // The mock runs outside SGX. The default must fail closed rather than
    // silently trusting the asserted key.
    await expect(fetchNetworkKey(NOMAD_URL, CHAIN_ID)).rejects.toMatchObject({
      code: "ATTESTATION_MISSING",
    });
  });
});
