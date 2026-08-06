import { describe, expect, it } from "vitest";
import { MIRAGE_MRSIGNER, createNetworkConfig, networks } from "../src/networks.js";

describe("networks", () => {
  it("defines Ethereum, Sepolia, and Tempo transport endpoints", () => {
    expect(networks.ethereum).toMatchObject({ chainId: 1, kind: "ethereum" });
    expect(networks.sepolia).toMatchObject({ chainId: 11155111, kind: "ethereum" });
    expect(networks.tempo).toMatchObject({ chainId: 42431, kind: "tempo" });
  });

  it("contains no client-side platform or node pricing constants", () => {
    for (const network of Object.values(networks)) {
      expect(network).not.toHaveProperty("platformFeeRate");
      expect(network).not.toHaveProperty("nodeFeeUsd");
      expect(network).not.toHaveProperty("nodeFeeWei");
      expect(network).not.toHaveProperty("gas");
      expect(network).not.toHaveProperty("bondPotMarginBps");
    }
  });

  it("requires an attested Mirage enclave on every built-in network", () => {
    for (const network of Object.values(networks)) {
      expect(network.attestation?.required).toBe(true);
      expect(network.attestation?.expectedMrSigner).toEqual([MIRAGE_MRSIGNER]);
    }
    expect(networks.ethereum.attestation?.allowDebug).toBe(false);
  });
});

describe("createNetworkConfig", () => {
  it("copies the base and deep-merges attestation policy", () => {
    const config = createNetworkConfig("ethereum", {
      rpcUrl: "https://rpc.test",
      attestation: { allowDebug: true },
    });
    expect(config.rpcUrl).toBe("https://rpc.test");
    expect(config.attestation?.allowDebug).toBe(true);
    expect(config.attestation?.required).toBe(true);
    expect(config).not.toBe(networks.ethereum);
    expect(config.attestation).not.toBe(networks.ethereum.attestation);
    expect(networks.ethereum.attestation?.allowDebug).toBe(false);
  });
});
