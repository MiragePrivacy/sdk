import { describe, it, expect } from "vitest";
import { networks, createNetworkConfig } from "../src/networks.js";

describe("networks", () => {
  it("has all three built-in networks", () => {
    expect(networks.ethereum).toBeDefined();
    expect(networks.sepolia).toBeDefined();
    expect(networks.tempo).toBeDefined();
  });

  it("ethereum defaults", () => {
    const eth = networks.ethereum;
    expect(eth.kind).toBe("ethereum");
    expect(eth.chainId).toBe(1);
    expect(eth.enableAtomicBatch).toBe(false);
    expect(eth.enableCompliance).toBe(true);
    expect(eth.platformFeeRate).toBe(50n);
    expect(eth.nodeFeeUsd).toBe(2_000000n);
  });

  it("sepolia defaults", () => {
    const sep = networks.sepolia;
    expect(sep.kind).toBe("ethereum");
    expect(sep.chainId).toBe(11155111);
    expect(sep.enableCompliance).toBe(true);
  });

  it("tempo defaults", () => {
    const tempo = networks.tempo;
    expect(tempo.kind).toBe("tempo");
    expect(tempo.chainId).toBe(42431);
    expect(tempo.enableAtomicBatch).toBe(true);
    expect(tempo.enableCompliance).toBe(false);
    expect(tempo.nodeFeeUsd).toBe(200000n);
  });

  it("has correct gas constants from reference", () => {
    const eth = networks.ethereum;
    expect(eth.gas.approve).toBe(46_686n);
    expect(eth.gas.deploy).toBe(2_167_182n);
    expect(eth.gas.bond).toBe(109_816n);
    expect(eth.gas.fund).toBe(120_000n);
    expect(eth.gas.collect).toBe(250_000n);
  });

  it("has native gas constants distinct from erc20", () => {
    const eth = networks.ethereum;
    expect(eth.nativeGas.deploy).toBe(1_924_115n);
    expect(eth.nativeGas.bond).toBe(92_366n);
    expect(eth.nativeGas.collect).toBe(250_000n);
    expect(eth.nativeGas.deploy).not.toBe(eth.gas.deploy);
  });

  it("has a bond pot margin", () => {
    expect(networks.ethereum.bondPotMarginBps).toBe(150n);
    expect(networks.ethereum.nodeFeeWei).toBe(500_000_000_000_000n);
  });

  it("requires attestation on every built-in network", () => {
    for (const network of Object.values(networks)) {
      expect(network.attestation?.required).toBe(true);
    }
  });

  it("never allows debug enclaves on mainnet", () => {
    expect(networks.ethereum.attestation?.allowDebug).toBe(false);
  });

  it("has correct tempo gas constants", () => {
    const tempo = networks.tempo;
    expect(tempo.gas.approve).toBe(279_126n);
    expect(tempo.gas.deploy).toBe(11_748_263n);
    expect(tempo.gas.bond).toBe(825_039n);
    expect(tempo.gas.fund).toBe(310_574n);
    expect(tempo.gas.collect).toBe(932_363n);
  });
});

describe("createNetworkConfig", () => {
  it("creates from network id without overrides", () => {
    const config = createNetworkConfig("ethereum");
    expect(config).toEqual(networks.ethereum);
    // Must be a separate object
    expect(config).not.toBe(networks.ethereum);
    expect(config.gas).not.toBe(networks.ethereum.gas);
  });

  it("overrides top-level fields", () => {
    const config = createNetworkConfig("ethereum", {
      platformFeeRate: 100n,
      enableCompliance: false,
    });
    expect(config.platformFeeRate).toBe(100n);
    expect(config.enableCompliance).toBe(false);
    expect(config.chainId).toBe(1);
    expect(config.kind).toBe("ethereum");
  });

  it("deep-merges gas constants", () => {
    const config = createNetworkConfig("ethereum", {
      gas: { approve: 60_000n },
    });
    expect(config.gas.approve).toBe(60_000n);
    expect(config.gas.deploy).toBe(networks.ethereum.gas.deploy);
    expect(config.gas.bond).toBe(networks.ethereum.gas.bond);
    expect(config.gas.fund).toBe(networks.ethereum.gas.fund);
    expect(config.gas.collect).toBe(networks.ethereum.gas.collect);
  });

  it("accepts a full config as base", () => {
    const custom = { ...networks.sepolia, gas: { ...networks.sepolia.gas }, chainId: 99999 };
    const config = createNetworkConfig(custom, { platformFeeRate: 0n });
    expect(config.chainId).toBe(99999);
    expect(config.platformFeeRate).toBe(0n);
  });

  it("does not mutate the built-in network", () => {
    const beforeApprove = networks.ethereum.gas.approve;
    const beforeDeploy = networks.ethereum.gas.deploy;
    createNetworkConfig("ethereum", { gas: { approve: 999n } });
    expect(networks.ethereum.gas.approve).toBe(beforeApprove);
    expect(networks.ethereum.gas.deploy).toBe(beforeDeploy);
  });

  it("does not mutate a custom config passed as base", () => {
    const custom = { ...networks.sepolia, gas: { ...networks.sepolia.gas } };
    const originalApprove = custom.gas.approve;
    createNetworkConfig(custom, { gas: { approve: 999n } });
    expect(custom.gas.approve).toBe(originalApprove);
  });

  it("merges attestation overrides without dropping required", () => {
    // Replacing the object wholesale would silently disable verification.
    const config = createNetworkConfig("ethereum", { attestation: { allowDebug: true } });
    expect(config.attestation?.allowDebug).toBe(true);
    expect(config.attestation?.required).toBe(true);
  });

  it("allows explicitly opting out of attestation", () => {
    const config = createNetworkConfig("ethereum", { attestation: { required: false } });
    expect(config.attestation?.required).toBe(false);
  });

  it("does not mutate the built-in attestation policy", () => {
    createNetworkConfig("ethereum", { attestation: { allowDebug: true } });
    expect(networks.ethereum.attestation?.allowDebug).toBe(false);
  });

  it("deep-merges nativeGas independently of gas", () => {
    const config = createNetworkConfig("ethereum", { nativeGas: { deploy: 111n } });
    expect(config.nativeGas.deploy).toBe(111n);
    expect(config.nativeGas.bond).toBe(networks.ethereum.nativeGas.bond);
    expect(config.gas.deploy).toBe(networks.ethereum.gas.deploy);
    expect(networks.ethereum.nativeGas.deploy).toBe(1_924_115n);
  });
});
