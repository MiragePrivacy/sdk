import { describe, it, expect } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { publicKeyToAddress } from "viem/utils";
import { deriveBlindedSigner, computeBondPot } from "../src/internal/bond.js";
import { networks } from "../src/networks.js";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("deriveBlindedSigner", () => {
  const secret = secp256k1.utils.randomSecretKey();
  const globalKey = `0x${toHex(secp256k1.getPublicKey(secret, true))}`;

  it("produces an address the enclave can recover with g + s", () => {
    const { blindedSigner, blindingScalar } = deriveBlindedSigner(globalKey);

    // The enclave signs with g + s; that key must recover to blindedSigner.
    const combined = secp256k1.Point.Fn.add(
      secp256k1.Point.Fn.fromBytes(secret),
      secp256k1.Point.Fn.fromBytes(
        Uint8Array.from(
          (blindingScalar.slice(2).match(/../g) ?? []).map((b) => parseInt(b, 16)),
        ),
      ),
    );
    const enclaveAddress = publicKeyToAddress(
      `0x${toHex(secp256k1.Point.BASE.multiply(combined).toBytes(false))}`,
    );

    expect(blindedSigner).toBe(enclaveAddress);
  });

  it("accepts a key without the 0x prefix", () => {
    expect(() => deriveBlindedSigner(globalKey.slice(2))).not.toThrow();
  });

  it("never reuses a scalar", () => {
    const scalars = new Set(
      Array.from({ length: 25 }, () => deriveBlindedSigner(globalKey).blindingScalar),
    );
    expect(scalars.size).toBe(25);
  });

  it("emits a 32-byte scalar", () => {
    const { blindingScalar } = deriveBlindedSigner(globalKey);
    expect(blindingScalar).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("rejects a missing key", () => {
    expect(() => deriveBlindedSigner("")).toThrow(/required/i);
  });

  it("rejects a malformed key", () => {
    expect(() => deriveBlindedSigner("0xdeadbeef")).toThrow(/valid secp256k1/i);
  });
});

describe("computeBondPot", () => {
  const { gas, nativeGas } = networks.ethereum;
  const maxFeePerGas = 30_000_000_000n;

  it("covers bond + collect with margin", () => {
    const pot = computeBondPot({
      escrowType: "erc20",
      gas,
      nativeGas,
      maxFeePerGas,
      marginBps: 150n,
    });

    const bare = (gas.bond + gas.collect) * maxFeePerGas;
    expect(pot).toBeGreaterThan(bare);
    expect(pot).toBe((((gas.bond + gas.collect) * 150n + 99n) / 100n) * maxFeePerGas);
  });

  it("uses native gas for native escrows", () => {
    const pot = computeBondPot({
      escrowType: "native",
      gas,
      nativeGas,
      maxFeePerGas,
      marginBps: 150n,
    });

    expect(pot).toBe((((nativeGas.bond + nativeGas.collect) * 150n + 99n) / 100n) * maxFeePerGas);
  });

  it("is zero for batch escrows, which bill bond through the reward", () => {
    expect(
      computeBondPot({ escrowType: "batch", gas, nativeGas, maxFeePerGas, marginBps: 150n }),
    ).toBe(0n);
  });
});
