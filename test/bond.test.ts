import { describe, it, expect } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { publicKeyToAddress } from "viem/utils";
import { deriveBlindedSigners } from "../src/internal/bond.js";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("deriveBlindedSigners", () => {
  const secret = secp256k1.utils.randomSecretKey();
  const globalKey = `0x${toHex(secp256k1.getPublicKey(secret, true))}`;

  it("derives one ordered signer per row from s + index", () => {
    const result = deriveBlindedSigners(globalKey, 3);
    const scalarBytes = Uint8Array.from(
      (result.blindingScalar.slice(2).match(/../g) ?? []).map((byte) => parseInt(byte, 16)),
    );
    const scalar = secp256k1.Point.Fn.fromBytes(scalarBytes);

    expect(result.blindedSigners).toHaveLength(3);
    for (let index = 0; index < 3; index++) {
      const privateKey = secp256k1.Point.Fn.add(
        secp256k1.Point.Fn.fromBytes(secret),
        secp256k1.Point.Fn.add(scalar, BigInt(index)),
      );
      const expected = publicKeyToAddress(
        `0x${toHex(secp256k1.Point.BASE.multiply(privateKey).toBytes(false))}`,
      );
      expect(result.blindedSigners[index]).toBe(expected);
    }
  });

  it("rejects an empty signer set", () => {
    expect(() => deriveBlindedSigners(globalKey, 0)).toThrow(/at least one/i);
  });
});
