import type { Address } from "viem";
import { publicKeyToAddress } from "viem/utils";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { MirageError } from "../errors.js";

export interface BatchBlindedSigners {
  /** Ordered one-time bid signers committed into EscrowBatch. */
  blindedSigners: Address[];
  /** Base scalar needed by Nomad to derive each corresponding private key. */
  blindingScalar: `0x${string}`;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Derive `G + (s + i)B` for every batch row from one fresh base scalar.
 * Nomad receives only `s` inside the encrypted Signal; the pricing API receives
 * only the resulting public addresses.
 */
export function deriveBatchBlindedSigners(
  globalKeyHex: string,
  signerCount: number,
): BatchBlindedSigners {
  if (!Number.isSafeInteger(signerCount) || signerCount < 1) {
    throw new MirageError("INVALID_PARAMS", "At least one batch signer is required");
  }

  let globalPoint;
  try {
    globalPoint = secp256k1.Point.fromHex(globalKeyHex.replace(/^0x/, ""));
  } catch (cause) {
    throw new MirageError("INVALID_NETWORK_KEY", "Enclave public key is not a valid secp256k1 point", {
      cause,
    });
  }

  while (true) {
    const scalarBytes = secp256k1.utils.randomSecretKey();
    const scalar = secp256k1.Point.Fn.fromBytes(scalarBytes);
    const blindedSigners: Address[] = [];
    let valid = true;

    for (let index = 0; index < signerCount; index++) {
      const indexedScalar = secp256k1.Point.Fn.add(scalar, BigInt(index));
      if (indexedScalar === 0n) {
        valid = false;
        break;
      }
      const point = globalPoint.add(secp256k1.Point.BASE.multiply(indexedScalar));
      blindedSigners.push(publicKeyToAddress(`0x${toHex(point.toBytes(false))}`));
    }

    if (valid) {
      return {
        blindedSigners,
        blindingScalar: `0x${toHex(scalarBytes)}`,
      };
    }
  }
}
