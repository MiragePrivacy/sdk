import type { Address } from "viem";
import { publicKeyToAddress } from "viem/utils";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import type { EscrowKind, GasConstants, NativeGasConstants } from "../types.js";
import { MirageError } from "../errors.js";

export interface BlindedSigner {
  /** address(G + s*B), stored on-chain as the escrow's blindedSigner. */
  blindedSigner: Address;
  /**
   * The per-escrow blinding scalar s, sent in the signal so the enclave signs
   * the BondAuth with g + s. Must never be reused across escrows: reuse links
   * escrows to the network key.
   */
  blindingScalar: `0x${string}`;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Derive a fresh stealth signer from the enclave's global public key G.
 *
 * P = G + s*B for a random scalar s. The enclave holds g (where G = g*B) and
 * signs the escrow's BondAuth with g + s, which recovers to address(P).
 */
export function deriveBlindedSigner(globalKeyHex: string): BlindedSigner {
  if (!globalKeyHex) {
    throw new MirageError(
      "MISSING_NETWORK_KEY",
      "Enclave public key is required to derive a blinded signer",
    );
  }

  let g;
  try {
    g = secp256k1.Point.fromHex(globalKeyHex.replace(/^0x/, ""));
  } catch (cause) {
    throw new MirageError("INVALID_NETWORK_KEY", "Enclave public key is not a valid secp256k1 point", {
      cause,
    });
  }

  const scalar = secp256k1.utils.randomSecretKey();
  const point = g.add(secp256k1.Point.BASE.multiply(secp256k1.Point.Fn.fromBytes(scalar)));

  return {
    blindedSigner: publicKeyToAddress(`0x${toHex(point.toBytes(false))}`),
    blindingScalar: `0x${toHex(scalar)}`,
  };
}

/**
 * Size the ETH pot the escrow holds to pay for the node's bond and collect
 * transactions. Margin covers gas price drift between deploy and collect;
 * unspent surplus is recoverable, so this is an outlay rather than a fee.
 */
export function computeBondPot(params: {
  escrowType: EscrowKind;
  gas: GasConstants;
  nativeGas: NativeGasConstants;
  maxFeePerGas: bigint;
  marginBps: bigint;
}): bigint {
  const { escrowType, gas, nativeGas, maxFeePerGas, marginBps } = params;

  // Batch escrows bill bond and collect through the node reward instead.
  if (escrowType === "batch") return 0n;

  const source = escrowType === "native" ? nativeGas : gas;
  const gasUnits = ((source.bond + source.collect) * marginBps + 99n) / 100n;
  return gasUnits * maxFeePerGas;
}
