import { ed25519 } from "@noble/curves/ed25519.js";
import type { Hex } from "viem";
import { bytes } from "./encoding";

/** One verification profile in Rust and JS: canonical, nonzero prime-order A/R. */
export function verifyEd25519(signature: Hex, hash: Hex, key: Hex): boolean {
  try {
    const raw = bytes(signature, 64);
    const publicKey = bytes(key, 32);
    const a = ed25519.Point.fromBytes(publicKey, false);
    const r = ed25519.Point.fromBytes(raw.subarray(0, 32), false);
    if (a.isSmallOrder() || r.isSmallOrder() || !a.isTorsionFree() || !r.isTorsionFree()) return false;
    return ed25519.verify(raw, bytes(hash, 32), publicKey, { zip215:false });
  } catch { return false; }
}
