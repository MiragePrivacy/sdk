import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, recoverTypedDataAddress, type Address, type Hex, type TypedDataDefinition } from "viem";
import { bytes, uint, utf8 } from "./encoding";

export interface UnlockSigner {
  address: Address;
  signTypedData(data: TypedDataDefinition): Promise<Hex>;
}

/** Private arrays must stay in memory and be disposed on logout. Never serialize this object. */
export interface MemberKeys {
  generation: number;
  signingSeed: Uint8Array;
  kemSecret: Uint8Array;
  memberKeyId: Hex;
  kemPublicKey: Hex;
}

export function unlockMessage(generation = 0) {
  uint(generation, 32);
  return {
    domain: { name: "Mirage Workspaces", version: "1" },
    primaryType: "Unlock" as const,
    types: { Unlock: [{ name: "scope", type: "string" }, { name: "generation", type: "uint32" }] },
    message: { scope: "mirage-member-v1", generation },
  } as const;
}

/** Signature bytes are a root secret. The generation must match the signed message. */
export function deriveMemberKeys(signature: Hex, generation = 0): MemberKeys {
  uint(generation, 32);
  const raw = bytes(signature.toLowerCase() as Hex, 65);
  // Accept standard Ethereum RSV only. Normalize parity so 0/1 and 27/28 agree.
  if (raw[64] < 2) raw[64] += 27;
  if (raw[64] !== 27 && raw[64] !== 28) throw new Error("Invalid unlock signature recovery byte");
  if (secp256k1.Signature.fromBytes(raw.subarray(0, 64)).hasHighS()) throw new Error("Unlock signature must use low-S encoding");
  const signingSeed = hkdf(sha256, raw, utf8("mirage-member-v1"), utf8("sign"), 32);
  const kemSecret = hkdf(sha256, raw, utf8("mirage-member-v1"), utf8("kem"), 32);
  raw.fill(0);
  return { generation, signingSeed, kemSecret,
    memberKeyId: bytesToHex(ed25519.getPublicKey(signingSeed)),
    kemPublicKey: bytesToHex(x25519.getPublicKey(kemSecret)) };
}

export async function unlockMember(signer: UnlockSigner, generation = 0): Promise<MemberKeys> {
  const data = unlockMessage(generation);
  const expectedAddress = signer.address;
  const signature = await signer.signTypedData(data);
  const recovered = await recoverTypedDataAddress({ ...data, signature });
  if (recovered.toLowerCase() !== expectedAddress.toLowerCase()) throw new Error("Unlock signer changed");
  return deriveMemberKeys(signature, generation);
}

/** Best-effort zeroization; JavaScript cannot guarantee removal of runtime copies. */
export function disposeMemberKeys(keys: MemberKeys): void {
  keys.signingSeed.fill(0);
  keys.kemSecret.fill(0);
}
