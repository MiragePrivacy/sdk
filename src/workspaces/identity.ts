import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, encodeAbiParameters, keccak256, type Hex } from "viem";
import { bytes, uint, utf8 } from "./encoding";
import { disposeMemberKeys, unlockMember, type MemberKeys, type UnlockSigner } from "./keys";
import { verifyEd25519 } from "./signatures";

export const LINK_TYPE = "MirageIdentityLink(bytes32 keyA,bytes32 kemA,bytes32 keyB,bytes32 kemB,uint64 issuedAt)";
export const UNLINK_TYPE = "MirageIdentityUnlink(bytes32 linkId,bytes32 remainingKey,bytes32 revokedKey,uint64 issuedAt)";
export const ROTATION_TYPE = "MirageIdentityRotation(bytes32 oldKey,bytes32 oldKem,bytes32 newKey,bytes32 newKem,uint32 generation,uint64 issuedAt)";
export interface IdentityLink { keyA: Hex; kemA: Hex; keyB: Hex; kemB: Hex; issuedAt: number }
export interface SignedIdentityLink extends IdentityLink { signatureA: Hex; signatureB: Hex }
export interface IdentityUnlink {linkId:Hex;remainingKey:Hex;revokedKey:Hex;issuedAt:number}
export interface SignedIdentityUnlink extends IdentityUnlink {signature:Hex}
export interface IdentityLinkState {link:SignedIdentityLink;unlinking:boolean;rotations:SignedIdentityRotation[];workspaceIds:Hex[]}
export interface IdentityRotation { oldKey: Hex; oldKem: Hex; newKey: Hex; newKem: Hex; generation: number; issuedAt: number }
export interface SignedIdentityRotation extends IdentityRotation { signatureOld: Hex; signatureNew: Hex }

export function linkHash(link: IdentityLink): Hex {
  for (const key of [link.keyA, link.kemA, link.keyB, link.kemB]) bytes(key, 32);
  if (link.keyA >= link.keyB) throw new Error("Identity links require distinct, sorted signing keys");
  uint(link.issuedAt, 53, 1);
  return keccak256(encodeAbiParameters(
    [{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"uint64"}],
    [keccak256(utf8(LINK_TYPE)), link.keyA, link.kemA, link.keyB, link.kemB, BigInt(link.issuedAt)],
  ));
}

export function unlinkHash(unlink:IdentityUnlink):Hex {
  for(const key of [unlink.linkId,unlink.remainingKey,unlink.revokedKey])bytes(key,32);
  if(unlink.remainingKey===unlink.revokedKey)throw new Error("Unlink must retain a different key");
  uint(unlink.issuedAt,53,1);
  return keccak256(encodeAbiParameters([{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"uint64"}],
    [keccak256(utf8(UNLINK_TYPE)),unlink.linkId,unlink.remainingKey,unlink.revokedKey,BigInt(unlink.issuedAt)]));
}
export function createIdentityUnlink(linkId:Hex,revokedKey:Hex,remaining:MemberKeys,issuedAt:number):SignedIdentityUnlink {
  const unlink={linkId,remainingKey:remaining.memberKeyId,revokedKey,issuedAt};
  return {...unlink,signature:sign(unlinkHash(unlink),remaining)};
}
export function verifyIdentityUnlink(unlink:SignedIdentityUnlink):boolean {
  try{return verify(unlink.signature,unlinkHash(unlink),unlink.remainingKey);}catch{return false;}
}
/** Verify both generation branches before trusting link membership metadata. */
export function linkedKeyBranches(state:IdentityLinkState):[Map<Hex,Hex>,Map<Hex,Hex>] {
  if(!verifyIdentityLink(state.link)||typeof state.unlinking!=="boolean"||!Array.isArray(state.rotations)||!Array.isArray(state.workspaceIds))throw new Error("Invalid identity link state");
  for(const workspace of state.workspaceIds)bytes(workspace,16);
  const pointers=new Map<Hex,SignedIdentityRotation>();
  for(const pointer of state.rotations){
    if(pointers.has(pointer.oldKey)||!verifyIdentityRotation(pointer))throw new Error("Invalid linked identity rotation");
    pointers.set(pointer.oldKey,pointer);
  }
  const seen=new Set<Hex>(),used=new Set<Hex>();
  const branch=(initial:Hex,kem:Hex)=>{
    const keys=new Map<Hex,Hex>();let key=initial,generation:number|undefined;
    for(;;){
      if(seen.has(key))throw new Error("Linked identity branches overlap or cycle");
      seen.add(key);keys.set(key,kem);
      const pointer=pointers.get(key);if(!pointer)break;
      if(pointer.oldKem!==kem||(generation!==undefined&&pointer.generation!==generation+1))throw new Error("Invalid linked identity generation");
      used.add(key);key=pointer.newKey;kem=pointer.newKem;generation=pointer.generation;
    }
    return keys;
  };
  const branches:[Map<Hex,Hex>,Map<Hex,Hex>]=[branch(state.link.keyA,state.link.kemA),branch(state.link.keyB,state.link.kemB)];
  if(used.size!==pointers.size)throw new Error("Unrelated linked identity pointer");
  return branches;
}

export function rotationHash(rotation: IdentityRotation): Hex {
  for (const key of [rotation.oldKey, rotation.oldKem, rotation.newKey, rotation.newKem]) bytes(key, 32);
  if (rotation.oldKey === rotation.newKey) throw new Error("Rotation must replace the key");
  uint(rotation.generation, 32, 1); uint(rotation.issuedAt, 53, 1);
  return keccak256(encodeAbiParameters(
    [{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"uint32"},{type:"uint64"}],
    [keccak256(utf8(ROTATION_TYPE)), rotation.oldKey, rotation.oldKem, rotation.newKey, rotation.newKem, rotation.generation, BigInt(rotation.issuedAt)],
  ));
}

const sign = (hash: Hex, keys: MemberKeys): Hex => {
  if (bytesToHex(ed25519.getPublicKey(keys.signingSeed)) !== keys.memberKeyId) throw new Error("Signing key unavailable");
  return bytesToHex(ed25519.sign(bytes(hash, 32), keys.signingSeed));
};
const verify = verifyEd25519;

export function createIdentityLink(first: MemberKeys, second: MemberKeys, issuedAt: number): SignedIdentityLink {
  const [a, b] = first.memberKeyId < second.memberKeyId ? [first, second] : [second, first];
  const link = { keyA:a.memberKeyId, kemA:a.kemPublicKey, keyB:b.memberKeyId, kemB:b.kemPublicKey, issuedAt };
  const hash = linkHash(link);
  return { ...link, signatureA:sign(hash, a), signatureB:sign(hash, b) };
}

export function verifyIdentityLink(link: SignedIdentityLink): boolean {
  try { const hash = linkHash(link); return verify(link.signatureA, hash, link.keyA) && verify(link.signatureB, hash, link.keyB); }
  catch { return false; }
}

export function createIdentityRotation(old: MemberKeys, replacement: MemberKeys, issuedAt: number): SignedIdentityRotation {
  if (replacement.generation !== old.generation + 1) throw new Error("Rotation must increment generation by one");
  const rotation = { oldKey:old.memberKeyId, oldKem:old.kemPublicKey, newKey:replacement.memberKeyId,
    newKem:replacement.kemPublicKey, generation:replacement.generation, issuedAt };
  const hash = rotationHash(rotation);
  return { ...rotation, signatureOld:sign(hash, old), signatureNew:sign(hash, replacement) };
}

export function verifyIdentityRotation(rotation: SignedIdentityRotation): boolean {
  try { const hash = rotationHash(rotation); return verify(rotation.signatureOld, hash, rotation.oldKey) && verify(rotation.signatureNew, hash, rotation.newKey); }
  catch { return false; }
}

/** Discovery only: these pointers confer no membership, session or envelope authority. */
export async function followIdentityRotations(signer: UnlockSigner, initial: MemberKeys, pointers: readonly SignedIdentityRotation[]): Promise<MemberKeys> {
  if (pointers.length > 64) throw new Error("Too many identity rotations");
  const chain = pointers.map(pointer => ({ ...pointer }));
  let current = initial;
  try {
    for (const pointer of chain) {
      if (!verifyIdentityRotation(pointer) || pointer.oldKey !== current.memberKeyId || pointer.oldKem !== current.kemPublicKey || pointer.generation !== current.generation + 1)
        throw new Error("Invalid identity rotation chain");
      const next = await unlockMember(signer, pointer.generation);
      if (next.memberKeyId !== pointer.newKey || next.kemPublicKey !== pointer.newKem) {
        disposeMemberKeys(next); throw new Error("Re-derived identity does not match rotation pointer");
      }
      if (current !== initial) disposeMemberKeys(current);
      current = next;
    }
    return current;
  } catch (error) { if (current !== initial) disposeMemberKeys(current); throw error; }
}
