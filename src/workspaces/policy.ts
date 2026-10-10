import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, encodeAbiParameters, keccak256, type Hex } from "viem";
import { bytes, canonicalJson, uint, utf8, type Json } from "./encoding";
import { envelopeInfo, type KeyEnvelope } from "./hpke";
import { linkedKeyBranches, verifyIdentityLink, verifyIdentityRotation, type SignedIdentityLink, type SignedIdentityRotation } from "./identity";
import { type MemberKeys } from "./keys";
import { type AuthorPolicyCheck } from "./records";
import { verifyEd25519 } from "./signatures";

export const CAPS = { PROPOSE:1, VOTE:2, EXECUTE:4, WRITE:8, ALL:15 } as const;
export const ZERO_HASH = `0x${"00".repeat(32)}` as Hex;
export const POLICY_OP_TYPE = "MiragePolicyOp(bytes16 workspaceId,uint64 policyVersion,bytes32 prevOpHash,string kind,bytes32 payloadHash,uint64 issuedAt,bytes32 signerKeyId)";

export interface MemberKey {
  memberKeyId: Hex;
  kemPublicKey: Hex;
  generation: number;
  holdsAdmin: boolean;
  addedAtVersion: number;
  removedAtVersion: number | null;
}
export interface PolicyMember {
  memberId: Hex;
  caps: number;
  addedAtVersion: number;
  removedAtVersion: number | null;
  voteInvalidatedAtVersion: number;
  keys: MemberKey[];
}
export interface Policy {
  workspaceId: Hex;
  policyVersion: number;
  headHash: Hex;
  adminPublicKey: Hex;
  adminEpoch: number;
  keyEpoch: number;
  approvalThreshold: number;
  pendingThreshold: number | null;
  personal: boolean;
  members: PolicyMember[];
  envelopes: KeyEnvelope[];
}
export interface InitialKey { memberKeyId: Hex; kemPublicKey: Hex; generation: number }
export interface RotationMaterial { newEpoch: number; newAdminPublicKey: Hex | null; envelopes: KeyEnvelope[] }
export interface InviteGrant {
  workspaceId: Hex;
  grantId: Hex;
  invitePublicKey: Hex;
  caps: number;
  holdsAdmin: boolean;
  policyVersion: number;
  adminEpoch: number;
  keyEpoch: number;
  contentEpochs: number[];
  ciphertextHash: Hex;
  issuedAt: number;
  expiresAt: number;
  signature: Hex;
}
export interface InviteAcceptance {
  grantHash: Hex;
  memberId: Hex;
  acceptingKeyId: Hex;
  keys: InitialKey[];
  identityProofs: {link:SignedIdentityLink;rotations:SignedIdentityRotation[]}[];
  envelopes: KeyEnvelope[];
  inviteSignature: Hex;
}
export interface PolicyPayloads {
  create: { memberId:Hex; key:InitialKey; adminPublicKey:Hex; personal:boolean; envelopes:KeyEnvelope[] };
  add_member: { grant:InviteGrant; acceptance:InviteAcceptance; finalization?:{rotation:RotationMaterial;adminEnvelopes:KeyEnvelope[]} };
  link_key: { memberId:Hex; generation:number; link:SignedIdentityLink; rotations?:SignedIdentityRotation[]; envelopes:KeyEnvelope[] };
  unlink_key: { memberId:Hex; keyId:Hex; rotation:RotationMaterial };
  remove_key: { memberId:Hex; keyId:Hex; rotation:RotationMaterial };
  remove_member: { memberId:Hex; rotation:RotationMaterial };
  rotate_member: { memberId:Hex; pointer:SignedIdentityRotation; rotation:RotationMaterial };
  rotate_content: { rotation:RotationMaterial };
  rotate_admin: { rotation:RotationMaterial };
  set_threshold: { approvalThreshold:number };
  set_caps: { memberId:Hex; caps:number };
}
export type PolicyKind = keyof PolicyPayloads;
export type PolicyOp = { [K in PolicyKind]: {
  workspaceId:Hex; policyVersion:number; prevOpHash:Hex; kind:K;
  payload:PolicyPayloads[K]; issuedAt:number; signerKeyId:Hex;
  signature:Hex; adminSignature:Hex | null;
} }[PolicyKind];

function hashJson(domain:string,value:Json):Hex {
  return keccak256(utf8(`${domain}:${canonicalJson(value)}`));
}
export function inviteGrantHash(grant:InviteGrant):Hex {
  const {signature:_,...unsigned}=grant;
  return hashJson("mirage-invite-grant-v1",unsigned as unknown as Json);
}
export function inviteAcceptanceHash(acceptance:InviteAcceptance):Hex {
  const {inviteSignature:_,...unsigned}=acceptance;
  return hashJson("mirage-invite-acceptance-v1",unsigned as unknown as Json);
}

function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`Invalid workspace policy: ${message}`);
}
function fields(value: object, expected: string[]): void {
  requireCondition(value !== null && typeof value === "object" && !Array.isArray(value), "object required");
  requireCondition(Object.keys(value).sort().join(",") === [...expected].sort().join(","), "unexpected or missing fields");
}
function signingKey(key: Hex): void {
  const point = ed25519.Point.fromBytes(bytes(key, 32), false);
  requireCondition(!point.isSmallOrder() && point.isTorsionFree(), "invalid signing key");
}
function initialKey(key: InitialKey): void {
  fields(key, ["memberKeyId","kemPublicKey","generation"]);
  signingKey(key.memberKeyId); uint(key.generation,32);
  // Reject non-contributory KEM public keys before they can enter a roster.
  x25519.getSharedSecret(new Uint8Array(32).fill(1), bytes(key.kemPublicKey,32));
}
function envelope(envelope: KeyEnvelope, workspaceId: Hex): void {
  fields(envelope,["workspaceId","kind","epoch","recipientKeyId","enc","ciphertext"]);
  requireCondition(envelope.workspaceId === workspaceId,"envelope workspace");
  envelopeInfo(envelope); signingKey(envelope.recipientKeyId);
  bytes(envelope.enc,32); bytes(envelope.ciphertext,48);
}
const envelopeId = (e: KeyEnvelope) => `${e.recipientKeyId}:${e.kind}:${e.epoch}`;
export const currentMembers = (policy: Policy) => policy.members.filter(m => m.removedAtVersion === null);
export function currentMemberKey(policy: Policy, keyId: Hex): { member:PolicyMember; key:MemberKey } | undefined {
  for (const member of currentMembers(policy)) {
    const key = member.keys.find(k => k.memberKeyId === keyId && k.removedAtVersion === null);
    if (key) return {member,key};
  }
}
function memberById(policy: Policy, memberId: Hex): PolicyMember {
  bytes(memberId,16);
  const member = currentMembers(policy).find(m => m.memberId === memberId);
  requireCondition(member,"member is not current"); return member;
}
function ensureNewKey(policy: Policy, keyId: Hex): void {
  requireCondition(!policy.members.some(m => m.keys.some(k => k.memberKeyId === keyId)),"key already appeared in this workspace");
}
function liveKeys(policy: Policy): MemberKey[] { return currentMembers(policy).flatMap(m => m.keys.filter(k => k.removedAtVersion === null)); }

export function policyOpHash(op: PolicyOp): Hex {
  fields(op,["workspaceId","policyVersion","prevOpHash","kind","payload","issuedAt","signerKeyId","signature","adminSignature"]);
  bytes(op.workspaceId,16); bytes(op.prevOpHash,32); signingKey(op.signerKeyId);
  uint(op.policyVersion,53,1); uint(op.issuedAt,53,1);
  const payload = utf8(canonicalJson(op.payload as unknown as Json));
  requireCondition(payload.length <= 4 * 1024 * 1024,"operation too large");
  return keccak256(encodeAbiParameters(
    [{type:"bytes32"},{type:"bytes16"},{type:"uint64"},{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"uint64"},{type:"bytes32"}],
    [keccak256(utf8(POLICY_OP_TYPE)),op.workspaceId,BigInt(op.policyVersion),op.prevOpHash,
      keccak256(utf8(op.kind)),keccak256(payload),BigInt(op.issuedAt),op.signerKeyId],
  ));
}

export function signPolicyOp(op: PolicyOp, memberKeys: MemberKeys, adminSeed: Uint8Array | null): PolicyOp {
  requireCondition(op.signerKeyId === memberKeys.memberKeyId,"operation signer mismatch");
  requireCondition(bytesToHex(ed25519.getPublicKey(memberKeys.signingSeed)) === memberKeys.memberKeyId,"signing key unavailable");
  const hash = bytes(policyOpHash(op),32);
  return { ...op, signature:bytesToHex(ed25519.sign(hash,memberKeys.signingSeed)),
    adminSignature:adminSeed === null ? null : bytesToHex(ed25519.sign(hash,adminSeed)) };
}

/** Validate the full replacement envelope set before committing any state. */
function rotate(policy: Policy, material: RotationMaterial, requireAdmin: boolean): void {
  fields(material,["newEpoch","newAdminPublicKey","envelopes"]);
  uint(material.newEpoch,32,1);
  requireCondition(material.newEpoch === policy.keyEpoch + 1,"epoch must increment once");
  requireCondition((material.newAdminPublicKey !== null) === requireAdmin,"admin rotation requirement");
  if (requireAdmin) {
    signingKey(material.newAdminPublicKey!);
    requireCondition(material.newAdminPublicKey !== policy.adminPublicKey,"admin key must change");
  }
  const keys = liveKeys(policy);
  requireCondition(keys.some(k => k.holdsAdmin),"workspace must retain an owner key");
  const expected = keys.flatMap(k => [
    `${k.memberKeyId}:content:${material.newEpoch}`,
    ...(requireAdmin && k.holdsAdmin ? [`${k.memberKeyId}:admin:${material.newEpoch}`] : []),
  ]);
  appendEnvelopes(policy,material.envelopes,expected);
  policy.keyEpoch = material.newEpoch;
  if (requireAdmin) { policy.adminPublicKey = material.newAdminPublicKey!; policy.adminEpoch = material.newEpoch; }
}
function appendEnvelopes(policy: Policy, supplied: KeyEnvelope[], expected: string[]): void {
  requireCondition(Array.isArray(supplied) && supplied.length === expected.length,"incomplete envelope set");
  const ids = supplied.map(e => { envelope(e,policy.workspaceId); return envelopeId(e); });
  requireCondition(new Set(ids).size === ids.length,"duplicate envelope");
  requireCondition([...ids].sort().join("|") === [...expected].sort().join("|"),"wrong envelope recipients or epochs");
  requireCondition(!policy.envelopes.some(e => ids.includes(envelopeId(e))),"envelope replacement");
  policy.envelopes.push(...structuredClone(supplied));
}

/** Pure replay. Failed operations leave the caller's previous state untouched. */
export function applyPolicyOp(previous: Policy | null, input: PolicyOp): Policy {
  const op = structuredClone(input);
  const hash = policyOpHash(op);
  requireCondition(verifyEd25519(op.signature,hash,op.signerKeyId),"actor signature");
  if (op.kind === "create") {
    requireCondition(previous === null && op.policyVersion === 1 && op.prevOpHash === ZERO_HASH,"invalid create head");
    fields(op.payload,["memberId","key","adminPublicKey","personal","envelopes"]);
    const p = op.payload; initialKey(p.key); bytes(p.memberId,16); signingKey(p.adminPublicKey);
    requireCondition(typeof p.personal === "boolean","personal flag");
    requireCondition(p.key.memberKeyId === op.signerKeyId,"creator key");
    requireCondition(op.adminSignature !== null && verifyEd25519(op.adminSignature,hash,p.adminPublicKey),"initial admin signature");
    const policy: Policy = { workspaceId:op.workspaceId,policyVersion:1,headHash:hash,
      adminPublicKey:p.adminPublicKey,adminEpoch:1,keyEpoch:1,approvalThreshold:0,pendingThreshold:null,personal:p.personal,
      members:[{memberId:p.memberId,caps:15,addedAtVersion:1,removedAtVersion:null,voteInvalidatedAtVersion:0,
        keys:[{...p.key,holdsAdmin:true,addedAtVersion:1,removedAtVersion:null}]}],envelopes:[] };
    appendEnvelopes(policy,p.envelopes,[`${p.key.memberKeyId}:content:1`,`${p.key.memberKeyId}:admin:1`]);
    return policy;
  }
  requireCondition(previous !== null,"missing create");
  requireCondition(op.workspaceId === previous.workspaceId && op.policyVersion === previous.policyVersion + 1 && op.prevOpHash === previous.headHash,"stale or forked head");
  const policy = structuredClone(previous);
  if (op.kind === "add_member") {
    fields(op.payload,["grant","acceptance",...(Object.hasOwn(op.payload,"finalization")?["finalization"]:[])]);
    const {grant,acceptance,finalization}=op.payload;
    fields(grant,["workspaceId","grantId","invitePublicKey","caps","holdsAdmin","policyVersion","adminEpoch","keyEpoch","contentEpochs","ciphertextHash","issuedAt","expiresAt","signature"]);
    fields(acceptance,["grantHash","memberId","acceptingKeyId","keys","identityProofs","envelopes","inviteSignature"]);
    bytes(grant.grantId,16);signingKey(grant.invitePublicKey);uint(grant.caps,4);uint(grant.policyVersion,53,1);uint(grant.adminEpoch,32,1);uint(grant.keyEpoch,32,1);
    bytes(grant.ciphertextHash,32);uint(grant.issuedAt,53,1);uint(grant.expiresAt,53,1);
    requireCondition(grant.workspaceId===previous.workspaceId&&grant.policyVersion===previous.policyVersion&&grant.adminEpoch===previous.adminEpoch&&grant.keyEpoch===previous.keyEpoch,"stale invite grant");
    requireCondition(grant.expiresAt>=op.issuedAt&&grant.issuedAt<=op.issuedAt&&grant.expiresAt>grant.issuedAt,"expired invite grant");
    requireCondition(typeof grant.holdsAdmin==="boolean"&&verifyEd25519(grant.signature,inviteGrantHash(grant),previous.adminPublicKey),"invite grant signature");
    requireCondition(Array.isArray(grant.contentEpochs),"invite content epochs");
    for(const epoch of grant.contentEpochs)uint(epoch,32,1);
    requireCondition(new Set(grant.contentEpochs).size===grant.contentEpochs.length&&grant.contentEpochs.every((epoch,index)=>index===0||grant.contentEpochs[index-1]<epoch)&&(!grant.contentEpochs.length||grant.contentEpochs.at(-1)===previous.keyEpoch),"invalid invite content epochs");
    requireCondition(acceptance.grantHash===inviteGrantHash(grant),"invite grant hash");bytes(acceptance.memberId,16);
    requireCondition(verifyEd25519(acceptance.inviteSignature,inviteAcceptanceHash(acceptance),grant.invitePublicKey),"invite acceptance signature");
    requireCondition(Array.isArray(acceptance.keys)&&acceptance.keys.length>0&&acceptance.keys.length<=8,"invite member keys");
    for(const key of acceptance.keys){initialKey(key);ensureNewKey(previous,key.memberKeyId);}
    requireCondition(new Set(acceptance.keys.map(key=>key.memberKeyId)).size===acceptance.keys.length,"duplicate invite member key");
    requireCondition(acceptance.keys.map(key=>key.memberKeyId).sort().join("|")===acceptance.keys.map(key=>key.memberKeyId).join("|"),"invite member keys must be ordered");
    signingKey(acceptance.acceptingKeyId);
    const accepting=acceptance.keys.find(key=>key.memberKeyId===acceptance.acceptingKeyId);requireCondition(accepting,"accepting key missing");
    requireCondition(Array.isArray(acceptance.identityProofs)&&acceptance.identityProofs.length<=1,"invalid invite identity proofs");
    const linked=new Map<Hex,{kem:Hex;generation:number}>();
    for(const proof of acceptance.identityProofs){
      fields(proof,["link","rotations"]);const branches=linkedKeyBranches({link:proof.link,rotations:proof.rotations,workspaceIds:[],unlinking:false});
      const actorBranch=branches.findIndex(branch=>[...branch.keys()].at(-1)===acceptance.acceptingKeyId);requireCondition(actorBranch!==-1&&branches[actorBranch].get(acceptance.acceptingKeyId)===accepting.kemPublicKey,"identity proof does not contain accepting key");
      const [key,kem]=[...branches[1-actorBranch]].at(-1)!;const pointer=proof.rotations.find(rotation=>rotation.newKey===key);
      linked.set(key,{kem,generation:pointer?.generation??0});
    }
    for(const key of acceptance.keys)if(key.memberKeyId!==acceptance.acceptingKeyId){const proof=linked.get(key.memberKeyId);requireCondition(proof?.kem===key.kemPublicKey&&proof.generation===key.generation,"unlinked invite member key");linked.delete(key.memberKeyId);}
    requireCondition(linked.size===0,"identity proof key missing from acceptance");
    requireCondition(!previous.members.some(member=>member.memberId===acceptance.memberId),"member already appeared in workspace");
    const delayed=grant.contentEpochs.length===0;
    requireCondition(delayed===Boolean(finalization),"invite finalization requirement");
    if(delayed){
      requireCondition(acceptance.envelopes.length===0,"pending acceptance envelopes");
      const owner=currentMemberKey(previous,op.signerKeyId);requireCondition(owner?.key.holdsAdmin,"owner required to finalize invite");
      requireCondition(op.adminSignature!==null&&verifyEd25519(op.adminSignature,hash,previous.adminPublicKey),"current owner and admin signature required");
    }else{
      requireCondition(acceptance.acceptingKeyId===op.signerKeyId,"invite actor key");
      requireCondition(op.adminSignature===null,"unexpected admin signature");
    }
    const expected=acceptance.keys.flatMap(key=>[
      ...grant.contentEpochs.map(epoch=>`${key.memberKeyId}:content:${epoch}`),
      ...(grant.holdsAdmin?[`${key.memberKeyId}:admin:${previous.adminEpoch}`]:[]),
    ]);
    policy.members.push({memberId:acceptance.memberId,caps:grant.caps,addedAtVersion:op.policyVersion,removedAtVersion:null,voteInvalidatedAtVersion:0,
      keys:acceptance.keys.map(key=>({...key,holdsAdmin:grant.holdsAdmin,addedAtVersion:op.policyVersion,removedAtVersion:null}))});
    if(delayed){
      fields(finalization!,["rotation","adminEnvelopes"]);
      const adminExpected=grant.holdsAdmin?acceptance.keys.map(key=>`${key.memberKeyId}:admin:${previous.adminEpoch}`):[];
      appendEnvelopes(policy,finalization!.adminEnvelopes,adminExpected);rotate(policy,finalization!.rotation,false);
    }else appendEnvelopes(policy,acceptance.envelopes,expected);
    policy.policyVersion=op.policyVersion;policy.headHash=hash;return policy;
  }
  const actor = currentMemberKey(previous,op.signerKeyId);
  requireCondition(actor,"actor revoked");
  const admin = () => requireCondition(actor.key.holdsAdmin && op.adminSignature !== null && verifyEd25519(op.adminSignature,hash,previous.adminPublicKey),"current owner and admin signature required");
  const noAdmin = () => requireCondition(op.adminSignature === null,"unexpected admin signature");
  switch (op.kind) {
    case "link_key": {
      fields(op.payload,["memberId","generation","link","envelopes",...(Object.hasOwn(op.payload,"rotations")?["rotations"]:[])]);
      const p = op.payload; requireCondition(p.memberId === actor.member.memberId,"link belongs to another member");
      fields(p.link,["keyA","kemA","keyB","kemB","issuedAt","signatureA","signatureB"]);
      requireCondition(verifyIdentityLink(p.link),"cross-signed link");
      const rotations=p.rotations??[];
      if(p.rotations!==undefined)requireCondition(Array.isArray(rotations)&&rotations.length>0,"empty link rotation proof");
      for(const pointer of rotations)fields(pointer,["oldKey","oldKem","newKey","newKem","generation","issuedAt","signatureOld","signatureNew"]);
      const branches=linkedKeyBranches({link:p.link,rotations,workspaceIds:[],unlinking:false});
      const actorBranch=branches.findIndex(branch=>branch.has(op.signerKeyId));
      requireCondition(actorBranch!==-1,"link does not contain actor");
      requireCondition(branches[actorBranch].get(op.signerKeyId)===actor.key.kemPublicKey,"actor KEM mismatch");
      const actorPointer=rotations.find(pointer=>pointer.newKey===op.signerKeyId);
      const successor=rotations.find(pointer=>pointer.oldKey===op.signerKeyId);
      requireCondition(!actorPointer||actorPointer.generation===actor.key.generation,"actor generation mismatch");
      requireCondition(!successor||successor.generation===actor.key.generation+1,"actor successor generation mismatch");
      const [memberKeyId,kemPublicKey]=[...branches[1-actorBranch]].at(-1)!;
      const endpoint=rotations.find(pointer=>pointer.newKey===memberKeyId);
      requireCondition(!endpoint||endpoint.generation===p.generation,"linked generation mismatch");
      const newKey={memberKeyId,kemPublicKey,generation:p.generation};
      initialKey(newKey); ensureNewKey(policy,newKey.memberKeyId); noAdmin();
      const contentEpochs = policy.envelopes.filter(e => e.recipientKeyId === op.signerKeyId && e.kind === "content").map(e => e.epoch);
      const expected = contentEpochs.map(epoch => `${newKey.memberKeyId}:content:${epoch}`);
      if (actor.key.holdsAdmin) expected.push(`${newKey.memberKeyId}:admin:${policy.adminEpoch}`);
      appendEnvelopes(policy,p.envelopes,expected);
      memberById(policy,p.memberId).keys.push({...newKey,holdsAdmin:actor.key.holdsAdmin,addedAtVersion:op.policyVersion,removedAtVersion:null});
      break;
    }
    case "unlink_key": case "remove_key": {
      fields(op.payload,["memberId","keyId","rotation"]);
      const p = op.payload; const member = memberById(policy,p.memberId);
      const key = member.keys.find(k => k.memberKeyId === p.keyId && k.removedAtVersion === null);
      requireCondition(key,"key already revoked");
      requireCondition(p.keyId !== op.signerKeyId,"remaining key must authorize removal");
      requireCondition(member.keys.filter(k => k.removedAtVersion === null).length > 1,"use remove_member for last key");
      if (op.kind === "unlink_key") {
        requireCondition(p.memberId === actor.member.memberId,"unlink belongs to another member");
        if (key.holdsAdmin) admin(); else noAdmin();
      } else admin();
      key.removedAtVersion = op.policyVersion;
      rotate(policy,p.rotation,key.holdsAdmin); break;
    }
    case "remove_member": {
      fields(op.payload,["memberId","rotation"]); admin();
      const member = memberById(policy,op.payload.memberId);
      requireCondition(member.memberId !== actor.member.memberId,"remaining owner must remove member");
      const keys = member.keys.filter(k => k.removedAtVersion === null);
      member.removedAtVersion = op.policyVersion; member.voteInvalidatedAtVersion = op.policyVersion;
      for (const key of keys) key.removedAtVersion = op.policyVersion;
      rotate(policy,op.payload.rotation,keys.some(k => k.holdsAdmin)); break;
    }
    case "rotate_member": {
      fields(op.payload,["memberId","pointer","rotation"]);
      const p = op.payload; const pointer = p.pointer;
      fields(pointer,["oldKey","oldKem","newKey","newKem","generation","issuedAt","signatureOld","signatureNew"]);
      requireCondition(p.memberId === actor.member.memberId && pointer.oldKey === op.signerKeyId && pointer.oldKem === actor.key.kemPublicKey,"rotation actor");
      requireCondition(verifyIdentityRotation(pointer) && pointer.generation === actor.key.generation + 1,"rotation pointer");
      const replacement = {memberKeyId:pointer.newKey,kemPublicKey:pointer.newKem,generation:pointer.generation};
      initialKey(replacement); ensureNewKey(policy,pointer.newKey);
      if (actor.key.holdsAdmin) admin(); else noAdmin();
      const member = memberById(policy,p.memberId);
      member.keys.find(k => k.memberKeyId === op.signerKeyId && k.removedAtVersion === null)!.removedAtVersion = op.policyVersion;
      member.keys.push({...replacement,holdsAdmin:actor.key.holdsAdmin,addedAtVersion:op.policyVersion,removedAtVersion:null});
      // A replacement generation keeps all content epochs previously granted to this login.
      const historical = policy.envelopes.filter(e => e.recipientKeyId === op.signerKeyId && e.kind === "content");
      const oldEnvelopes = p.rotation.envelopes.filter(e => e.epoch <= previous.keyEpoch && e.kind === "content");
      appendEnvelopes(policy,oldEnvelopes,historical.map(e => `${pointer.newKey}:content:${e.epoch}`));
      rotate(policy,{...p.rotation,envelopes:p.rotation.envelopes.filter(e => !oldEnvelopes.includes(e))},actor.key.holdsAdmin);
      break;
    }
    case "rotate_content": case "rotate_admin":
      fields(op.payload,["rotation"]); admin(); rotate(policy,op.payload.rotation,op.kind === "rotate_admin"); break;
    case "set_threshold": {
      fields(op.payload,["approvalThreshold"]); admin(); uint(op.payload.approvalThreshold,32);
      const voters = currentMembers(policy).filter(m => (m.caps & CAPS.VOTE) !== 0).length;
      requireCondition(op.payload.approvalThreshold <= Math.max(0,voters - 1),"threshold exceeds eligible non-proposer voters");
      policy.approvalThreshold = op.payload.approvalThreshold; break;
    }
    case "set_caps": {
      fields(op.payload,["memberId","caps"]); admin(); uint(op.payload.caps,4);
      const member = memberById(policy,op.payload.memberId);
      if ((member.caps & CAPS.VOTE) !== 0 && (op.payload.caps & CAPS.VOTE) === 0) member.voteInvalidatedAtVersion = op.policyVersion;
      member.caps = op.payload.caps; break;
    }
    default: throw new Error("Unsupported workspace policy operation");
  }
  policy.policyVersion = op.policyVersion; policy.headHash = hash;
  return policy;
}

export function replayPolicy(ops: readonly PolicyOp[]): Policy {
  requireCondition(ops.length > 0,"empty log");
  let policy: Policy | null = null;
  for (const op of ops) policy = applyPolicyOp(policy,op);
  return policy!;
}

/** Verify the whole log before allowing historical ciphertext authors. */
export function policyAuthorCheck(ops: readonly PolicyOp[]): AuthorPolicyCheck {
  const history = new Map<number,Policy>(); let policy: Policy | null = null;
  for (const op of ops) { policy = applyPolicyOp(policy,op); history.set(policy.policyVersion,policy); }
  return (header,capability) => {
    const at = history.get(header.authorPolicyVersion);
    if (!at || at.workspaceId !== header.workspaceId || header.keyEpoch > at.keyEpoch) return false;
    const author = currentMemberKey(at,header.authorKeyId);
    return !!author && (author.member.caps & capability) === capability && at.envelopes.some(e =>
      e.recipientKeyId === header.authorKeyId && e.kind === "content" && e.epoch === header.keyEpoch);
  };
}
