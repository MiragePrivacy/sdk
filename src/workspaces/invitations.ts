import {ed25519} from "@noble/curves/ed25519.js";
import {hkdf} from "@noble/hashes/hkdf.js";
import {sha256} from "@noble/hashes/sha2.js";
import {bytesToHex,keccak256,type Hex} from "viem";
import {buffer,bytes,canonicalJson,randomBytes,randomId,utf8,type Json} from "./encoding";
import {sealKey} from "./hpke";
import {linkedKeyBranches} from "./identity";
import type {MemberKeys} from "./keys";
import {applyPolicyOp,inviteAcceptanceHash,inviteGrantHash,replayPolicy,signPolicyOp,ZERO_HASH,type InviteAcceptance,type InviteGrant,type PolicyOp} from "./policy";
import {WorkspaceClient,type InviteBundle,type InviteCiphertext,type PendingInvite,type PolicyResponse} from "./client";
import {WorkspaceKeyring} from "./personal";

const ENCRYPTION_LABEL="mirage-invite-encryption-v1";
const SIGNING_LABEL="mirage-invite-signing-v1";

interface InvitePayload {
  version:1;
  workspaceId:Hex;
  grantId:Hex;
  contentKeys:{epoch:number;key:Hex}[];
  adminKey:Hex|null;
}
export type InviteHistory="all"|"from_invitation"|"from_acceptance";
export interface CreatedInvite {grantId:Hex;secret:Hex;bundle:InviteBundle}
export type AcceptedInvite={status:"joined";policy:PolicyResponse}|{status:"pending";workspaceId:Hex};

function derive(secret:Uint8Array,label:string):Uint8Array {
  return hkdf(sha256,secret,undefined,utf8(label),32);
}
function aad(workspaceId:Hex,grantId:Hex):Uint8Array {
  return utf8(canonicalJson({workspaceId,grantId}));
}
function ciphertextHash(value:InviteCiphertext):Hex {
  const nonce=bytes(value.nonce,12),ciphertext=bytes(value.ciphertext),joined=new Uint8Array(nonce.length+ciphertext.length);
  joined.set(nonce);joined.set(ciphertext,nonce.length);return keccak256(bytesToHex(joined));
}
async function aesKey(raw:Uint8Array,usage:"encrypt"|"decrypt"):Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey("raw",buffer(raw),"AES-GCM",false,[usage]);
}
async function encryptPayload(secret:Uint8Array,payload:InvitePayload):Promise<InviteCiphertext> {
  const raw=derive(secret,ENCRYPTION_LABEL),nonce=randomBytes(12);
  try {
    const key=await aesKey(raw,"encrypt");
    const plaintext=utf8(canonicalJson(payload as unknown as Json));
    const ciphertext=new Uint8Array(await globalThis.crypto.subtle.encrypt({name:"AES-GCM",iv:buffer(nonce),additionalData:buffer(aad(payload.workspaceId,payload.grantId)),tagLength:128},key,buffer(plaintext)));
    return {nonce:bytesToHex(nonce),ciphertext:bytesToHex(ciphertext)};
  } finally {raw.fill(0);}
}
async function decryptPayload(secret:Uint8Array,bundle:InviteBundle):Promise<InvitePayload> {
  const raw=derive(secret,ENCRYPTION_LABEL);
  try {
    const key=await aesKey(raw,"decrypt");
    const plaintext=await globalThis.crypto.subtle.decrypt({name:"AES-GCM",iv:buffer(bytes(bundle.ciphertext.nonce,12)),additionalData:buffer(aad(bundle.grant.workspaceId,bundle.grant.grantId)),tagLength:128},key,buffer(bytes(bundle.ciphertext.ciphertext)));
    const payload=JSON.parse(new TextDecoder(undefined,{fatal:true}).decode(plaintext)) as InvitePayload;
    if(canonicalJson(payload as unknown as Json)!==new TextDecoder().decode(plaintext))throw new Error("Invite payload is not canonical");
    return payload;
  } finally {raw.fill(0);}
}

export async function createWorkspaceInvite(input:{client:WorkspaceClient;keyring:WorkspaceKeyring;history:InviteHistory;holdsAdmin?:boolean;caps?:number;expiresAt?:number}):Promise<CreatedInvite> {
  let policy=input.keyring.policySnapshot(),rotation:PolicyOp|undefined,preparedContent:Uint8Array|undefined;
  if(policy.personal)throw new Error("Personal workspaces cannot invite members");
  if(input.history==="from_invitation"){
    const prepared=await input.keyring.prepareContentRotationWithKey();rotation=prepared.op;preparedContent=prepared.contentKey;policy=applyPolicyOp(policy,rotation);
  }
  const contentEpochs=input.history==="all"
    ? [...new Set(policy.envelopes.filter(envelope=>envelope.kind==="content").map(envelope=>envelope.epoch))].sort((a,b)=>a-b)
    : input.history==="from_invitation"?[policy.keyEpoch]:[];
  const content=preparedContent?new Map([[policy.keyEpoch,preparedContent]]):input.keyring.inviteContentKeys(contentEpochs),secret=randomBytes(32),grantId=randomId();
  let admin:Uint8Array|null=null;
  try {
    if(input.holdsAdmin&&input.history!=="from_acceptance")admin=input.keyring.inviteAdminKey();
    const payload:InvitePayload={version:1,workspaceId:policy.workspaceId,grantId,contentKeys:[...content].map(([epoch,key])=>({epoch,key:bytesToHex(key)})),adminKey:admin?bytesToHex(admin):null};
    const ciphertext=await encryptPayload(secret,payload),inviteSeed=derive(secret,SIGNING_LABEL),now=Math.floor(Date.now()/1000);
    try {
      const unsigned:InviteGrant={workspaceId:policy.workspaceId,grantId,invitePublicKey:bytesToHex(ed25519.getPublicKey(inviteSeed)),caps:input.caps??15,holdsAdmin:input.holdsAdmin??false,
        policyVersion:policy.policyVersion,adminEpoch:policy.adminEpoch,keyEpoch:policy.keyEpoch,contentEpochs,ciphertextHash:ciphertextHash(ciphertext),issuedAt:now,expiresAt:input.expiresAt??now+7*24*60*60,signature:ZERO_HASH};
      const grant={...unsigned,signature:input.keyring.signAdminHash(inviteGrantHash(unsigned))};
      const bundle=await input.client.createInvite(policy.workspaceId,grant,ciphertext,rotation);
      if(rotation)await input.keyring.load(bundle.policy);
      return {grantId,secret:bytesToHex(secret),bundle};
    } finally {inviteSeed.fill(0);}
  } finally {for(const key of content.values())key.fill(0);admin?.fill(0);secret.fill(0);}
}

export function verifyInviteBundle(bundle:InviteBundle):PolicyResponse {
  const policy=replayPolicy(bundle.policy.ops);
  if(canonicalJson(policy as unknown as Json)!==canonicalJson(bundle.policy.policy as unknown as Json))throw new Error("Invite policy does not match its signed log");
  const grant=bundle.grant;
  if(grant.workspaceId!==policy.workspaceId||grant.policyVersion!==policy.policyVersion||grant.adminEpoch!==policy.adminEpoch||grant.keyEpoch!==policy.keyEpoch)throw new Error("Invite is stale");
  if(grant.expiresAt<Math.floor(Date.now()/1000)||grant.ciphertextHash!==ciphertextHash(bundle.ciphertext)||!ed25519.verify(bytes(grant.signature,64),bytes(inviteGrantHash(grant),32),bytes(policy.adminPublicKey,32)))throw new Error("Invalid invite grant");
  return bundle.policy;
}

export async function acceptWorkspaceInvite(client:WorkspaceClient,keys:MemberKeys,grantId:Hex,secretHex:Hex):Promise<AcceptedInvite> {
  const bundle=await client.invite(grantId);verifyInviteBundle(bundle);
  const secret=bytes(secretHex,32),inviteSeed=derive(secret,SIGNING_LABEL);
  try {
    const payload=await decryptPayload(secret,bundle),grant=bundle.grant;
    const delayed=grant.contentEpochs.length===0;
    if(payload.version!==1||payload.workspaceId!==grant.workspaceId||payload.grantId!==grant.grantId||payload.contentKeys.map(item=>item.epoch).join(",")!==grant.contentEpochs.join(",")||Boolean(payload.adminKey)!==(grant.holdsAdmin&&!delayed))throw new Error("Invite payload does not match grant");
    const memberId=randomId(),identityProofs=[] as InviteAcceptance["identityProofs"],memberKeys=[{memberKeyId:keys.memberKeyId,kemPublicKey:keys.kemPublicKey,generation:keys.generation}];
    for(const state of await client.links())if(!state.unlinking){
      const branches=linkedKeyBranches(state),actor=branches.findIndex(branch=>[...branch.keys()].at(-1)===keys.memberKeyId);
      if(actor!==-1){const [memberKeyId,kemPublicKey]=[...branches[1-actor]].at(-1)!;const pointer=state.rotations.find(rotation=>rotation.newKey===memberKeyId);memberKeys.push({memberKeyId,kemPublicKey,generation:pointer?.generation??0});identityProofs.push({link:state.link,rotations:state.rotations});}
    }
    memberKeys.sort((a,b)=>a.memberKeyId.localeCompare(b.memberKeyId));
    const envelopes=await Promise.all(memberKeys.flatMap(member=>[
      ...payload.contentKeys.map(item=>sealKey({workspaceId:grant.workspaceId,kind:"content",epoch:item.epoch},member.memberKeyId,member.kemPublicKey,bytes(item.key,32))),
      ...(payload.adminKey?[sealKey({workspaceId:grant.workspaceId,kind:"admin",epoch:grant.adminEpoch},member.memberKeyId,member.kemPublicKey,bytes(payload.adminKey,32))]:[]),
    ]));
    const unsigned:InviteAcceptance={grantHash:inviteGrantHash(grant),memberId,acceptingKeyId:keys.memberKeyId,keys:memberKeys,identityProofs,envelopes,inviteSignature:ZERO_HASH};
    const acceptance={...unsigned,inviteSignature:bytesToHex(ed25519.sign(bytes(inviteAcceptanceHash(unsigned),32),inviteSeed))};
    if(delayed){await client.submitPendingInvite(grantId,acceptance);return{status:"pending",workspaceId:grant.workspaceId};}
    const op:PolicyOp={workspaceId:grant.workspaceId,policyVersion:grant.policyVersion+1,prevOpHash:bundle.policy.policy.headHash,kind:"add_member",payload:{grant,acceptance},issuedAt:Math.floor(Date.now()/1000),signerKeyId:keys.memberKeyId,signature:ZERO_HASH,adminSignature:null};
    return{status:"joined",policy:await client.acceptInvite(grantId,signPolicyOp(op,keys,null))};
  } finally {secret.fill(0);inviteSeed.fill(0);}
}

export async function finalizePendingInvite(client:WorkspaceClient,keyring:WorkspaceKeyring,pending:PendingInvite):Promise<PolicyResponse> {
  const op=await keyring.prepareInviteFinalization(pending.grant,pending.acceptance);
  const response=await client.finalizeInvite(pending.grant.grantId,op);await keyring.load(response);return response;
}
