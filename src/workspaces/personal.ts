import {ed25519} from "@noble/curves/ed25519.js";
import {bytesToHex,type Hex} from "viem";
import {ApiError} from "../errors.js";
import {canonicalJson,randomBytes,randomId,uint,type Json} from "./encoding";
import {WorkspaceClient,type PolicyResponse} from "./client";
import {openKey,sealKey} from "./hpke";
import type {MemberKeys} from "./keys";
import {linkedKeyBranches,createIdentityRotation,verifyIdentityRotation,type SignedIdentityRotation,type IdentityLinkState,type SignedIdentityLink} from "./identity";
import {applyPolicyOp,currentMemberKey,policyOpHash,replayPolicy,signPolicyOp,ZERO_HASH,type PolicyOp,type Policy,type MemberKey,type RotationMaterial} from "./policy";

/** Private workspace material lives only in this sign-in's memory. */
export class WorkspaceKeyring {
  private readonly content=new Map<number,Uint8Array>();
  private admin:Uint8Array|null=null;
  private adminEpoch=0;
  private verified:PolicyResponse|null=null;
  private closed=false;
  private pending:Promise<void>=Promise.resolve();
  constructor(readonly workspaceId:Hex,private readonly member:MemberKeys){}
  close():void {
    this.closed=true;for(const key of this.content.values())key.fill(0);this.content.clear();
    this.admin?.fill(0);this.admin=null;this.verified=null;
  }
  /** Serializes refreshes so a stale response cannot replace a newer policy/key set. */
  async load(input:PolicyResponse):Promise<ReadonlyMap<number,Uint8Array>> {
    const snapshot=structuredClone(input);
    const task=this.pending.catch(()=>undefined).then(()=>this.refresh(snapshot));this.pending=task;
    await task;if(this.closed)throw new Error("Workspace keyring closed");return this.content;
  }
  private async refresh(response:PolicyResponse):Promise<void> {
    if(this.closed)throw new Error("Workspace keyring closed");
    const policy=replayPolicy(response.ops);
    if(policy.workspaceId!==this.workspaceId||canonicalJson(policy as unknown as Json)!==canonicalJson(response.policy as unknown as Json))throw new Error("Invalid keyring policy");
    const previous=this.verified?.policy;
    if(previous&&(policy.policyVersion<previous.policyVersion||policyOpHash(response.ops[previous.policyVersion-1])!==previous.headHash))throw new Error("Workspace keyring policy rollback");
    const actor=currentMemberKey(policy,this.member.memberKeyId);
    if(!actor){this.close();throw new Error("Workspace membership revoked");}
    const supplied=policy.envelopes.filter(e=>e.recipientKeyId===this.member.memberKeyId);
    const opened=new Map<number,Uint8Array>();let admin:Uint8Array|null=null;
    try {
      for(const envelope of supplied)if(envelope.kind==="content"&&!this.content.has(envelope.epoch)){
        const key=await openKey(envelope,{...envelope,recipientKeyId:this.member.memberKeyId},this.member.kemSecret);opened.set(envelope.epoch,key);
        if(this.closed)throw new Error("Workspace keyring closed");
      }
      if(!this.content.has(policy.keyEpoch)&&!opened.has(policy.keyEpoch))throw new Error("Current content envelope missing");
      if(actor.key.holdsAdmin&&(!this.admin||this.adminEpoch!==policy.adminEpoch)){
        const envelope=supplied.find(e=>e.kind==="admin"&&e.epoch===policy.adminEpoch);
        if(!envelope)throw new Error("Current admin envelope missing");
        admin=await openKey(envelope,{...envelope,recipientKeyId:this.member.memberKeyId},this.member.kemSecret);
        if(bytesToHex(ed25519.getPublicKey(admin))!==policy.adminPublicKey)throw new Error("Admin envelope does not match policy authority");
      }
      if(this.closed)throw new Error("Workspace keyring closed");
      for(const [epoch,key] of opened)this.content.set(epoch,key);opened.clear();
      if(admin){this.admin?.fill(0);this.admin=admin;admin=null;this.adminEpoch=policy.adminEpoch;}
      if(!actor.key.holdsAdmin){this.admin?.fill(0);this.admin=null;this.adminEpoch=0;}
      this.verified={policy,ops:response.ops};
    }finally{for(const key of opened.values())key.fill(0);admin?.fill(0);}
  }
  /** Copies this member's granted history and owner authority to its linked key. */
  async prepareLinkedKey(input:SignedIdentityLink|IdentityLinkState,peer:MemberKeys):Promise<PolicyOp|null> {
    if(this.closed||!this.verified)throw new Error("Workspace keyring unavailable");
    const state:IdentityLinkState="link" in input?structuredClone(input):{link:structuredClone(input),rotations:[],unlinking:false,workspaceIds:[]};
    if(state.unlinking)throw new Error("Identity unlink is in progress");
    const {link,rotations}=state,policy=this.verified.policy;
    const branches=linkedKeyBranches(state);
    const actorBranch=branches.findIndex(branch=>branch.get(this.member.memberKeyId)===this.member.kemPublicKey);
    if(actorBranch===-1||branches[1-actorBranch].get(peer.memberKeyId)!==peer.kemPublicKey||[...branches[1-actorBranch].keys()].at(-1)!==peer.memberKeyId)throw new Error("Link does not match current workspace sign-ins");
    const actor=currentMemberKey(policy,this.member.memberKeyId)!;
    const existing=currentMemberKey(policy,peer.memberKeyId);
    if(existing){
      if(existing.member.memberId!==actor.member.memberId)throw new Error("Linked sign-in already has a separate workspace membership");
      return null;
    }
    const envelopes=await Promise.all([...this.content].map(([epoch,key])=>sealKey({workspaceId:this.workspaceId,kind:"content",epoch},peer.memberKeyId,peer.kemPublicKey,key)));
    if(actor.key.holdsAdmin){
      if(!this.admin)throw new Error("Workspace admin authority unavailable");
      envelopes.push(await sealKey({workspaceId:this.workspaceId,kind:"admin",epoch:policy.adminEpoch},peer.memberKeyId,peer.kemPublicKey,this.admin));
    }
    return this.signOperation({workspaceId:this.workspaceId,policyVersion:policy.policyVersion+1,prevOpHash:policy.headHash,kind:"link_key",issuedAt:Math.floor(Date.now()/1000),signerKeyId:this.member.memberKeyId,
      payload:{memberId:actor.member.memberId,generation:peer.generation,link,...(rotations.length?{rotations}:{}),envelopes},signature:ZERO_HASH,adminSignature:null});
  }
  private async replacementMaterial(policy:Policy,recipients:MemberKey[],replaceAdmin:boolean):Promise<RotationMaterial> {
    const epoch=policy.keyEpoch+1;uint(epoch,32,1);
    const content=randomBytes(32),admin=replaceAdmin?randomBytes(32):null;
    try {
      const envelopes=await Promise.all(recipients.flatMap(key=>[
        sealKey({workspaceId:this.workspaceId,kind:"content",epoch},key.memberKeyId,key.kemPublicKey,content),
        ...(admin&&key.holdsAdmin?[sealKey({workspaceId:this.workspaceId,kind:"admin",epoch},key.memberKeyId,key.kemPublicKey,admin)]:[]),
      ]));
      if(this.closed)throw new Error("Workspace keyring closed");
      return {newEpoch:epoch,newAdminPublicKey:admin?bytesToHex(ed25519.getPublicKey(admin)):null,envelopes};
    } finally {content.fill(0);admin?.fill(0);}
  }
  /** Revokes one login while retaining the member's other keys and authority. */
  async prepareRemoveKey(keyId:Hex,kind:"unlink_key"|"remove_key"="unlink_key"):Promise<PolicyOp|null> {
    if(this.closed||!this.verified)throw new Error("Workspace keyring unavailable");
    const policy=this.verified.policy,target=currentMemberKey(policy,keyId),actor=currentMemberKey(policy,this.member.memberKeyId)!;
    if(!target)return null;
    if(keyId===this.member.memberKeyId)throw new Error("Use a remaining sign-in to revoke this key");
    if(kind==="unlink_key"&&target.member.memberId!==actor.member.memberId)throw new Error("Unlink belongs to another member");
    if((kind==="remove_key"||target.key.holdsAdmin)&&!this.admin)throw new Error("Workspace admin authority unavailable");
    if(target.member.keys.filter(key=>key.removedAtVersion===null).length<2)throw new Error("Remove the member to revoke its last key");
    const recipients=policy.members.filter(member=>member.removedAtVersion===null).flatMap(member=>member.keys.filter(key=>key.removedAtVersion===null&&key.memberKeyId!==keyId));
    const rotation=await this.replacementMaterial(policy,recipients,target.key.holdsAdmin);
    return this.signOperation({workspaceId:this.workspaceId,policyVersion:policy.policyVersion+1,prevOpHash:policy.headHash,kind,issuedAt:Math.floor(Date.now()/1000),signerKeyId:this.member.memberKeyId,
      payload:{memberId:target.member.memberId,keyId,rotation},signature:ZERO_HASH,adminSignature:null});
  }
  /** Replaces this sign-in's generation and preserves its granted history. */
  async prepareMemberRotation(replacement:MemberKeys,registeredPointer?:SignedIdentityRotation):Promise<PolicyOp> {
    if(this.closed||!this.verified)throw new Error("Workspace keyring unavailable");
    const policy=this.verified.policy,actor=currentMemberKey(policy,this.member.memberKeyId)!;
    if(actor.key.holdsAdmin&&!this.admin)throw new Error("Workspace admin authority unavailable");
    const issuedAt=Math.floor(Date.now()/1000),pointer=registeredPointer?structuredClone(registeredPointer):createIdentityRotation(this.member,replacement,issuedAt);
    if(!verifyIdentityRotation(pointer)||pointer.oldKey!==this.member.memberKeyId||pointer.oldKem!==this.member.kemPublicKey||pointer.newKey!==replacement.memberKeyId||pointer.newKem!==replacement.kemPublicKey||pointer.generation!==replacement.generation||replacement.generation!==this.member.generation+1)throw new Error("Rotation pointer does not match replacement keys");
    const recipients=policy.members.filter(member=>member.removedAtVersion===null).flatMap(member=>member.keys.filter(key=>key.removedAtVersion===null&&key.memberKeyId!==this.member.memberKeyId));
    recipients.push({...actor.key,memberKeyId:replacement.memberKeyId,kemPublicKey:replacement.kemPublicKey,generation:replacement.generation,addedAtVersion:policy.policyVersion+1});
    const historical=policy.envelopes.filter(envelope=>envelope.recipientKeyId===this.member.memberKeyId&&envelope.kind==="content");
    const envelopes=await Promise.all(historical.map(envelope=>{
      const key=this.content.get(envelope.epoch);if(!key)throw new Error("Historical content key missing");
      return sealKey({workspaceId:this.workspaceId,kind:"content",epoch:envelope.epoch},replacement.memberKeyId,replacement.kemPublicKey,key);
    }));
    const rotation=await this.replacementMaterial(policy,recipients,actor.key.holdsAdmin);rotation.envelopes.push(...envelopes);
    return this.signOperation({workspaceId:this.workspaceId,policyVersion:policy.policyVersion+1,prevOpHash:policy.headHash,kind:"rotate_member",issuedAt,signerKeyId:this.member.memberKeyId,
      payload:{memberId:actor.member.memberId,pointer,rotation},signature:ZERO_HASH,adminSignature:null});
  }
  /** Signs an operation only when it validates against the last verified policy. */
  signOperation(op:PolicyOp):PolicyOp {
    if(this.closed||!this.verified)throw new Error("Workspace keyring unavailable");
    const policy=this.verified.policy;
    let needsAdmin=op.kind!=="link_key";
    if(op.kind==="unlink_key")needsAdmin=!!currentMemberKey(policy,op.payload.keyId)?.key.holdsAdmin;
    if(op.kind==="rotate_member")needsAdmin=!!currentMemberKey(policy,this.member.memberKeyId)?.key.holdsAdmin;
    if(needsAdmin&&!this.admin)throw new Error("Workspace admin authority unavailable");
    const signed=signPolicyOp(op,this.member,needsAdmin?this.admin:null);applyPolicyOp(policy,signed);return signed;
  }
}

export interface PersonalWorkspaces {primary:Hex;workspaceIds:Hex[]}
/** Separate pre-link personal histories remain accessible; the UI can sync all of them. */
export async function findOrCreatePersonalWorkspaces(client:WorkspaceClient,keys:MemberKeys):Promise<PersonalWorkspaces> {
  for(let attempt=0;attempt<3;attempt++){
    const discovery=await client.discover();
    if(discovery.rotations.length)throw new Error("Follow identity rotation pointers before selecting a personal workspace");
    const found:Hex[]=[];
    for(const id of discovery.workspaceIds){
      const {policy}=await client.policy(id);const member=currentMemberKey(policy,keys.memberKeyId);
      if(policy.personal&&member?.member.addedAtVersion===1)found.push(id);
    }
    if(found.length){found.sort();return{primary:found[0],workspaceIds:found};}
    const workspaceId=randomId();const content=randomBytes(32);const admin=randomBytes(32);
    try {
      const envelopes=await Promise.all([
        sealKey({workspaceId,kind:"content",epoch:1},keys.memberKeyId,keys.kemPublicKey,content),
        sealKey({workspaceId,kind:"admin",epoch:1},keys.memberKeyId,keys.kemPublicKey,admin),
      ]);
      const op:PolicyOp={workspaceId,policyVersion:1,prevOpHash:ZERO_HASH,kind:"create",issuedAt:Math.floor(Date.now()/1000),signerKeyId:keys.memberKeyId,
        payload:{memberId:randomId(),key:{memberKeyId:keys.memberKeyId,kemPublicKey:keys.kemPublicKey,generation:keys.generation},adminPublicKey:bytesToHex(ed25519.getPublicKey(admin)),personal:true,envelopes},
        signature:ZERO_HASH,adminSignature:null};
      await client.create(signPolicyOp(op,keys,admin));return{primary:workspaceId,workspaceIds:[workspaceId]};
    }catch(error){if(!(error instanceof ApiError&&error.statusCode===409)||attempt===2)throw error;}
    finally{content.fill(0);admin.fill(0);}
  }
  throw new Error("Personal workspace creation could not settle");
}
