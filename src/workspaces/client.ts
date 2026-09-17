import type {Hex} from "viem";
import {request} from "../internal/request.js";
import {ApiError} from "../errors.js";
import {bytes,canonicalJson,uint,type Json} from "./encoding";
import {signWorkspaceChallenge,type WorkspaceChallenge} from "./challenge";
import type {MemberKeys} from "./keys";
import {applyPolicyOp,currentMemberKey,policyAuthorCheck,policyOpHash,replayPolicy,type InviteAcceptance,type InviteGrant,type Policy,type PolicyOp} from "./policy";
import {verifyRecord,type EncryptedRecord,type RecordType} from "./records";
import {verifyIdentityLink,verifyIdentityRotation,linkedKeyBranches,linkHash,createIdentityUnlink,type IdentityLinkState,type SignedIdentityLink,type SignedIdentityRotation} from "./identity";
import type {KeyEnvelope} from "./hpke";

export interface WorkspaceClientOptions {
  apiServer:string;
  principalHash:Hex;
  principalToken:()=>Promise<string>|string;
  keys:MemberKeys;
}
export interface WorkspaceSession {token:string;workspaceId:Hex;memberKeyId:Hex;caps:number;policyVersion:number;expiresAt:number}
export interface PolicyResponse {policy:Policy;ops:PolicyOp[]}
export interface RecordRow {record:EncryptedRecord;changeSequence:number;createdAt:string;updatedAt:string}
export interface RecordPage {records:RecordRow[];nextCursor:string;hasMore:boolean}
export interface Discovery {workspaceIds:Hex[];rotations:SignedIdentityRotation[];links?:IdentityLinkState[]}
export interface InviteCiphertext {nonce:Hex;ciphertext:Hex}
export interface InviteBundle {grant:InviteGrant;ciphertext:InviteCiphertext;policy:PolicyResponse}
export interface PendingInvite {grant:InviteGrant;acceptance:InviteAcceptance}
const same=(a:unknown,b:unknown)=>canonicalJson(a as Json)===canonicalJson(b as Json);

/** Per-sign-in client. Tokens, policy pins and keys are never persisted here. */
export class WorkspaceClient {
  private readonly base:string;
  private readonly stop=new AbortController();
  private readonly sessions=new Map<Hex,Promise<WorkspaceSession>>();
  private readonly policies=new Map<Hex,PolicyResponse>();
  constructor(private readonly options:WorkspaceClientOptions) {
    this.options={...options,keys:{...options.keys}};
    const url=new URL(options.apiServer);
    if(!["http:","https:"].includes(url.protocol)||url.username||url.password||url.search||url.hash)throw new Error("Invalid workspace API URL");
    this.base=url.toString().replace(/\/$/,"");bytes(options.principalHash,32);
  }
  /** Abort pending work before the caller disposes its private member keys. */
  close():void {this.stop.abort();this.sessions.clear();this.policies.clear();}
  private async fetch<T>(path:string,token:string,init:RequestInit={}):Promise<T> {
    this.stop.signal.throwIfAborted();
    const timeout=new AbortController();const timer=setTimeout(()=>timeout.abort(),20_000);
    try {
      const result=await request<T>(`${this.base}${path}`,{...init,credentials:"omit",cache:"no-store",redirect:"error",
        headers:{"Content-Type":"application/json",...init.headers,Authorization:`Bearer ${token}`},
        signal:AbortSignal.any([this.stop.signal,timeout.signal,...(init.signal?[init.signal]:[])])});
      this.stop.signal.throwIfAborted();return result;
    } finally {clearTimeout(timer);}
  }
  private async principal<T>(path:string,init:RequestInit={}):Promise<T> {
    const token=await this.options.principalToken();return this.fetch<T>(path,token,init);
  }
  /** Cross-signatures authorize the link; both independent sign-ins gate abuse. */
  async registerLink(input:SignedIdentityLink,other:WorkspaceClient):Promise<SignedIdentityLink> {
    const link=structuredClone(input);
    if(this.base!==other.base||this.options.principalHash===other.options.principalHash)throw new Error("Link requires independent sign-ins on the same API");
    if(!verifyIdentityLink(link))throw new Error("Invalid identity link signatures");
    const members=[this.options.keys,other.options.keys];
    if(!members.some(k=>k.memberKeyId===link.keyA&&k.kemPublicKey===link.kemA)||!members.some(k=>k.memberKeyId===link.keyB&&k.kemPublicKey===link.kemB))throw new Error("Identity link does not match sign-in keys");
    this.stop.signal.throwIfAborted();other.stop.signal.throwIfAborted();
    const token=await other.options.principalToken();
    other.stop.signal.throwIfAborted();
    const registered=await this.principal<SignedIdentityLink>("/identity/links",{method:"POST",body:JSON.stringify(link),signal:other.stop.signal,headers:{"X-Mirage-Link-Authorization":`Bearer ${token}`}});
    other.stop.signal.throwIfAborted();
    if(!same(link,registered))throw new Error("Server returned a different identity link");
    return registered;
  }
  /** A pointer advertises a replacement; only a policy operation grants access. */
  async registerRotation(input:SignedIdentityRotation):Promise<SignedIdentityRotation> {
    const pointer=structuredClone(input);this.verifyRotations([pointer]);
    const registered=await this.principal<SignedIdentityRotation>("/identity/rotations",{method:"POST",body:JSON.stringify(pointer)});
    if(!same(pointer,registered))throw new Error("Server returned a different identity rotation");
    return registered;
  }
  private verifyRotations(pointers:SignedIdentityRotation[]):void {
    if(!Array.isArray(pointers)||pointers.length>64)throw new Error("Invalid identity rotation chain");
    let {memberKeyId:key,kemPublicKey:kem,generation}=this.options.keys;
    const visited=new Set<Hex>([key]);
    for(const pointer of pointers){
      if(!verifyIdentityRotation(pointer)||pointer.oldKey!==key||pointer.oldKem!==kem||pointer.generation!==generation+1||visited.has(pointer.newKey))throw new Error("Invalid identity rotation chain");
      key=pointer.newKey;kem=pointer.newKem;generation=pointer.generation;visited.add(key);
    }
  }
  async rotations():Promise<SignedIdentityRotation[]> {
    const key=this.options.keys.memberKeyId;
    const challenge=await this.principal<WorkspaceChallenge>(`/identity/challenge?member=${key}`);
    const signature=signWorkspaceChallenge(challenge,this.options.keys,{purpose:"discovery",workspaceId:null,principalHash:this.options.principalHash});
    const pointers=await this.principal<SignedIdentityRotation[]>(`/identity/rotations?member=${key}&nonce=${challenge.nonce}&signature=${signature}`);
    this.verifyRotations(pointers);return pointers;
  }
  private verifyLinkState(state:IdentityLinkState):void {
    const branches=linkedKeyBranches(state);
    if(!branches.some(branch=>branch.get(this.options.keys.memberKeyId)===this.options.keys.kemPublicKey))throw new Error("Link state does not match sign-in key");
  }
  async links():Promise<IdentityLinkState[]> {
    const key=this.options.keys.memberKeyId;
    const challenge=await this.principal<WorkspaceChallenge>(`/identity/challenge?member=${key}`);
    const signature=signWorkspaceChallenge(challenge,this.options.keys,{purpose:"discovery",workspaceId:null,principalHash:this.options.principalHash});
    const links=await this.principal<IdentityLinkState[]>(`/identity/links?member=${key}&nonce=${challenge.nonce}&signature=${signature}`);
    if(!Array.isArray(links)||links.length>1)throw new Error("Invalid identity links response");
    for(const link of links)this.verifyLinkState(link);return links;
  }
  async deleteLink(input:IdentityLinkState,revokedKey:Hex):Promise<void> {
    const state=structuredClone(input);this.verifyLinkState(state);
    const branches=linkedKeyBranches(state);
    if(!branches.some(branch=>branch.has(revokedKey)&&!branch.has(this.options.keys.memberKeyId)))throw new Error("Unlink must remove the other sign-in branch");
    const unlink=createIdentityUnlink(linkHash(state.link),revokedKey,this.options.keys,Math.floor(Date.now()/1000));
    await this.principal<void>("/identity/links",{method:"DELETE",body:JSON.stringify(unlink)});
  }
  async discover():Promise<Discovery> {
    const key=this.options.keys.memberKeyId;
    const challenge=await this.principal<WorkspaceChallenge>(`/identity/challenge?member=${key}`);
    const signature=signWorkspaceChallenge(challenge,this.options.keys,{purpose:"discovery",workspaceId:null,principalHash:this.options.principalHash});
    const result=await this.principal<Discovery>(`/workspaces?member=${key}&nonce=${challenge.nonce}&signature=${signature}`);
    if(!Array.isArray(result.workspaceIds)||!Array.isArray(result.rotations)||result.rotations.length>64)throw new Error("Invalid workspace discovery response");
    for(const workspace of result.workspaceIds)bytes(workspace,16);
    this.verifyRotations(result.rotations);
    if(result.links!==undefined){if(!Array.isArray(result.links)||result.links.length>1)throw new Error("Invalid identity links response");for(const link of result.links)this.verifyLinkState(link);}
    return result;
  }
  private async mint(workspace:Hex):Promise<WorkspaceSession> {
    const member=this.options.keys.memberKeyId;
    const challenge=await this.principal<WorkspaceChallenge>(`/workspaces/${workspace}/challenge?member=${member}`);
    const signature=signWorkspaceChallenge(challenge,this.options.keys,{purpose:"session",workspaceId:workspace,principalHash:this.options.principalHash});
    const session=await this.principal<WorkspaceSession>(`/workspaces/${workspace}/sessions`,{method:"POST",body:JSON.stringify({memberKeyId:member,nonce:challenge.nonce,signature})});
    const now=Math.floor(Date.now()/1000);
    uint(session.expiresAt,53,1);uint(session.caps,4);uint(session.policyVersion,53,1);
    if(session.workspaceId!==workspace||session.memberKeyId!==member||typeof session.token!=="string"||!/^mirage_ws_[A-Za-z0-9_-]{43}$/.test(session.token)||session.expiresAt<=now||session.expiresAt>now+3630)
      throw new Error("Invalid workspace session response");
    return session;
  }
  private async session(workspace:Hex):Promise<WorkspaceSession> {
    bytes(workspace,16);this.stop.signal.throwIfAborted();
    const pending=this.sessions.get(workspace);
    if(pending) {
      const session=await pending;
      if(session.expiresAt>Math.floor(Date.now()/1000)+30)return session;
      if(this.sessions.get(workspace)===pending)this.sessions.delete(workspace);
      return this.session(workspace);
    }
    const minted=this.mint(workspace);this.sessions.set(workspace,minted);
    try{return await minted;}catch(error){if(this.sessions.get(workspace)===minted)this.sessions.delete(workspace);throw error;}
  }
  private async workspace<T>(workspace:Hex,path:string,init:RequestInit={}):Promise<T> {
    const session=await this.session(workspace);
    try{return await this.fetch<T>(`/workspaces/${workspace}${path}`,session.token,init);}
    catch(error){if(error instanceof ApiError&&error.statusCode===401)this.sessions.delete(workspace);throw error;}
  }
  private pin(workspace:Hex,response:PolicyResponse,allowRevoked=false):PolicyResponse {
    const derived=replayPolicy(response.ops);
    if(derived.workspaceId!==workspace||!same(derived,response.policy))throw new Error("Server policy does not match signed log");
    const previous=this.policies.get(workspace);
    if(previous&&(derived.policyVersion<previous.policy.policyVersion||policyOpHash(response.ops[previous.policy.policyVersion-1])!==previous.policy.headHash))
      throw new Error("Workspace policy rollback or fork");
    if(!currentMemberKey(derived,this.options.keys.memberKeyId)){
      this.sessions.delete(workspace);
      if(!allowRevoked)throw new Error("Workspace membership revoked");
    }
    const verified={policy:derived,ops:structuredClone(response.ops)};
    this.policies.set(workspace,verified);return structuredClone(verified);
  }
  async create(op:PolicyOp):Promise<PolicyResponse> {
    const expected=applyPolicyOp(null,op);
    const actual=await this.principal<Policy>("/workspaces",{method:"POST",body:JSON.stringify(op)});
    if(!same(actual,expected))throw new Error("Invalid workspace creation response");
    return this.pin(op.workspaceId,{policy:actual,ops:[op]});
  }
  async policy(workspace:Hex):Promise<PolicyResponse> {
    return this.pin(workspace,await this.workspace<PolicyResponse>(workspace,"/policy"));
  }
  async append(op:PolicyOp):Promise<PolicyResponse> {
    const previous=await this.policy(op.workspaceId);
    if(op.prevOpHash!==previous.policy.headHash||op.policyVersion!==previous.policy.policyVersion+1)throw new ApiError(409,"Workspace policy changed");
    const expected=applyPolicyOp(previous.policy,op);
    const policy=await this.workspace<Policy>(op.workspaceId,"/policy/ops",{method:"POST",body:JSON.stringify(op)});
    if(!same(policy,expected))throw new Error("Invalid policy update response");
    // A successful self-replacement returns the exact signed state that revokes
    // this client. Accept that acknowledgement and discard its cached session.
    return this.pin(op.workspaceId,{policy,ops:[...previous.ops,op]},true);
  }
  async createInvite(workspace:Hex,grant:InviteGrant,ciphertext:InviteCiphertext,policyOp?:PolicyOp):Promise<InviteBundle> {
    const bundle=await this.workspace<InviteBundle>(workspace,"/invites",{method:"POST",body:JSON.stringify({grant,ciphertext,...(policyOp?{policyOp}:{})})});
    this.verifyInviteBundle(bundle,grant.grantId);return bundle;
  }
  async invite(grantId:Hex):Promise<InviteBundle> {
    bytes(grantId,16);const bundle=await this.principal<InviteBundle>(`/invites/${grantId}`);
    this.verifyInviteBundle(bundle,grantId);return bundle;
  }
  async acceptInvite(grantId:Hex,op:PolicyOp):Promise<PolicyResponse> {
    bytes(grantId,16);const bundle=await this.invite(grantId);
    if(op.workspaceId!==bundle.grant.workspaceId||op.kind!=="add_member")throw new Error("Invalid invite acceptance operation");
    const expected=applyPolicyOp(bundle.policy.policy,op);
    const actual=await this.principal<Policy>(`/invites/${grantId}/accept`,{method:"POST",body:JSON.stringify(op)});
    if(!same(actual,expected))throw new Error("Invalid invite acceptance response");
    return this.pin(op.workspaceId,{policy:actual,ops:[...bundle.policy.ops,op]});
  }
  async submitPendingInvite(grantId:Hex,acceptance:InviteAcceptance):Promise<void> {
    bytes(grantId,16);const result=await this.principal<{status:string}>(`/invites/${grantId}/accept`,{method:"POST",body:JSON.stringify(acceptance)});
    if(result.status!=="pending")throw new Error("Invalid pending invite response");
  }
  async pendingInvites(workspace:Hex):Promise<PendingInvite[]> {
    const values=await this.workspace<PendingInvite[]>(workspace,"/invites");
    if(!Array.isArray(values))throw new Error("Invalid pending invites response");return values;
  }
  async finalizeInvite(grantId:Hex,op:PolicyOp):Promise<PolicyResponse> {
    bytes(grantId,16);const previous=await this.policy(op.workspaceId),expected=applyPolicyOp(previous.policy,op);
    const actual=await this.workspace<Policy>(op.workspaceId,`/invites/${grantId}/finalize`,{method:"POST",body:JSON.stringify(op)});
    if(!same(actual,expected))throw new Error("Invalid invite finalization response");
    return this.pin(op.workspaceId,{policy:actual,ops:[...previous.ops,op]});
  }
  private verifyInviteBundle(bundle:InviteBundle,grantId:Hex):void {
    const policy=replayPolicy(bundle.policy.ops);
    if(!same(policy,bundle.policy.policy)||bundle.grant.grantId!==grantId||bundle.grant.workspaceId!==policy.workspaceId)throw new Error("Invalid invite bundle");
    bytes(bundle.ciphertext.nonce,12);bytes(bundle.ciphertext.ciphertext);
  }
  async envelopes(workspace:Hex):Promise<KeyEnvelope[]> {
    const verified=await this.policy(workspace);
    const envelopes=await this.workspace<KeyEnvelope[]>(workspace,"/envelopes");
    if(!Array.isArray(envelopes))throw new Error("Invalid envelope response");
    const expected=verified.policy.envelopes.filter(e=>e.recipientKeyId===this.options.keys.memberKeyId);
    if(envelopes.length!==expected.length||envelopes.some(e=>!expected.some(v=>same(v,e))))throw new Error("Envelopes do not match signed policy");
    if(new Set(envelopes.map(e=>`${e.kind}:${e.epoch}`)).size!==envelopes.length)throw new Error("Duplicate envelope response");
    return envelopes;
  }
  private verifyRow(workspace:Hex,row:RecordRow,policy:PolicyResponse,recordId?:Hex):void {
    uint(row.changeSequence,53,1);
    if(row.record.workspaceId!==workspace||(recordId!==undefined&&row.record.recordId!==recordId)||!verifyRecord(row.record,policyAuthorCheck(policy.ops)))
      throw new Error("Invalid workspace record or author policy");
  }
  async record(workspace:Hex,id:Hex):Promise<RecordRow> {
    bytes(id,32);let policy=await this.policy(workspace);
    const row=await this.workspace<RecordRow>(workspace,`/records/${id}`);
    if(row.record.authorPolicyVersion>policy.policy.policyVersion)policy=await this.policy(workspace);
    this.verifyRow(workspace,row,policy,id);return row;
  }
  async records(workspace:Hex,since?:string,type?:RecordType):Promise<RecordPage> {
    let policy=await this.policy(workspace);const query=new URLSearchParams();
    if(since)query.set("since",since);if(type)query.set("type",type);
    const page=await this.workspace<RecordPage>(workspace,`/records?${query}`);
    if(!Array.isArray(page.records)||page.records.length>100||typeof page.nextCursor!=="string"||page.nextCursor.length>512||typeof page.hasMore!=="boolean")throw new Error("Invalid workspace record page");
    if(page.records.some(row=>row.record.authorPolicyVersion>policy.policy.policyVersion))policy=await this.policy(workspace);
    let last=0;const seen=new Set<string>();
    for(const row of page.records){this.verifyRow(workspace,row,policy);if(row.changeSequence<=last||seen.has(row.record.recordId)||(type&&row.record.type!==type))throw new Error("Invalid sync ordering or type");last=row.changeSequence;seen.add(row.record.recordId);}
    if(page.hasMore&&(!page.records.length||page.nextCursor===since))throw new Error("Workspace sync did not advance");
    return page;
  }
  async put(record:EncryptedRecord,previousRevision:number):Promise<RecordRow> {
    uint(previousRevision);const policy=await this.policy(record.workspaceId);
    if(record.authorKeyId!==this.options.keys.memberKeyId||!verifyRecord(record,policyAuthorCheck(policy.ops)))throw new Error("Invalid record write authority");
    const row=await this.workspace<RecordRow>(record.workspaceId,`/records/${record.recordId}`,{method:"PUT",headers:{"If-Match":String(previousRevision)},body:JSON.stringify(record)});
    this.verifyRow(record.workspaceId,row,policy,record.recordId);
    if(!same(row.record,record))throw new Error("Record write returned a different revision");return row;
  }
}
