import {sha256} from "@noble/hashes/sha2.js";
import {bytesToHex,type Hex} from "viem";
import {generatePrivateKey,privateKeyToAccount} from "viem/accounts";
import {ApiError} from "../errors.js";
import {request} from "../internal/request.js";
import {bytes,canonicalJson,randomId,uint,utf8,type Json} from "./encoding";
import {WorkspaceClient,workspaceApiBase,type PendingInvite,type PolicyResponse,type RecordRow} from "./client";
import {usdSnapshot} from "./history";
import {createIdentityRotation,verifyIdentityRotation,type SignedIdentityRotation} from "./identity";
import {createWorkspaceInvite,finalizePendingInvite,type InviteHistory} from "./invitations";
import {disposeMemberKeys,unlockMember,type MemberKeys,type UnlockSigner} from "./keys";
import {WorkspaceKeyring,createTeamWorkspace} from "./personal";
import {CAPS,SUPPORT_MEMBER_ID,currentMemberKey,currentMembers,type InitialKey,type Policy,type PolicyMember} from "./policy";
import {SUPPORT_RECORD_TYPES,type SupportRecordType} from "./records";

export {SUPPORT_MEMBER_ID};
/** The staff workspace keeps the support identity in one well-known record. */
export const SUPPORT_IDENTITY_RECORD_ID=bytesToHex(sha256(utf8("mirage-support-identity-v1")));
export const MAX_SUPPORT_MESSAGE_CHARS=8000;
export const MAX_SUPPORT_SUBJECT_CHARS=200;
const MAX_REPORT_BYTES=240*1024;

// ---------------------------------------------------------------------------
// Anonymous identity
// ---------------------------------------------------------------------------

/** A throwaway secp256k1 key that unlocks member keys and signs SIWE messages without a wallet. */
export interface AnonymousSigner extends UnlockSigner {
  address:Hex;
  privateKey:Hex;
  signMessage(message:string):Promise<Hex>;
}
export function anonymousSignerFromPrivateKey(privateKey:Hex):AnonymousSigner {
  bytes(privateKey,32);
  const account=privateKeyToAccount(privateKey);
  return {address:account.address,privateKey,signTypedData:data=>account.signTypedData(data),signMessage:message=>account.signMessage({message})};
}
export const createAnonymousSigner=():AnonymousSigner=>anonymousSignerFromPrivateKey(generatePrivateKey());

// ---------------------------------------------------------------------------
// Support key configuration
// ---------------------------------------------------------------------------

/** Generation-0 support keys, pinned in the consuming build. */
export interface SupportRoot {rootKeyId:Hex;rootKem:Hex}
export type SupportKey=InitialKey;
export interface SupportConfig {
  rootKeyId:Hex;
  rootKem:Hex;
  supportMemberId:Hex;
  staffWorkspaceId:Hex;
  rotations:SignedIdentityRotation[];
  current:SupportKey;
}
/** Follows the cross-signed rotation chain from the pinned root to its tip. */
export function verifySupportChain(root:SupportRoot,rotations:readonly SignedIdentityRotation[]):SupportKey {
  bytes(root.rootKeyId,32);bytes(root.rootKem,32);
  if(!Array.isArray(rotations)||rotations.length>64)throw new Error("Invalid support rotation chain");
  let memberKeyId=root.rootKeyId,kemPublicKey=root.rootKem,generation=0;
  const visited=new Set<Hex>([memberKeyId]);
  for(const pointer of rotations){
    if(!verifyIdentityRotation(pointer)||pointer.oldKey!==memberKeyId||pointer.oldKem!==kemPublicKey||pointer.generation!==generation+1||visited.has(pointer.newKey))throw new Error("Invalid support rotation chain");
    memberKeyId=pointer.newKey;kemPublicKey=pointer.newKem;generation=pointer.generation;visited.add(memberKeyId);
  }
  return {memberKeyId,kemPublicKey,generation};
}
/** The server cannot substitute a support key: everything is checked against the pinned root. */
export function verifySupportConfig(input:SupportConfig,root:SupportRoot,minGeneration=0):SupportConfig {
  const config=structuredClone(input);
  if(config===null||typeof config!=="object"||config.rootKeyId!==root.rootKeyId||config.rootKem!==root.rootKem)throw new Error("Support root does not match the pinned key");
  if(config.supportMemberId!==SUPPORT_MEMBER_ID)throw new Error("Invalid support member id");
  bytes(config.staffWorkspaceId,16);
  const current=verifySupportChain(root,config.rotations);
  if(canonicalJson(config.current as unknown as Json)!==canonicalJson(current as unknown as Json))throw new Error("Support key does not match its rotation chain");
  if(current.generation<minGeneration)throw new Error("Support rotation chain was rolled back");
  return {rootKeyId:root.rootKeyId,rootKem:root.rootKem,supportMemberId:SUPPORT_MEMBER_ID,staffWorkspaceId:config.staffWorkspaceId,rotations:config.rotations,current};
}
function fetchConfig(apiServer:string):Promise<SupportConfig> {
  return request<SupportConfig>(`${workspaceApiBase(apiServer)}/support/config`,{credentials:"omit",redirect:"error",signal:AbortSignal.timeout(20_000)});
}
/** Pass the highest generation seen before as `minGeneration` to refuse a truncated chain. */
export async function fetchSupportConfig(apiServer:string,root:SupportRoot,options:{minGeneration?:number}={}):Promise<SupportConfig> {
  return verifySupportConfig(await fetchConfig(apiServer),root,options.minGeneration);
}

// ---------------------------------------------------------------------------
// Record bodies
// ---------------------------------------------------------------------------

export const TICKET_CATEGORIES=["transaction","bug","feedback","other"] as const;
export type TicketCategory=typeof TICKET_CATEGORIES[number];
export type TicketStatus="open"|"closed";
export type SupportRole="user"|"support";
export const SUPPORT_REPORT_STEPS=["approve","deploy","execute","cancel","other"] as const;
export interface SupportTicketBody {
  version:1;kind:"support_ticket";subject:string;category:TicketCategory;status:TicketStatus;
  createdAt:string;closedAt?:string;closedBy?:SupportRole;reportIds:Hex[];
}
export interface SupportMessageBody {version:1;kind:"support_message";ticketId:Hex;text:string;sentAt:string;staffLabel?:string}
export interface SupportReportError {message:string;code?:string;step:typeof SUPPORT_REPORT_STEPS[number]}
export interface SupportReportInput {clientVersion:string;userAgent:string;error:SupportReportError;transaction:{[field:string]:Json}}
export interface SupportReportBody extends SupportReportInput {version:1;kind:"support_report";ticketId?:Hex;createdAt:string}
export interface SupportIdentityGeneration {generation:number;privateKey:Hex;address:Hex}
/** `pendingRotation` names the generation whose rollout to user workspaces is unfinished. */
export interface SupportIdentityBody {version:1;kind:"support_identity";generations:SupportIdentityGeneration[];pendingRotation?:number}
export interface SupportRosterBody {version:1;workspaceName?:string;memberLabels?:{[memberId:string]:string};invitationLabels?:{[grantId:string]:string}}
export interface SupportTombstone {version:1;kind:SupportRecordType;deleted:true}
export type SupportBody=SupportTicketBody|SupportMessageBody|SupportReportBody|SupportIdentityBody|SupportRosterBody;

function invalid(what:string):never {throw new Error(`Invalid ${what}`);}
function object(value:unknown,what:string,required:readonly string[],optional:readonly string[]=[]):{[key:string]:Json} {
  if(value===null||typeof value!=="object"||Array.isArray(value))invalid(what);
  const keys=Object.keys(value);
  if(required.some(key=>!keys.includes(key))||keys.some(key=>!required.includes(key)&&!optional.includes(key)))invalid(what);
  return value as {[key:string]:Json};
}
const text=(value:unknown,max:number,min=0):value is string=>typeof value==="string"&&value.length>=min&&value.length<=max;
const iso=(value:unknown):value is string=>{
  if(typeof value!=="string"||value.length>32)return false;
  const date=new Date(value);return Number.isFinite(date.getTime())&&date.toISOString()===value;
};
const id=(value:unknown,length:number):value is Hex=>{try{bytes(value as Hex,length);return true;}catch{return false;}};
const labels=(value:unknown):boolean=>value!==null&&typeof value==="object"&&!Array.isArray(value)&&Object.values(value).every(label=>text(label,100,1));

export function isSupportTombstone(value:Json):value is {version:1;kind:SupportRecordType;deleted:true} {
  return value!==null&&typeof value==="object"&&!Array.isArray(value)&&value.deleted===true;
}
export function supportTombstone(type:SupportRecordType):SupportTombstone {
  if(!SUPPORT_RECORD_TYPES.includes(type))invalid("support record type");
  return {version:1,kind:type,deleted:true};
}
export function parseSupportTicket(value:Json):SupportTicketBody {
  const v=object(value,"support ticket",["version","kind","subject","category","status","createdAt","reportIds"],["closedAt","closedBy"]);
  if(v.version!==1||v.kind!=="support_ticket"||!text(v.subject,MAX_SUPPORT_SUBJECT_CHARS,1)||!TICKET_CATEGORIES.includes(v.category as TicketCategory)||!iso(v.createdAt)||
    !Array.isArray(v.reportIds)||v.reportIds.length>100||!v.reportIds.every(report=>id(report,32))||new Set(v.reportIds).size!==v.reportIds.length)invalid("support ticket");
  const closed=v.status==="closed";
  if((!closed&&v.status!=="open")||closed!==iso(v.closedAt)||closed!==(v.closedBy==="user"||v.closedBy==="support")||(!closed&&(v.closedAt!==undefined||v.closedBy!==undefined)))invalid("support ticket");
  return v as unknown as SupportTicketBody;
}
export function parseSupportMessage(value:Json):SupportMessageBody {
  const v=object(value,"support message",["version","kind","ticketId","text","sentAt"],["staffLabel"]);
  if(v.version!==1||v.kind!=="support_message"||!id(v.ticketId,32)||!text(v.text,MAX_SUPPORT_MESSAGE_CHARS,1)||!iso(v.sentAt)||(v.staffLabel!==undefined&&!text(v.staffLabel,100,1)))invalid("support message");
  return v as unknown as SupportMessageBody;
}
function reportError(value:unknown):SupportReportError {
  const v=object(value,"support report error",["message","step"],["code"]);
  if(!text(v.message,4000)||!SUPPORT_REPORT_STEPS.includes(v.step as SupportReportError["step"])||(v.code!==undefined&&!text(v.code,200)))invalid("support report error");
  return v as unknown as SupportReportError;
}
export function parseSupportReport(value:Json):SupportReportBody {
  const v=object(value,"support report",["version","kind","createdAt","clientVersion","userAgent","error","transaction"],["ticketId"]);
  if(v.version!==1||v.kind!=="support_report"||!iso(v.createdAt)||!text(v.clientVersion,200)||!text(v.userAgent,1000)||(v.ticketId!==undefined&&!id(v.ticketId,32))||
    v.transaction===null||typeof v.transaction!=="object"||Array.isArray(v.transaction))invalid("support report");
  // Fields outside the allowlist are never surfaced, even when another client sent them.
  return {...(v as unknown as SupportReportBody),error:reportError(v.error),transaction:reportTransaction(v.transaction)};
}
export function parseSupportIdentity(value:Json):SupportIdentityBody {
  const v=object(value,"support identity",["version","kind","generations"],["pendingRotation"]);
  if(v.version!==1||v.kind!=="support_identity"||!Array.isArray(v.generations)||!v.generations.length||v.generations.length>65)invalid("support identity");
  v.generations.forEach((entry,index)=>{
    const g=object(entry,"support identity generation",["generation","privateKey","address"]);
    if(g.generation!==index||!id(g.privateKey,32)||!id(g.address,20))invalid("support identity generation");
  });
  if(v.pendingRotation!==undefined&&(v.generations.length<2||v.pendingRotation!==v.generations.length-1))invalid("support identity rotation marker");
  return v as unknown as SupportIdentityBody;
}
export function parseSupportRoster(value:Json):SupportRosterBody {
  const v=object(value,"support roster",["version"],["workspaceName","memberLabels","invitationLabels"]);
  if(v.version!==1||(v.workspaceName!==undefined&&!text(v.workspaceName,100))||(v.memberLabels!==undefined&&!labels(v.memberLabels))||(v.invitationLabels!==undefined&&!labels(v.invitationLabels)))invalid("support roster");
  return v as unknown as SupportRosterBody;
}
/** Validates a decrypted support record body. Tombstones are returned as such. */
export function parseSupportBody(type:SupportRecordType,value:Json):SupportBody|SupportTombstone {
  if(isSupportTombstone(value)){
    const v=object(value,"support tombstone",["version","kind","deleted"]);
    if(v.version!==1||v.kind!==type)invalid("support tombstone");
    return supportTombstone(type);
  }
  switch(type){
    case "support_ticket":return parseSupportTicket(value);
    case "support_message":return parseSupportMessage(value);
    case "support_report":return parseSupportReport(value);
    case "support_identity":return parseSupportIdentity(value);
    case "roster":return parseSupportRoster(value);
    default:return invalid("support record type");
  }
}

// ---------------------------------------------------------------------------
// Diagnostic reports
// ---------------------------------------------------------------------------

type ReportField="string"|"integer"|"boolean"|"usd"|"strings"|"stringMap"|"transfers"|"approval";
/** In-flight transfer secrets. Reports are the only upload path that carries them. */
export const SUPPORT_REPORT_SECRET_FIELDS=["seed","selectorMapping","blindingScalar","sealedPricingAuthorization"] as const;
/** Everything a report may carry from a local transaction record. Anything else is dropped. */
export const SUPPORT_REPORT_FIELDS:Readonly<Record<string,ReportField>>=Object.freeze({
  status:"string",chainId:"integer",date:"string",
  recipient:"string",recipientENS:"string",amount:"string",tokenAddress:"string",tokenSymbol:"string",tokenDecimals:"integer",transfers:"transfers",
  approveTxHash:"string",approveTxHashes:"strings",deployTxHash:"string",submitTxHash:"string",submitTxHashes:"strings",cancelTxHash:"string",
  escrowAddress:"string",escrowType:"string",nativeEth:"boolean",quoteCommitment:"string",senderAddress:"string",
  depositByAsset:"stringMap",msgValue:"string",
  seed:"string",selectorMapping:"stringMap",blindingScalar:"string",sealedPricingAuthorization:"string",
  totalFeeUsd:"usd",networkFeeUsd:"usd",tokenTotalUsd:"usd",transfersTotalUsd:"usd",
  serviceFeeAsset:"string",serviceFeeAmount:"string",rewardAsset:"string",sdkRewardAmount:"string",
  userApproveGas:"string",userDeployGas:"string",userGasPrice:"string",
  approval:"approval",signalSubmitted:"boolean",approveBroadcasted:"boolean",deployedAt:"integer",fromBlock:"string",
});
const TRANSFER_FIELDS:Readonly<Record<string,ReportField>>={recipient:"string",recipientENS:"string",amount:"string",tokenAddress:"string",decimals:"integer",symbol:"string"};
const APPROVAL_FIELDS:Readonly<Record<string,ReportField>>={version:"integer",chainId:"integer",escrowContract:"string",deploymentTxHash:"string",runtimeCodeHash:"string",quoteCommitment:"string",approvedAt:"integer",signature:"string"};
const MAX_FIELD_CHARS=128*1024;

function reportValue(kind:ReportField,value:unknown):Json|undefined {
  const string=(input:unknown):input is string=>typeof input==="string"&&input.length<=MAX_FIELD_CHARS;
  switch(kind){
    case "string":return string(value)?value:undefined;
    case "integer":return typeof value==="number"&&Number.isSafeInteger(value)&&!Object.is(value,-0)?value:undefined;
    case "boolean":return typeof value==="boolean"?value:undefined;
    case "usd":
      if(typeof value==="string")return /^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value)&&value.length<=64?value:undefined;
      try{return usdSnapshot(value as number);}catch{return undefined;}
    case "strings":return Array.isArray(value)&&value.length<=256&&value.every(string)?[...value]:undefined;
    case "stringMap":{
      if(value===null||typeof value!=="object"||Array.isArray(value))return undefined;
      const entries=Object.entries(value);
      return entries.length<=1024&&entries.every(([,entry])=>string(entry))?Object.fromEntries(entries):undefined;
    }
    case "transfers":return Array.isArray(value)&&value.length<=256?value.map(row=>pick(TRANSFER_FIELDS,row)):undefined;
    case "approval":return value!==null&&typeof value==="object"&&!Array.isArray(value)?pick(APPROVAL_FIELDS,value):undefined;
  }
}
function pick(allowed:Readonly<Record<string,ReportField>>,source:unknown):{[field:string]:Json} {
  const result:{[field:string]:Json}={};
  if(source===null||typeof source!=="object"||Array.isArray(source))return result;
  for(const [field,kind] of Object.entries(allowed)){
    if(!Object.hasOwn(source,field))continue;
    const value=reportValue(kind,(source as Record<string,unknown>)[field]);
    if(value!==undefined)result[field]=value;
  }
  return result;
}
/** Copies only allowlisted, well-typed fields. Unknown or malformed fields are dropped. */
export function reportTransaction(tx:unknown):{[field:string]:Json} {return pick(SUPPORT_REPORT_FIELDS,tx);}
/** USD snapshots become decimal strings because record bodies carry no fractional numbers. */
export function buildSupportReport(tx:Record<string,unknown>,error:SupportReportError,meta:{clientVersion:string;userAgent:string}):SupportReportInput {
  const failure:SupportReportError={message:String(error.message).slice(0,4000),step:SUPPORT_REPORT_STEPS.includes(error.step)?error.step:"other"};
  if(error.code!==undefined&&error.code!==null)failure.code=String(error.code).slice(0,200);
  return {clientVersion:String(meta.clientVersion).slice(0,200),userAgent:String(meta.userAgent).slice(0,1000),error:failure,transaction:reportTransaction(tx)};
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export interface SupportTicket {
  ticketId:Hex;revision:number;subject:string;category:TicketCategory;status:TicketStatus;
  createdAt:string;closedAt?:string;closedBy?:SupportRole;reportIds:Hex[];
  /** Server time of the latest revision. */
  updatedAt:string;
  /** Whether the latest revision was signed by the support member. */
  fromSupport:boolean;
}
export interface SupportMessage {messageId:Hex;ticketId:Hex;text:string;sentAt:string;fromSupport:boolean;staffLabel?:string;authorKeyId:Hex}
export interface SupportReport extends SupportReportInput {reportId:Hex;revision:number;ticketId?:Hex;createdAt:string;fromSupport:boolean}
interface Entry {type:SupportRecordType;recordId:Hex;revision:number;sequence:number;authorKeyId:Hex;updatedAt:string;body:SupportBody|null}

const conflict=(error:unknown)=>error instanceof ApiError&&[409,412].includes(error.statusCode);
const denied=(error:unknown)=>(error instanceof ApiError&&[401,403,404].includes(error.statusCode))||(error instanceof Error&&error.message==="Workspace membership revoked");
async function settle<T>(task:()=>Promise<T>):Promise<T> {
  for(let attempt=0;;attempt++){
    try{return await task();}catch(error){if(attempt===3||!conflict(error))throw error;}
  }
}
function requireSupportRealm(client:WorkspaceClient):void {
  if(client.realm!=="support")throw new Error("Support requires a support-realm workspace client");
}

/** One support workspace as seen by its user or by the support identity. */
export class SupportSession {
  readonly workspaceId:Hex;
  private readonly entries=new Map<Hex,Entry>();
  private policy:Policy;
  private cursor?:string;
  private grantedEpochs:number[]=[];
  constructor(private readonly client:WorkspaceClient,private readonly keys:MemberKeys,private readonly keyring:WorkspaceKeyring,
      readonly role:SupportRole,private readonly staffLabel?:string) {
    requireSupportRealm(client);
    if(keyring.realm!=="support")throw new Error("Support requires a support-realm keyring");
    this.workspaceId=keyring.workspaceId;this.policy=keyring.policySnapshot();
  }
  /** Drops this session's content keys. */
  close():void {this.keyring.close();this.entries.clear();}
  private async refresh():Promise<number[]> {
    const response=await this.client.policy(this.workspaceId);
    const epochs=[...(await this.keyring.load(response)).keys()].sort((a,b)=>a-b);
    this.policy=response.policy;return epochs;
  }
  /** Authorship comes from the signed policy log, never from record contents. */
  private supportMember():PolicyMember|undefined {
    const own=this.policy.members.find(member=>member.keys.some(key=>key.memberKeyId===this.keys.memberKeyId));
    if(this.role==="support")return own;
    const member=this.policy.members.find(candidate=>candidate.memberId===SUPPORT_MEMBER_ID);
    return member===own?undefined:member;
  }
  private fromSupport(authorKeyId:Hex):boolean {
    return !!this.supportMember()?.keys.some(key=>key.memberKeyId===authorKeyId);
  }
  /** Call after `refresh`: authors are checked against the keyring's verified policy. */
  private async read(row:RecordRow):Promise<SupportBody|null> {
    const type=row.record.type;
    if(!SUPPORT_RECORD_TYPES.includes(type as SupportRecordType))throw new Error("Unexpected record type in support workspace");
    const body=parseSupportBody(type as SupportRecordType,await this.keyring.decryptRecord(row.record));
    if("deleted" in body)return null;
    // Messages are immutable: their only later revision is a tombstone.
    if(type==="support_message"&&row.record.revision!==1)throw new Error("Support message was edited");
    return body;
  }
  private ingest(row:RecordRow,body:SupportBody|null):boolean {
    const {recordId,revision,authorKeyId}=row.record,previous=this.entries.get(recordId);
    if(previous&&previous.revision>revision)return false;
    this.entries.set(recordId,{type:row.record.type as SupportRecordType,recordId,revision,sequence:row.changeSequence,authorKeyId,updatedAt:row.updatedAt,body});
    return previous?.revision!==revision;
  }
  /** Pulls records changed since the last call and reports whether anything new arrived. */
  async sync():Promise<{changed:boolean}> {
    const granted=await this.refresh();
    // Newly granted epochs can make earlier, previously skipped ciphertext readable.
    if(granted.some(epoch=>!this.grantedEpochs.includes(epoch)))this.cursor=undefined;
    this.grantedEpochs=granted;
    let changed=false;
    for(let pages=0;pages<1000;pages++){
      const page=await this.client.records(this.workspaceId,this.cursor);
      // A concurrent policy update may have introduced authors or new epochs.
      if(page.records.length)this.grantedEpochs=await this.refresh();
      for(const row of page.records){
        if(!this.grantedEpochs.includes(row.record.keyEpoch))continue;
        // A malformed body hides that record only; it must not stall the conversation.
        let body:SupportBody|null=null;
        try{body=await this.read(row);}catch{body=null;}
        if(this.ingest(row,body))changed=true;
      }
      this.cursor=page.nextCursor;
      if(!page.hasMore)break;
    }
    return {changed};
  }
  private live<T extends SupportBody>(type:SupportRecordType):(Entry&{body:T})[] {
    return [...this.entries.values()].filter((entry):entry is Entry&{body:T}=>entry.type===type&&entry.body!==null).sort((a,b)=>a.sequence-b.sequence);
  }
  private ticket(entry:Entry&{body:SupportTicketBody}):SupportTicket {
    const {version:_,kind:__,...fields}=entry.body;
    return {ticketId:entry.recordId,revision:entry.revision,...fields,reportIds:[...fields.reportIds],updatedAt:entry.updatedAt,fromSupport:this.fromSupport(entry.authorKeyId)};
  }
  private message(entry:Entry&{body:SupportMessageBody}):SupportMessage {
    const fromSupport=this.fromSupport(entry.authorKeyId),{ticketId,text:content,sentAt,staffLabel}=entry.body;
    // Only the support member may attribute a message to a staffer.
    return {messageId:entry.recordId,ticketId,text:content,sentAt,fromSupport,...(fromSupport&&staffLabel?{staffLabel}:{}),authorKeyId:entry.authorKeyId};
  }
  private report(entry:Entry&{body:SupportReportBody}):SupportReport {
    const {version:_,kind:__,...fields}=entry.body;
    return {reportId:entry.recordId,revision:entry.revision,...structuredClone(fields),fromSupport:this.fromSupport(entry.authorKeyId)};
  }
  /** Most recently changed first. */
  tickets():SupportTicket[] {return this.live<SupportTicketBody>("support_ticket").reverse().map(entry=>this.ticket(entry));}
  /** Oldest first, in server order. */
  messages(ticketId:Hex):SupportMessage[] {
    return this.live<SupportMessageBody>("support_message").filter(entry=>entry.body.ticketId===ticketId).map(entry=>this.message(entry));
  }
  reports():SupportReport[] {return this.live<SupportReportBody>("support_report").reverse().map(entry=>this.report(entry));}
  private async write(type:SupportRecordType,body:SupportBody|SupportTombstone,recordId:Hex=randomId(32),previousRevision=0):Promise<Entry> {
    await this.refresh();
    const row=await this.client.put(await this.keyring.encryptRecord(type,body as unknown as Json,recordId,previousRevision+1),previousRevision);
    this.ingest(row,"deleted" in body?null:body);
    return this.entries.get(recordId)!;
  }
  private async latest(type:SupportRecordType,recordId:Hex):Promise<{row:RecordRow;body:SupportBody|null}> {
    bytes(recordId,32);
    const row=await this.client.record(this.workspaceId,recordId);
    if(row.record.type!==type)throw new Error("Support record has a different type");
    await this.refresh();
    return {row,body:await this.read(row)};
  }
  private reviseTicket(ticketId:Hex,change:(body:SupportTicketBody)=>SupportTicketBody|null):Promise<void> {
    return settle(async()=>{
      const {row,body}=await this.latest("support_ticket",ticketId);
      if(!body)throw new Error("Support ticket was deleted");
      const next=change(body as SupportTicketBody);
      if(next)await this.write("support_ticket",parseSupportTicket(next as unknown as Json),ticketId,row.record.revision);
      else this.ingest(row,body);
    });
  }
  async createTicket(input:{subject:string;category:TicketCategory;text:string;reportId?:Hex}):Promise<SupportTicket> {
    const now=new Date().toISOString();
    const ticket=parseSupportTicket({version:1,kind:"support_ticket",subject:input.subject,category:input.category,status:"open",createdAt:now,reportIds:input.reportId?[input.reportId]:[]});
    // Validate the first message before anything is written.
    parseSupportMessage({version:1,kind:"support_message",ticketId:randomId(32),text:input.text,sentAt:now});
    const entry=await this.write("support_ticket",ticket);
    await this.sendMessage(entry.recordId,input.text);
    return this.ticket(entry as Entry&{body:SupportTicketBody});
  }
  /** `staffLabel` is honoured for the support role only. */
  async sendMessage(ticketId:Hex,content:string,options:{staffLabel?:string}={}):Promise<SupportMessage> {
    const ticket=this.entries.get(ticketId);
    if(ticket?.type!=="support_ticket"||!ticket.body)throw new Error("Unknown support ticket");
    const label=this.role==="support"?options.staffLabel??this.staffLabel:undefined;
    const body=parseSupportMessage({version:1,kind:"support_message",ticketId,text:content,sentAt:new Date().toISOString(),...(label?{staffLabel:label}:{})});
    return this.message(await this.write("support_message",body) as Entry&{body:SupportMessageBody});
  }
  closeTicket(ticketId:Hex):Promise<void> {
    return this.reviseTicket(ticketId,body=>body.status==="closed"?null:{...body,status:"closed",closedAt:new Date().toISOString(),closedBy:this.role});
  }
  reopenTicket(ticketId:Hex):Promise<void> {
    return this.reviseTicket(ticketId,({closedAt:_,closedBy:__,...body})=>body.status==="open"?null:{...body,status:"open"});
  }
  /** Pass the output of `buildSupportReport`; the allowlist is applied again before sealing. */
  async submitReport(report:SupportReportInput,ticketId?:Hex):Promise<SupportReport> {
    if(ticketId!==undefined){
      const ticket=this.entries.get(ticketId);
      if(ticket?.type!=="support_ticket"||!ticket.body)throw new Error("Unknown support ticket");
    }
    const body=parseSupportReport({version:1,kind:"support_report",createdAt:new Date().toISOString(),clientVersion:report.clientVersion,userAgent:report.userAgent,
      error:report.error as unknown as Json,transaction:report.transaction,...(ticketId?{ticketId}:{})});
    if(utf8(canonicalJson(body as unknown as Json)).length>MAX_REPORT_BYTES)throw new Error("Support report is too large");
    const entry=await this.write("support_report",body);
    if(ticketId)await this.reviseTicket(ticketId,ticket=>ticket.reportIds.includes(entry.recordId)?null:{...ticket,reportIds:[...ticket.reportIds,entry.recordId]});
    return this.report(entry as Entry&{body:SupportReportBody});
  }
  /** Replaces the stored revision with a tombstone, erasing the content from the server. */
  deleteRecord(type:SupportRecordType,recordId:Hex):Promise<void> {
    return settle(async()=>{
      const {row,body}=await this.latest(type,recordId);
      if(body)await this.write(type,supportTombstone(type),recordId,row.record.revision);
      else this.ingest(row,null);
    });
  }
}

/** A support member whose keys all descend from the pinned root. */
function verifiedSupportMember(policy:Policy,config:SupportConfig):PolicyMember|undefined {
  const member=policy.members.find(candidate=>candidate.memberId===SUPPORT_MEMBER_ID);
  if(!member)return undefined;
  const chain=new Map<Hex,Hex>([[config.rootKeyId,config.rootKem],...config.rotations.map(pointer=>[pointer.newKey,pointer.newKem] as [Hex,Hex])]);
  if(member.caps!==CAPS.WRITE||member.keys.some(key=>key.holdsAdmin||chain.get(key.memberKeyId)!==key.kemPublicKey))throw new Error("Support member key is not in the verified rotation chain");
  if(member.removedAtVersion!==null)throw new Error("Support was removed from this workspace");
  return member;
}
/**
 * Finds the caller's support workspace or, with `create`, makes one and grants
 * the current support key access. Returns null when none exists and `create` is false.
 */
export async function openSupportWorkspace(opts:{client:WorkspaceClient;keys:MemberKeys;root:SupportRoot;create:boolean}):Promise<SupportSession|null> {
  const {client,keys,root}=opts;requireSupportRealm(client);
  let config=await fetchSupportConfig(client.apiServer,root);
  for(let attempt=0;attempt<4;attempt++){
    const discovery=await client.discover();
    if(discovery.rotations.length)throw new Error("Follow identity rotation pointers before opening support");
    let workspaceId:Hex|undefined;
    for(const candidate of [...discovery.workspaceIds].sort()){
      if(candidate===config.staffWorkspaceId)continue;
      const {policy}=await client.policy(candidate);
      if(currentMemberKey(policy,keys.memberKeyId)?.member.addedAtVersion===1){workspaceId=candidate;break;}
    }
    if(!workspaceId){
      if(!opts.create)return null;
      // One workspace per creator key: a concurrent creation is found on the next pass.
      try{workspaceId=await createTeamWorkspace(client,keys);}catch(error){if(attempt===3||!conflict(error))throw error;continue;}
    }
    const keyring=new WorkspaceKeyring(workspaceId,keys,"support");
    try{
      for(let grant=0;;grant++){
        const response=await client.policy(workspaceId);await keyring.load(response);
        if(verifiedSupportMember(response.policy,config))break;
        try{await keyring.load(await client.addSupportMember(await keyring.prepareAddSupportMember(config.current)));break;}
        catch(error){
          // A stale support generation or a concurrent grant: refetch the chain and look again.
          if(grant===3||!conflict(error))throw error;
          config=await fetchSupportConfig(client.apiServer,root,{minGeneration:config.current.generation});
        }
      }
      const session=new SupportSession(client,keys,keyring,"user");
      await session.sync();return session;
    }catch(error){keyring.close();throw error;}
  }
  throw new Error("Support workspace creation could not settle");
}

// ---------------------------------------------------------------------------
// Staff workspace
// ---------------------------------------------------------------------------

export interface SupportIdentity {
  /** One independent random key per generation, oldest first. */
  generations:SupportIdentityGeneration[];
  /** Generation-0 public keys: the values pinned by clients and set in API config. */
  root:SupportRoot;
  /** Public keys of the newest stored generation. */
  current:SupportKey;
  /** Generation whose rollout to user workspaces has not finished, if any. */
  pendingRotation:number|null;
  revision:number;
}
export interface StaffMember {memberId:Hex;caps:number;isOwner:boolean;self:boolean;label?:string}
/** Member keys of one support identity generation. The caller disposes them. */
export async function supportIdentityKeys(identity:Pick<SupportIdentity,"generations">,generation=identity.generations.length-1):Promise<MemberKeys> {
  const entry=identity.generations[generation];
  if(!entry||entry.generation!==generation)throw new Error("Unknown support identity generation");
  const signer=anonymousSignerFromPrivateKey(entry.privateKey);
  if(signer.address.toLowerCase()!==entry.address)throw new Error("Support identity address does not match its key");
  return unlockMember(signer,generation);
}
async function describeIdentity(body:SupportIdentityBody,revision:number):Promise<SupportIdentity> {
  const publicKey=async(generation:number):Promise<SupportKey>=>{
    const keys=await supportIdentityKeys(body,generation);
    try{return {memberKeyId:keys.memberKeyId,kemPublicKey:keys.kemPublicKey,generation};}finally{disposeMemberKeys(keys);}
  };
  const first=await publicKey(0),current=body.generations.length>1?await publicKey(body.generations.length-1):first;
  return {generations:structuredClone(body.generations),root:{rootKeyId:first.memberKeyId,rootKem:first.kemPublicKey},current,pendingRotation:body.pendingRotation??null,revision};
}
function identityGeneration(generation:number):SupportIdentityGeneration {
  const signer=createAnonymousSigner();
  return {generation,privateKey:signer.privateKey,address:signer.address.toLowerCase() as Hex};
}

/** The team workspace, in the support realm, that holds the support identity. */
export class StaffWorkspace {
  private policy:PolicyResponse;
  constructor(readonly client:WorkspaceClient,private readonly keys:MemberKeys,private readonly keyring:WorkspaceKeyring,policy:PolicyResponse) {
    requireSupportRealm(client);this.policy=policy;
  }
  get workspaceId():Hex {return this.keyring.workspaceId;}
  get memberId():Hex {return currentMemberKey(this.policy.policy,this.keys.memberKeyId)!.member.memberId;}
  get isOwner():boolean {return currentMemberKey(this.policy.policy,this.keys.memberKeyId)!.key.holdsAdmin;}
  close():void {this.keyring.close();}
  private async refresh():Promise<PolicyResponse> {
    const policy=await this.client.policy(this.workspaceId);
    await this.keyring.load(policy);this.policy=policy;return policy;
  }
  private async readIdentity():Promise<{body:SupportIdentityBody;revision:number}|null> {
    let row:RecordRow;
    try{row=await this.client.record(this.workspaceId,SUPPORT_IDENTITY_RECORD_ID);}
    catch(error){if(error instanceof ApiError&&error.statusCode===404)return null;throw error;}
    if(row.record.type!=="support_identity")throw new Error("Support identity record has a different type");
    const body=parseSupportBody("support_identity",await this.keyring.decryptRecord(row.record,await this.refresh()));
    if("deleted" in body)throw new Error("Support identity was deleted");
    return {body:body as SupportIdentityBody,revision:row.record.revision};
  }
  private async writeIdentity(body:SupportIdentityBody,previousRevision:number):Promise<SupportIdentity> {
    await this.refresh();
    const record=await this.keyring.encryptRecord("support_identity",parseSupportIdentity(body as unknown as Json) as unknown as Json,SUPPORT_IDENTITY_RECORD_ID,previousRevision+1);
    return describeIdentity(body,(await this.client.put(record,previousRevision)).record.revision);
  }
  /** Null before bootstrap. */
  async identity():Promise<SupportIdentity|null> {
    const stored=await this.readIdentity();
    return stored&&describeIdentity(stored.body,stored.revision);
  }
  /** Creates generation 0 once; later calls return the stored identity. `root` goes into API config and client builds. */
  bootstrapIdentity():Promise<SupportIdentity> {
    return settle(async()=>{
      const stored=await this.readIdentity();
      return stored?describeIdentity(stored.body,stored.revision):this.writeIdentity({version:1,kind:"support_identity",generations:[identityGeneration(0)]},0);
    });
  }
  /** Stores a fresh key for the next generation and marks its rollout as pending. Owner only. */
  beginRotation():Promise<SupportIdentity> {
    return settle(async()=>{
      const stored=await this.readIdentity();
      if(!stored)throw new Error("Support identity has not been bootstrapped");
      if(stored.body.pendingRotation!==undefined)return describeIdentity(stored.body,stored.revision);
      const generation=stored.body.generations.length;
      return this.writeIdentity({...stored.body,generations:[...stored.body.generations,identityGeneration(generation)],pendingRotation:generation},stored.revision);
    });
  }
  /** Clears the rollout marker once every user workspace has moved to `generation`. */
  finishRotation(generation:number):Promise<SupportIdentity> {
    return settle(async()=>{
      const stored=await this.readIdentity();
      if(!stored)throw new Error("Support identity has not been bootstrapped");
      if(stored.body.pendingRotation!==generation)return describeIdentity(stored.body,stored.revision);
      const {pendingRotation:_,...body}=stored.body;
      return this.writeIdentity(body,stored.revision);
    });
  }
  private async roster():Promise<{row?:RecordRow;body:SupportRosterBody}> {
    let cursor:string|undefined,latest:{row:RecordRow;body:SupportRosterBody}|undefined;
    for(let pages=0;pages<100;pages++){
      const page=await this.client.records(this.workspaceId,cursor,"roster"),policy=await this.refresh();
      for(const row of page.records){
        const body=parseSupportBody("roster",await this.keyring.decryptRecord(row.record,policy));
        if(!("deleted" in body))latest={row,body:body as SupportRosterBody};
      }
      cursor=page.nextCursor;
      if(!page.hasMore)break;
    }
    return latest??{body:{version:1,workspaceName:"Mirage Support"}};
  }
  private updateRoster(change:(body:SupportRosterBody)=>void):Promise<void> {
    return settle(async()=>{
      const {row,body}=await this.roster();change(body);
      await this.refresh();
      await this.client.put(await this.keyring.encryptRecord("roster",parseSupportRoster(body as unknown as Json) as unknown as Json,row?.record.recordId,(row?.record.revision??0)+1),row?.record.revision??0);
    });
  }
  /** Current staff, with roster labels. A member invited with a label keeps it until relabelled. */
  async members():Promise<StaffMember[]> {
    const {policy,ops}=await this.refresh(),{body}=await this.roster();
    const invited=new Map<Hex,Hex>();
    for(const op of ops)if(op.kind==="add_member")invited.set(op.payload.acceptance.memberId,op.payload.grant.grantId);
    return currentMembers(policy).map(member=>{
      const label=body.memberLabels?.[member.memberId]??body.invitationLabels?.[invited.get(member.memberId)??""];
      return {memberId:member.memberId,caps:member.caps,isOwner:member.keys.some(key=>key.removedAtVersion===null&&key.holdsAdmin),
        self:member.keys.some(key=>key.memberKeyId===this.keys.memberKeyId),...(label?{label}:{})};
    });
  }
  /** Owner only. The invitee joins with `acceptWorkspaceInvite` on a support-realm client. */
  async invite(options:{label?:string;owner?:boolean;history?:InviteHistory;expiresAt?:number}={}):Promise<{grantId:Hex;secret:Hex}> {
    await this.refresh();
    const {grantId,secret}=await createWorkspaceInvite({client:this.client,keyring:this.keyring,history:options.history??"all",
      holdsAdmin:options.owner??false,caps:options.owner?CAPS.ALL:CAPS.WRITE,expiresAt:options.expiresAt});
    const label=options.label;
    if(label)await this.updateRoster(body=>{body.invitationLabels={...body.invitationLabels,[grantId]:label};});
    return {grantId,secret};
  }
  pendingInvites():Promise<PendingInvite[]> {return this.client.pendingInvites(this.workspaceId);}
  async finalizeInvite(pending:PendingInvite):Promise<void> {
    await this.refresh();this.policy=await finalizePendingInvite(this.client,this.keyring,pending);
  }
  /** Owner only. Rotate the support key afterwards: the removed member knew it. */
  removeMember(memberId:Hex):Promise<void> {
    return settle(async()=>{
      await this.refresh();
      const policy=await this.client.append(await this.keyring.prepareRemoveMember(memberId));
      await this.keyring.load(policy);this.policy=policy;
    });
  }
  setLabel(memberId:Hex,label:string):Promise<void> {
    bytes(memberId,16);
    return this.updateRoster(body=>{body.memberLabels={...body.memberLabels,[memberId]:label};});
  }
}
/** Opens the staff workspace named by `workspaceId`, or else by the API's support config. */
export async function openStaffWorkspace(opts:{client:WorkspaceClient;keys:MemberKeys;workspaceId?:Hex}):Promise<StaffWorkspace> {
  requireSupportRealm(opts.client);
  const workspaceId=opts.workspaceId??(await fetchConfig(opts.client.apiServer)).staffWorkspaceId;
  bytes(workspaceId,16);
  const policy=await opts.client.policy(workspaceId),keyring=new WorkspaceKeyring(workspaceId,opts.keys,"support");
  try{await keyring.load(policy);}catch(error){keyring.close();throw error;}
  return new StaffWorkspace(opts.client,opts.keys,keyring,policy);
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

export interface AdminWorkspaceRow {
  workspaceId:Hex;changeSequence:number;recordCount:number;createdAt:string;updatedAt:string;awaitingSupport:boolean;blocked:boolean;
}
export interface AdminWorkspacePage {workspaces:AdminWorkspaceRow[];nextCursor:string;hasMore:boolean}
export interface SupportAdminOptions {
  apiServer:string;
  staff:StaffWorkspace;
  identity:SupportIdentity;
  /** SIWE sign-in for a support identity key; message construction lives in the app. The hash may omit its 0x prefix. */
  signIn:(signer:AnonymousSigner)=>Promise<{principalHash:string;token:string}>;
  /** Attached to every message sent through sessions this admin opens. */
  staffLabel?:string;
  /** How long a `signIn` result is reused. Defaults to five minutes. */
  signInTtlMs?:number;
  /** Wait between attempts when the API rate-limits a rotation batch. Defaults to 15 seconds. */
  retryDelayMs?:number;
}
interface IdentityAccess {keys:MemberKeys;client:WorkspaceClient}

/** Staff-side operations performed as the shared support identity. */
export class SupportAdmin {
  private identity:SupportIdentity;
  private readonly access=new Map<number,Promise<IdentityAccess>>();
  private readonly sessions=new Set<SupportSession>();
  constructor(private readonly options:SupportAdminOptions) {
    workspaceApiBase(options.apiServer);this.identity=structuredClone(options.identity);
  }
  /** Closes opened sessions and disposes the derived support keys. */
  close():void {
    for(const session of this.sessions)session.close();this.sessions.clear();
    for(const pending of this.access.values())pending.then(({keys,client})=>{client.close();disposeMemberKeys(keys);},()=>undefined);
    this.access.clear();
  }
  private use(generation:number):Promise<IdentityAccess> {
    let pending=this.access.get(generation);
    if(!pending){
      pending=(async()=>{
        const signer=anonymousSignerFromPrivateKey(this.identity.generations[generation].privateKey),keys=await supportIdentityKeys(this.identity,generation);
        const ttl=this.options.signInTtlMs??300_000;
        let signedIn=await this.options.signIn(signer),at=Date.now(),renewal:Promise<void>|null=null;
        const principalHash=(signedIn.principalHash.startsWith("0x")?signedIn.principalHash:`0x${signedIn.principalHash}`).toLowerCase() as Hex;
        const principalToken=async()=>{
          if(Date.now()-at>=ttl){
            renewal??=this.options.signIn(signer).then(next=>{
              if(next.principalHash!==signedIn.principalHash)throw new Error("Support sign-in changed principal");
              signedIn=next;at=Date.now();
            }).finally(()=>{renewal=null;});
            await renewal;
          }
          return signedIn.token;
        };
        return {keys,client:new WorkspaceClient({apiServer:this.options.apiServer,realm:"support",principalHash,principalToken,keys})};
      })();
      this.access.set(generation,pending);
      pending.catch(()=>{if(this.access.get(generation)===pending)this.access.delete(generation);});
    }
    return pending;
  }
  /** Index of user workspaces; `since` returns only those changed after that cursor. */
  async list(since?:string,limit?:number):Promise<AdminWorkspacePage> {
    const query=new URLSearchParams();
    if(since)query.set("since",since);
    if(limit!==undefined)query.set("limit",String(uint(limit,8,1)));
    const page=await this.options.staff.client.supportAdmin<AdminWorkspacePage>(this.options.staff.workspaceId,`/workspaces?${query}`);
    if(!Array.isArray(page.workspaces)||page.workspaces.length>200||typeof page.nextCursor!=="string"||typeof page.hasMore!=="boolean")throw new Error("Invalid support workspace index");
    for(const row of page.workspaces){
      bytes(row.workspaceId,16);uint(row.changeSequence);uint(row.recordCount);
      if(typeof row.awaitingSupport!=="boolean"||typeof row.blocked!=="boolean")throw new Error("Invalid support workspace index");
    }
    if(page.hasMore&&(!page.workspaces.length||page.nextCursor===since))throw new Error("Support workspace index did not advance");
    return page;
  }
  /** Opens a user workspace as the support member, newest identity generation first. */
  async open(workspaceId:Hex):Promise<SupportSession> {
    bytes(workspaceId,16);
    for(let generation=this.identity.generations.length-1;generation>=0;generation--){
      const {keys,client}=await this.use(generation);
      let policy:PolicyResponse;
      try{policy=await client.policy(workspaceId);}catch(error){if(denied(error))continue;throw error;}
      const keyring=new WorkspaceKeyring(workspaceId,keys,"support");
      try{
        await keyring.load(policy);
        const session=new SupportSession(client,keys,keyring,"support",this.options.staffLabel);
        await session.sync();this.sessions.add(session);return session;
      }catch(error){keyring.close();throw error;}
    }
    throw new Error("The support identity is not a member of this workspace");
  }
  private moderate(workspaceId:Hex,method:"POST"|"DELETE"):Promise<void> {
    bytes(workspaceId,16);
    return this.options.staff.client.supportAdmin<void>(this.options.staff.workspaceId,`/workspaces/${workspaceId}/block`,{method});
  }
  block(workspaceId:Hex):Promise<void> {return this.moderate(workspaceId,"POST");}
  unblock(workspaceId:Hex):Promise<void> {return this.moderate(workspaceId,"DELETE");}
  /** Cheap check, from the identity record alone, for an interrupted rotation. */
  async pendingRotation():Promise<{generation:number}|null> {
    const identity=await this.options.staff.identity();
    return identity&&identity.pendingRotation!==null?{generation:identity.pendingRotation}:null;
  }
  private async patient<T>(task:()=>Promise<T>):Promise<T> {
    for(let attempt=0;;attempt++){
      try{return await task();}catch(error){
        if(attempt===7||!(error instanceof ApiError)||error.statusCode!==429)throw error;
        await new Promise(resolve=>setTimeout(resolve,this.options.retryDelayMs??15_000));
      }
    }
  }
  /**
   * Replaces the support key everywhere. Safe to call again after an interruption:
   * the stored pending generation is reused and finished workspaces are skipped.
   * Rebuild this object from `staff.identity()` afterwards.
   */
  async rotateSupportKey(onProgress?:(done:number,total:number)=>void):Promise<void> {
    const {staff,apiServer}=this.options;
    this.identity=await staff.beginRotation();
    const target=this.identity.pendingRotation;
    if(target===null||target<1)throw new Error("Support rotation could not start");
    const previous=await this.use(target-1),next=await this.use(target);
    let config=await fetchSupportConfig(apiServer,this.identity.root);
    if(config.current.generation<target){
      if(config.current.memberKeyId!==previous.keys.memberKeyId)throw new Error("Stored support identity is behind the registered rotation chain");
      try{await previous.client.registerRotation(createIdentityRotation(previous.keys,next.keys,Math.floor(Date.now()/1000)));}
      catch(error){if(!conflict(error))throw error;}
      config=await fetchSupportConfig(apiServer,this.identity.root,{minGeneration:target});
    }
    const pointer=config.rotations[target-1];
    if(config.current.generation!==target||config.current.memberKeyId!==next.keys.memberKeyId||config.current.kemPublicKey!==next.keys.kemPublicKey||!pointer)
      throw new Error("A different support key is registered for this generation");
    const rows:AdminWorkspaceRow[]=[];
    for(let cursor:string|undefined,pages=0;pages<10_000;pages++){
      const page=await this.patient(()=>this.list(cursor,200));
      rows.push(...page.workspaces);cursor=page.nextCursor;
      if(!page.hasMore)break;
    }
    let done=0;onProgress?.(done,rows.length);
    for(const row of rows){
      await this.patient(()=>settle(async()=>{
        let policy:PolicyResponse;
        try{policy=await previous.client.policy(row.workspaceId);}catch(error){
          if(!denied(error))throw error;
          // Denial alone is not proof of rotation: confirm the replacement is the current key.
          try{await next.client.policy(row.workspaceId);}catch(inner){if(!denied(inner))throw inner;}
          return;
        }
        const keyring=new WorkspaceKeyring(row.workspaceId,previous.keys,"support");
        try{
          await keyring.load(policy);
          await previous.client.append(await keyring.prepareMemberRotation(next.keys,pointer));
        }finally{keyring.close();}
      }));
      onProgress?.(++done,rows.length);
    }
    this.identity=await staff.finishRotation(target);
  }
}
