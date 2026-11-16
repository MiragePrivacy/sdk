import type {Hex} from "viem";
import {ApiError} from "../errors.js";
import {canonicalJson,type Json} from "./encoding";
import {WorkspaceClient,type PolicyResponse,type RecordRow} from "./client";
import {HistoryConflictError,completedHistory,historyRecordId,mergeCompletedHistory,parseCompletedHistory,type CompletedHistory,type LocalHistoryRecord} from "./history";
import {openRecord,sealRecord} from "./records";
import {policyAuthorCheck} from "./policy";
import type {MemberKeys} from "./keys";

export interface SyncCheckpoint {cursor?:string;grantedEpochs:number[]}
export interface SyncedHistory {recordId:Hex;revision:number;body:CompletedHistory}
/** Both verified, allowlisted copies are retained for an explicit device-local decision. */
export class HistoryUploadConflict extends HistoryConflictError {
  constructor(readonly recordId:Hex,readonly local:CompletedHistory,readonly remote:CompletedHistory) {
    super("Completed history differs from the synced copy");
  }
}
/** Commit decrypted history and its cursor atomically; namespace by API, workspace and member key. */
export interface HistorySyncStore {
  checkpoint():Promise<SyncCheckpoint>;
  commit(records:SyncedHistory[],checkpoint:SyncCheckpoint):Promise<void>;
}
export interface HistorySyncOptions {
  client:WorkspaceClient;
  workspaceId:Hex;
  memberKeys:MemberKeys;
  /** Authenticate envelopes against this policy before returning memory-only content keys. */
  loadKeys:(policy:PolicyResponse)=>Promise<ReadonlyMap<number,Uint8Array>>;
}
/** Completed-history uploads only. Durable enqueue/retry is supplied by the frontend outbox. */
export class HistorySync {
  constructor(private readonly options:HistorySyncOptions){}
  private async open(row:RecordRow,policy:PolicyResponse,keys:ReadonlyMap<number,Uint8Array>):Promise<CompletedHistory> {
    if(row.record.type!=="execution_event")throw new Error("History record has a different type");
    const key=keys.get(row.record.keyEpoch);if(!key)throw new Error("History epoch is not granted");
    const body=parseCompletedHistory(await openRecord(row.record,key,policyAuthorCheck(policy.ops)));
    if(historyRecordId(body.chainId,body.deployTxHash)!==row.record.recordId)throw new Error("History import ID does not match deployment");
    return body;
  }
  async importLocal(record:LocalHistoryRecord):Promise<RecordRow|null> {
    const body=completedHistory(record);return body?this.upload(body):null;
  }
  async upload(input:CompletedHistory):Promise<RecordRow> {
    const original=parseCompletedHistory(input as unknown as Json);
    const id=historyRecordId(original.chainId,original.deployTxHash);
    const {client,workspaceId,memberKeys}=this.options;
    for(let attempt=0;attempt<4;attempt++) {
      try {
        let existing:RecordRow|undefined;
        try{existing=await client.record(workspaceId,id);}catch(error){if(!(error instanceof ApiError&&error.statusCode===404))throw error;}
        const policy=await client.policy(workspaceId);const keys=await this.options.loadKeys(policy);
        const currentKey=keys.get(policy.policy.keyEpoch);if(!currentKey)throw new Error("Current workspace content key unavailable");
        let body=original;
        if(existing) {
          const remote=await this.open(existing,policy,keys);
          try{body=mergeCompletedHistory(remote,original);}catch(error){
            if(error instanceof HistoryConflictError)throw new HistoryUploadConflict(id,original,remote);
            throw error;
          }
          if(canonicalJson(remote as unknown as Json)===canonicalJson(body as unknown as Json))return existing;
        }
        const encrypted=await sealRecord({workspaceId,recordId:id,type:"execution_event",revision:(existing?.record.revision??0)+1,
          keyEpoch:policy.policy.keyEpoch,authorPolicyVersion:policy.policy.policyVersion,authorKeyId:memberKeys.memberKeyId},body as unknown as Json,currentKey,memberKeys.signingSeed);
        return await client.put(encrypted,existing?.record.revision??0);
      } catch(error) {
        if(attempt===3||!(error instanceof ApiError)||![409,412].includes(error.statusCode))throw error;
      }
    }
    throw new Error("History update could not settle");
  }
  async pull(store:HistorySyncStore):Promise<void> {
    const {client,workspaceId}=this.options;
    const policy=await client.policy(workspaceId);const keys=await this.options.loadKeys(policy);
    const grantedEpochs=[...keys.keys()].sort((a,b)=>a-b);const saved=await store.checkpoint();
    // Newly granted history must be visited even if earlier ciphertext was skipped.
    let cursor=grantedEpochs.some(epoch=>!saved.grantedEpochs.includes(epoch))?undefined:saved.cursor;
    for(let pageCount=0;pageCount<1000;pageCount++) {
      const page=await client.records(workspaceId,cursor,"execution_event");
      // A concurrent policy update may have introduced authors or new epochs.
      const current=await client.policy(workspaceId);const currentKeys=await this.options.loadKeys(current);
      const records:SyncedHistory[]=[];
      for(const row of page.records) {
        if(!currentKeys.has(row.record.keyEpoch))continue;
        records.push({recordId:row.record.recordId,revision:row.record.revision,body:await this.open(row,current,currentKeys)});
      }
      await store.commit(records,{cursor:page.nextCursor,grantedEpochs});cursor=page.nextCursor;
      if(!page.hasMore)return;
    }
    // The committed cursor lets the next polling cycle continue large histories.
  }
}
