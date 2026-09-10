import {describe,it,expect,vi} from "vitest";
import type {Hex} from "viem";
import vectors from "./fixtures/workspaces.json";
import {ApiError} from "../src/errors";
import {HistorySync,HistoryUploadConflict,type SyncCheckpoint} from "../src/workspaces/sync";
import {completedHistory,historyRecordId,type CompletedHistory} from "../src/workspaces/history";
import {deriveMemberKeys} from "../src/workspaces/keys";
import {sealRecord,type EncryptedRecord} from "../src/workspaces/records";
import type {WorkspaceClient,RecordRow,PolicyResponse} from "../src/workspaces/client";
import type {Json} from "../src/workspaces/encoding";

const local=()=>({status:"success",chainId:31337,date:"2026-09-10T12:00:00Z",deployTxHash:`0x${"aa".repeat(32)}`,submitTxHash:`0x${"bb".repeat(32)}`,recipient:`0x${"cc".repeat(20)}`,amount:"1",tokenAddress:`0x${"dd".repeat(20)}`,tokenSymbol:"TEST",tokenDecimals:18});
function setup(){
  const keys=deriveMemberKeys(vectors.unlock[0].signature as Hex);
  const policy={policy:vectors.policy.states[0],ops:vectors.policy.ops.slice(0,1)} as PolicyResponse;
  const content=new Uint8Array(32).fill(43);let remote:RecordRow|undefined;
  const make=async(body:CompletedHistory)=>sealRecord({workspaceId:policy.policy.workspaceId,recordId:historyRecordId(body.chainId,body.deployTxHash),type:"execution_event",revision:1,keyEpoch:1,authorKeyId:keys.memberKeyId,authorPolicyVersion:1},body as unknown as Json,content,keys.signingSeed);
  const row=(record:EncryptedRecord):RecordRow=>({record,changeSequence:record.revision,createdAt:"2026-09-10",updatedAt:"2026-09-10"});
  const client={policy:vi.fn(async()=>policy),record:vi.fn(async()=>{if(!remote)throw new ApiError(404,"missing");return remote;}),
    put:vi.fn(async(record:EncryptedRecord)=>{remote=row(record);return remote;}),
    records:vi.fn(async()=>({records:remote?[remote]:[],hasMore:false,nextCursor:"next"}))};
  const sync=new HistorySync({client:client as unknown as WorkspaceClient,workspaceId:policy.policy.workspaceId,memberKeys:keys,loadKeys:async()=>new Map([[1,content]])});
  return {sync,client,make,row,setRemote:(record:EncryptedRecord)=>remote=row(record)};
}
describe("completed history sync",()=>{
  it("returns both safe copies for review without overwriting conflicting history",async()=>{
    const f=setup();const remote=completedHistory(local())!;f.setRemote(await f.make(remote));
    const proposed=completedHistory({...local(),amount:"2"})!;
    const error=await f.sync.upload(proposed).catch(error=>error);
    expect(error).toBeInstanceOf(HistoryUploadConflict);
    expect(error.local).toEqual(proposed);expect(error.remote).toEqual(remote);
    expect(error.recordId).toBe(historyRecordId(remote.chainId,remote.deployTxHash));
    expect(f.client.put).not.toHaveBeenCalled();
  });
  it("does not contact the API for in-flight history",async()=>{
    const f=setup();expect(await f.sync.importLocal({...local(),status:"pending"})).toBeNull();
    expect(f.client.record).not.toHaveBeenCalled();expect(f.client.policy).not.toHaveBeenCalled();expect(f.client.put).not.toHaveBeenCalled();
  });
  it("deduplicates repeated imports and retries using the canonical deployment ID",async()=>{
    const f=setup();const a=await f.sync.importLocal(local());const b=await f.sync.importLocal(local());
    expect(a).toEqual(b);expect(f.client.put).toHaveBeenCalledTimes(1);
    expect(a!.record.recordId).toBe(historyRecordId(local().chainId,local().deployTxHash));
  });
  it("re-reads a competing revision and preserves the other device's hashes",async()=>{
    const f=setup();const competitor=completedHistory({...local(),approveTxHashes:[`0x${"ee".repeat(32)}`]})!;
    f.client.put.mockImplementationOnce(async()=>{f.setRemote(await f.make(competitor));throw new ApiError(412,"changed");});
    const result=await f.sync.importLocal({...local(),approveTxHashes:[`0x${"ff".repeat(32)}`]});
    expect(result!.record.revision).toBe(2);expect(f.client.record).toHaveBeenCalledTimes(2);
    const collected:any[]=[];
    await f.sync.pull({checkpoint:async()=>({grantedEpochs:[]}),commit:async(rows)=>{collected.push(...rows);}});
    expect(collected[0].body.approveTxHashes).toEqual([`0x${"ee".repeat(32)}`,`0x${"ff".repeat(32)}`]);
  });
  it("leaves the old checkpoint intact when durable cache storage fails",async()=>{
    const f=setup();await f.sync.importLocal(local());let checkpoint:SyncCheckpoint={grantedEpochs:[]};
    const commit=vi.fn(async(_rows:unknown,next:SyncCheckpoint)=>{checkpoint=next;});
    commit.mockImplementationOnce(async()=>{throw new Error("disk full");});
    await expect(f.sync.pull({checkpoint:async()=>checkpoint,commit})).rejects.toThrow("disk full");
    expect(checkpoint).toEqual({grantedEpochs:[]});
    await f.sync.pull({checkpoint:async()=>checkpoint,commit});expect(checkpoint.cursor).toBe("next");
    expect(commit.mock.calls[1][0]).toHaveLength(1);
  });
  it("does not advance a cursor past a body with a mismatched deployment identity",async()=>{
    const f=setup();const body=completedHistory(local())!;
    const record=await f.make(body);record.recordId=`0x${"99".repeat(32)}`;f.setRemote(record);
    const commit=vi.fn();await expect(f.sync.pull({checkpoint:async()=>({grantedEpochs:[]}),commit})).rejects.toThrow();expect(commit).not.toHaveBeenCalled();
  });
});
