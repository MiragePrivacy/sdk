import {describe,it,expect} from "vitest";
import {createHash} from "node:crypto";
import {completedHistory,historyRecordId,mergeCompletedHistory,parseCompletedHistory,type LocalHistoryRecord} from "../src/workspaces/history";
import type {Json} from "../src/workspaces/encoding";
const hash=(n:string)=>`0x${n.repeat(64)}`;
const address=(n:string)=>`0x${n.repeat(40)}`;
const local=():LocalHistoryRecord=>({status:"success",chainId:31337,date:"2026-09-10T12:00:00Z",deployTxHash:hash("a"),submitTxHashes:[hash("b")],recipient:address("c"),amount:"1.5000",tokenAddress:address("d"),tokenSymbol:"TEST",tokenDecimals:18});
describe("completed history",()=>{
  it("preserves finite USD display snapshots as canonical decimal strings",()=>{
    const body=completedHistory({...local(),totalFeeUsd:0.1234567,networkFeeUsd:0,tokenTotalUsd:1e-7,transfersTotalUsd:1e21})!;
    expect(body).toMatchObject({totalFeeUsd:"0.1234567",networkFeeUsd:"0",tokenTotalUsd:"0.0000001",transfersTotalUsd:"1000000000000000000000"});
    expect(parseCompletedHistory(body as unknown as Json)).toEqual(body);
    expect(mergeCompletedHistory(completedHistory(local())!,body)).toEqual(body);
    expect(()=>mergeCompletedHistory(body,{...body,totalFeeUsd:"2"})).toThrow("totalFeeUsd");
    for(const totalFeeUsd of [NaN,Infinity,-1])expect(()=>completedHistory({...local(),totalFeeUsd})).toThrow("USD snapshot");
    expect(()=>parseCompletedHistory({...body,totalFeeUsd:"0.12345670"} as unknown as Json)).toThrow("Noncanonical");
  });
  it("imports only completed delivery and never copies resumable secrets",()=>{
    const record={...local(),blindingScalar:"secret",sealedPricingAuthorization:"secret",approval:{signature:"secret"},selectorMapping:{secret:"secret"},seed:"secret",transfers:[{recipient:address("c"),amount:"1.5000",blindingScalar:"secret"}]};
    const safe=completedHistory(record)!;
    expect(JSON.stringify(safe)).not.toContain("secret");expect(safe.transfers[0].amount).toBe("1.5");
    for(const status of ["approve","deploy","pending","failed","cancelled"])expect(completedHistory({...record,status})).toBeNull();
    expect(completedHistory({...record,submitTxHashes:[]})).toBeNull();
    expect(completedHistory({...record,deployTxHash:undefined})).toBeNull();
    expect(parseCompletedHistory(safe as unknown as Json)).toEqual(safe);
  });
  it("uses the fixed uint64 chain and deploy hash import ID encoding",()=>{
    const chain=Buffer.alloc(8);chain.writeBigUInt64BE(31337n);
    const expected=`0x${createHash("sha256").update(chain).update(Buffer.from("a".repeat(64),"hex")).digest("hex")}`;
    expect(historyRecordId(31337,hash("a"))).toBe(expected);
    expect(historyRecordId(31337,hash("A"))).toBe(expected);
    expect(historyRecordId(1,hash("a"))).not.toBe(expected);
  });
  it("includes confirmed cancellations and refuses to merge them with successful delivery",()=>{
    const cancelled=completedHistory({...local(),status:"cancelled",submitTxHashes:[],cancelTxHash:hash("f")})!;
    expect(cancelled.status).toBe("cancelled");expect(cancelled.cancelTxHash).toBe(hash("f"));
    expect(parseCompletedHistory(cancelled as unknown as Json)).toEqual(cancelled);
    expect(()=>mergeCompletedHistory(completedHistory(local())!,cancelled)).toThrow("status");
  });
  it("merges missing metadata and every observed hash without dropping either copy",()=>{
    const a=completedHistory(local())!;
    const b=completedHistory({...local(),date:"2026-09-10T12:01:00Z",submitTxHashes:[hash("e")],approveTxHashes:[hash("f")],escrowAddress:address("a")})!;
    const merged=mergeCompletedHistory(a,b);
    expect(merged.deliveryTxHashes).toEqual([hash("b"),hash("e")]);expect(merged.approveTxHashes).toEqual([hash("f")]);
    expect(merged.observedAt).toHaveLength(2);expect(merged.escrowAddress).toBe(address("a"));
    expect(mergeCompletedHistory(b,a)).toEqual(merged);expect(mergeCompletedHistory(merged,a)).toEqual(merged);
  });
  it("refuses conflicting amounts, destinations and commitments instead of selecting a terminal status",()=>{
    const a=completedHistory({...local(),quoteCommitment:hash("1")})!;
    for(const patch of [{amount:"2"},{recipient:address("a")},{quoteCommitment:hash("2")},{deployTxHash:hash("f") }]){
      const b=completedHistory({...local(),...patch})!;expect(()=>mergeCompletedHistory(a,b)).toThrow("conflict");
    }
    expect(()=>parseCompletedHistory({...a,status:"failed"} as unknown as Json)).toThrow();
    expect(()=>parseCompletedHistory({...a,blindingScalar:"secret"} as unknown as Json)).toThrow();
  });
});
