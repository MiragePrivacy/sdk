import {sha256} from "@noble/hashes/sha2.js";
import {bytesToHex,concatBytes,type Hex} from "viem";
import {bytes,canonicalJson,uint,type Json} from "./encoding";

export interface LocalHistoryRow {recipient:string;recipientENS?:string;amount:string;tokenAddress?:string;decimals?:number;symbol?:string}
/** Structural input accepts the existing frontend record; only listed public history fields are copied. */
export interface LocalHistoryRecord {
  status:string;chainId:number;date:string;deployTxHash?:string;submitTxHash?:string;submitTxHashes?:string[];
  approveTxHash?:string;approveTxHashes?:string[];transfers?:LocalHistoryRow[];
  recipient:string;recipientENS?:string;amount:string;tokenAddress:string;tokenSymbol:string;tokenDecimals:number;
  escrowAddress?:string;quoteCommitment?:string;senderAddress?:string;
  cancelTxHash?:string;
  totalFeeUsd?:number;networkFeeUsd?:number;tokenTotalUsd?:number;transfersTotalUsd?:number;
}
export interface CompletedTransferRow {recipient:Hex;amount:string;tokenAddress:Hex;decimals:number;symbol:string;recipientENS?:string}
export interface CompletedHistory {
  version:1;kind:"completed_transfer";status:"success"|"cancelled";chainId:number;deployTxHash:Hex;
  observedAt:string[];transfers:CompletedTransferRow[];approveTxHashes:Hex[];deliveryTxHashes:Hex[];
  escrowAddress?:Hex;quoteCommitment?:Hex;senderAddress?:Hex;
  cancelTxHash?:Hex;
  /** Decimal strings preserve display snapshots without non-integer canonical JSON numbers. */
  totalFeeUsd?:string;networkFeeUsd?:string;tokenTotalUsd?:string;transfersTotalUsd?:string;
}
export class HistoryConflictError extends Error {constructor(message:string){super(message);this.name="HistoryConflictError";}}
function hex(value:string,length:number):Hex {const normalized=value.toLowerCase() as Hex;bytes(normalized,length);return normalized;}
const hashes=(values:(string|undefined)[])=>[...new Set(values.filter((v):v is string=>v!==undefined).map(v=>hex(v,32)))].sort();
function amount(value:string):string {
  if(!/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value))throw new Error("Invalid completed transfer amount");
  const [whole,fraction]=value.split(".");const tail=fraction?.replace(/0+$/,"");return tail?`${whole}.${tail}`:whole;
}
const usdFields=["totalFeeUsd","networkFeeUsd","tokenTotalUsd","transfersTotalUsd"] as const;
function usdSnapshot(value:number):string {
  if(typeof value!=="number"||!Number.isFinite(value)||value<0)throw new Error("Invalid history USD snapshot");
  const text=String(value);if(!text.includes("e"))return amount(text);
  const [mantissa,power]=text.split("e"),[whole,fraction=""]=mantissa.split("."),digits=whole+fraction,point=whole.length+Number(power);
  return amount(point<=0?`0.${"0".repeat(-point)}${digits}`:point>=digits.length?digits+"0".repeat(point-digits.length):`${digits.slice(0,point)}.${digits.slice(point)}`);
}
export function historyRecordId(chainId:number,deployTxHash:string):Hex {
  uint(chainId,53,1);const chain=new Uint8Array(8);new DataView(chain.buffer).setBigUint64(0,BigInt(chainId),false);
  return bytesToHex(sha256(concatBytes([chain,bytes(hex(deployTxHash,32),32)])));
}
/** Delivery or confirmed cancellation is terminal. Unresolved failures and pending transfers stay local. */
export function completedHistory(record:LocalHistoryRecord):CompletedHistory|null {
  if(!["success","cancelled"].includes(record.status)||!record.deployTxHash)return null;
  const deliveries=hashes([...(record.submitTxHashes??[]),record.submitTxHash]);
  if(record.status==="success"&&!deliveries.length)return null;
  if(record.status==="cancelled"&&!record.cancelTxHash)return null;
  uint(record.chainId,53,1);
  const date=new Date(record.date);if(!Number.isFinite(date.getTime()))throw new Error("Invalid completed transfer date");
  const rows=record.transfers?.length?record.transfers:[{recipient:record.recipient,recipientENS:record.recipientENS,amount:record.amount}];
  const transfers=rows.map(row=>{
    const decimals=row.decimals??record.tokenDecimals;uint(decimals,8);
    const result:CompletedTransferRow={recipient:hex(row.recipient,20),amount:amount(row.amount),tokenAddress:hex(row.tokenAddress??record.tokenAddress,20),
      decimals,symbol:row.symbol??record.tokenSymbol};
    if(row.recipientENS)result.recipientENS=row.recipientENS;return result;
  });
  const result:CompletedHistory={version:1,kind:"completed_transfer",status:record.status as "success"|"cancelled",chainId:record.chainId,deployTxHash:hex(record.deployTxHash,32),
    observedAt:[date.toISOString()],transfers,approveTxHashes:hashes([...(record.approveTxHashes??[]),record.approveTxHash]),deliveryTxHashes:deliveries};
  if(record.escrowAddress)result.escrowAddress=hex(record.escrowAddress,20);
  if(record.quoteCommitment)result.quoteCommitment=hex(record.quoteCommitment,32);
  if(record.senderAddress)result.senderAddress=hex(record.senderAddress,20);
  if(record.status==="cancelled")result.cancelTxHash=hex(record.cancelTxHash!,32);
  for(const field of usdFields)if(record[field]!==undefined)result[field]=usdSnapshot(record[field]);
  canonicalJson(result as unknown as Json);return result;
}
function equal(a:unknown,b:unknown){return canonicalJson(a as Json)===canonicalJson(b as Json);}
/** Keep every observed hash; never resolve conflicting recipients/amounts/final results by timestamp. */
export function mergeCompletedHistory(a:CompletedHistory,b:CompletedHistory):CompletedHistory {
  for(const field of ["version","kind","status","chainId","deployTxHash"] as const)
    if(a[field]!==b[field])throw new HistoryConflictError(`Completed history conflicts on ${field}`);
  if(a.transfers.length!==b.transfers.length)throw new HistoryConflictError("Completed history has different transfer rows");
  const merged=structuredClone(a);
  merged.transfers=a.transfers.map((row,index)=>{
    const other=b.transfers[index];
    for(const field of ["recipient","amount","tokenAddress","decimals"] as const)
      if(row[field]!==other[field])throw new HistoryConflictError(`Completed transfer row conflicts on ${field}`);
    const combined={...row};
    for(const field of ["symbol","recipientENS"] as const){
      if(row[field]&&other[field]&&row[field]!==other[field])throw new HistoryConflictError(`Completed transfer metadata conflicts on ${field}`);
      if(!combined[field]&&other[field])combined[field]=other[field];
    }
    return combined;
  });
  for(const field of ["escrowAddress","quoteCommitment","senderAddress","cancelTxHash"] as const){
    if(a[field]&&b[field]&&a[field]!==b[field])throw new HistoryConflictError(`Completed history conflicts on ${field}`);
    if(!merged[field]&&b[field])merged[field]=b[field];
  }
  for(const field of usdFields){
    if(a[field]!==undefined&&b[field]!==undefined&&a[field]!==b[field])throw new HistoryConflictError(`Completed history conflicts on ${field}`);
    if(merged[field]===undefined&&b[field]!==undefined)merged[field]=b[field];
  }
  merged.observedAt=[...new Set([...a.observedAt,...b.observedAt])].sort();
  merged.approveTxHashes=hashes([...a.approveTxHashes,...b.approveTxHashes]);
  merged.deliveryTxHashes=hashes([...a.deliveryTxHashes,...b.deliveryTxHashes]);
  return merged;
}
export function parseCompletedHistory(value:Json):CompletedHistory {
  if(!value||typeof value!=="object"||Array.isArray(value))throw new Error("Invalid completed history");
  const v=value as unknown as CompletedHistory;
  const allowed=["version","kind","status","chainId","deployTxHash","observedAt","transfers","approveTxHashes","deliveryTxHashes","escrowAddress","quoteCommitment","senderAddress","cancelTxHash",...usdFields];
  if(Object.keys(v).some(k=>!allowed.includes(k))||v.version!==1||v.kind!=="completed_transfer"||!["success","cancelled"].includes(v.status)||!Array.isArray(v.observedAt)||!v.observedAt.length||!Array.isArray(v.transfers)||!v.transfers.length||!Array.isArray(v.approveTxHashes)||!Array.isArray(v.deliveryTxHashes))throw new Error("Invalid completed history schema");
  const first=v.transfers[0];
  const canonical=completedHistory({status:v.status,chainId:v.chainId,date:v.observedAt[0],deployTxHash:v.deployTxHash,submitTxHashes:v.deliveryTxHashes,approveTxHashes:v.approveTxHashes,
    recipient:first.recipient,amount:first.amount,tokenAddress:first.tokenAddress,tokenSymbol:first.symbol,tokenDecimals:first.decimals,transfers:v.transfers,
    escrowAddress:v.escrowAddress,quoteCommitment:v.quoteCommitment,senderAddress:v.senderAddress,cancelTxHash:v.cancelTxHash,
    ...Object.fromEntries(usdFields.filter(field=>v[field]!==undefined).map(field=>[field,Number(v[field])]))});
  if(!canonical)throw new Error("History is not completed");
  canonical.observedAt=[...new Set(v.observedAt.map(d=>new Date(d).toISOString()))].sort();
  if(!equal(canonical,v))throw new Error("Noncanonical completed history");return canonical;
}
