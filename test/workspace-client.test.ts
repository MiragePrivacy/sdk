import {afterEach,describe,expect,it,vi} from "vitest";
import type {Hex} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {verifyIdentityUnlink,createIdentityRotation,type SignedIdentityLink,type IdentityLinkState,type SignedIdentityUnlink} from "../src/workspaces/identity";
import vectors from "./fixtures/workspaces.json";
import {WorkspaceClient} from "../src/workspaces/client";
import {deriveMemberKeys,unlockMember} from "../src/workspaces/keys";
import {sealRecord} from "../src/workspaces/records";
import {WorkspaceKeyring} from "../src/workspaces/personal";
import {applyPolicyOp} from "../src/workspaces/policy";

afterEach(()=>vi.unstubAllGlobals());
const wid=vectors.policy.ops[0].workspaceId as Hex;
function setup(){
  const keys=deriveMemberKeys(vectors.unlock[0].signature as Hex);
  const principalHash=`0x${"19".repeat(32)}` as Hex;
  let count=1;let policyOverride:unknown;let challengeOverride:Record<string,unknown>={};let recordOverride:unknown;let pageOverride:unknown;
  const requests:{url:string;init:RequestInit}[]=[];
  const fetcher=vi.fn(async(url:string,init:RequestInit)=>{
    requests.push({url,init});const path=new URL(url).pathname;
    const value=path.endsWith("/challenge")?{purpose:"session",workspaceId:wid,memberKeyId:keys.memberKeyId,principalHash,nonce:`0x${"20".repeat(32)}`,expiresAt:Math.floor(Date.now()/1000)+300,...challengeOverride}:
      path.endsWith("/sessions")?{token:`mirage_ws_${"s".repeat(43)}`,workspaceId:wid,memberKeyId:keys.memberKeyId,caps:15,policyVersion:count,expiresAt:Math.floor(Date.now()/1000)+3600}:
      path.endsWith("/policy")?policyOverride??{policy:vectors.policy.states[count-1],ops:vectors.policy.ops.slice(0,count)}:
      path.endsWith("/envelopes")?vectors.policy.states[count-1].envelopes.filter(e=>e.recipientKeyId===keys.memberKeyId):
      path.endsWith("/records")?pageOverride:recordOverride;
    return new Response(JSON.stringify(value),{status:200,headers:{"Content-Type":"application/json"}});
  });
  vi.stubGlobal("fetch",fetcher);
  const client=new WorkspaceClient({apiServer:"https://api.example",keys,principalHash,principalToken:()=>"principal-token"});
  return{client,keys,requests,fetcher,setCount:(n:number)=>count=n,setPolicy:(v:unknown)=>policyOverride=v,setChallenge:(v:Record<string,unknown>)=>challengeOverride=v,setRecord:(v:unknown)=>recordOverride=v,setPage:(v:unknown)=>pageOverride=v};
}
describe("workspace client",()=>{
  it("acknowledges a committed self-replacement but rejects later reads as the revoked key",async()=>{
    const f=setup(),before=await f.client.policy(wid),ring=new WorkspaceKeyring(wid,f.keys);
    await ring.load(before);const replacement=await unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`),1);
    const op=await ring.prepareMemberRotation(replacement),policy=applyPolicyOp(before.policy,op),after={policy,ops:[...before.ops,op]};
    const original=f.fetcher.getMockImplementation()!;
    f.fetcher.mockImplementation(async(url,init)=>{
      if(url.endsWith("/policy/ops")){f.setPolicy(after);return new Response(JSON.stringify(policy));}
      return original(url,init);
    });
    expect(await f.client.append(op)).toEqual(after);
    await expect(f.client.policy(wid)).rejects.toThrow("membership revoked");
    expect(f.requests.filter(r=>r.url.endsWith("/sessions"))).toHaveLength(2);ring.close();
  });
  it("publishes only this sign-in's verified pointer and rejects a substituted response",async()=>{
    const f=setup(),replacement=await unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`),1);
    const pointer=createIdentityRotation(f.keys,replacement,1234);f.setRecord(pointer);
    expect(await f.client.registerRotation(pointer)).toEqual(pointer);
    expect(f.requests[0].url).toBe("https://api.example/identity/rotations");
    expect(f.requests[0].init.headers).toMatchObject({Authorization:"Bearer principal-token"});
    f.setRecord({...pointer,issuedAt:1235});await expect(f.client.registerRotation(pointer)).rejects.toThrow("different identity rotation");
    await expect(f.client.registerRotation({...pointer,oldKem:replacement.kemPublicKey})).rejects.toThrow("rotation chain");
  });
  it("reads generation pointers only through a principal-bound signed challenge",async()=>{
    const f=setup(),replacement=await unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`),1);
    const pointer=createIdentityRotation(f.keys,replacement,1234);f.setChallenge({purpose:"discovery",workspaceId:null});f.setRecord([pointer]);
    expect(await f.client.rotations()).toEqual([pointer]);
    expect(f.requests[1].url).toContain("/identity/rotations?member=");
    f.setRecord([pointer,pointer]);await expect(f.client.rotations()).rejects.toThrow("rotation chain");
    f.setRecord([{...pointer,signatureNew:`0x${"99".repeat(64)}`}]);await expect(f.client.rotations()).rejects.toThrow("rotation chain");
  });
  it("reads linked generation proofs and signs deletion of only the other branch",async()=>{
    const f=setup();f.setChallenge({purpose:"discovery",workspaceId:null});
    const state={link:vectors.policy.ops[1].payload.link,unlinking:false,rotations:[vectors.policy.ops[8].payload.pointer],workspaceIds:[wid]} as IdentityLinkState;
    f.setRecord([state]);expect(await f.client.links()).toEqual([state]);
    await expect(f.client.deleteLink(state,f.keys.memberKeyId)).rejects.toThrow("other sign-in branch");
    f.fetcher.mockImplementationOnce(async(_url,init)=>{
      expect(init.method).toBe("DELETE");const proof=JSON.parse(init.body as string) as SignedIdentityUnlink;
      expect(proof.remainingKey).toBe(f.keys.memberKeyId);expect(proof.revokedKey).toBe(state.rotations[0].newKey);expect(verifyIdentityUnlink(proof)).toBe(true);
      return new Response(null,{status:204});
    });
    await f.client.deleteLink(state,state.rotations[0].newKey);
    const bad=structuredClone(state);bad.rotations[0].signatureNew=`0x${"99".repeat(64)}`;f.setRecord([bad]);
    await expect(f.client.links()).rejects.toThrow("rotation");
  });
  it("registers cross-signed links with both tokens only at the same API",async()=>{
    const f=setup(),keys=await unlockMember(privateKeyToAccount(`0x${"02".repeat(32)}`));
    const other=new WorkspaceClient({apiServer:"https://api.example",keys,principalHash:`0x${"28".repeat(32)}`,principalToken:()=>"second-token"});
    const link=vectors.policy.ops[1].payload.link as SignedIdentityLink;
    f.fetcher.mockImplementationOnce(async(_url,init)=>{
      expect(init.headers).toMatchObject({Authorization:"Bearer principal-token","X-Mirage-Link-Authorization":"Bearer second-token"});
      expect(JSON.parse(init.body as string)).toEqual(link);
      return new Response(JSON.stringify(link));
    });
    expect(await f.client.registerLink(link,other)).toEqual(link);
    const foreign=new WorkspaceClient({apiServer:"https://other.example",keys,principalHash:`0x${"28".repeat(32)}`,principalToken:()=>"second-token"});
    await expect(f.client.registerLink(link,foreign)).rejects.toThrow("same API");
    f.fetcher.mockResolvedValueOnce(new Response(JSON.stringify({...link,issuedAt:1})));
    await expect(f.client.registerLink(link,other)).rejects.toThrow("different identity link");
    other.close();await expect(f.client.registerLink(link,other)).rejects.toThrow();
  });
  it("coalesces concurrent session creation and verifies policy before returning it",async()=>{
    const f=setup();const [a,b]=await Promise.all([f.client.policy(wid),f.client.policy(wid)]);
    expect(a).toEqual(b);expect(a.policy).toEqual(vectors.policy.states[0]);
    expect(f.requests.filter(r=>new URL(r.url).pathname.endsWith("/sessions"))).toHaveLength(1);
    expect(f.requests.every(r=>r.init.credentials==="omit"&&r.init.cache==="no-store"&&r.init.redirect==="error")).toBe(true);
    a.policy.members[0].caps=0;
    expect((await f.client.policy(wid)).policy.members[0].caps).toBe(15);
    f.client.close();await expect(f.client.policy(wid)).rejects.toThrow();
  });
  it("does not sign a challenge redirected to another principal",async()=>{
    const f=setup();f.setChallenge({principalHash:`0x${"ff".repeat(32)}`});
    await expect(f.client.policy(wid)).rejects.toThrow("context");
    expect(f.requests.some(r=>r.init.method==="POST")).toBe(false);
  });
  it("rejects modified snapshots and a server rollback",async()=>{
    const f=setup();f.setCount(2);await f.client.policy(wid);f.setCount(1);
    await expect(f.client.policy(wid)).rejects.toThrow("rollback");
    const policy=structuredClone(vectors.policy.states[1]);policy.members[0].caps=0;
    f.setPolicy({policy,ops:vectors.policy.ops.slice(0,2)});
    await expect(f.client.policy(wid)).rejects.toThrow("signed log");
  });
  it("verifies record context and sync ordering before returning data",async()=>{
    const f=setup();const encrypted=await sealRecord({workspaceId:wid,recordId:`0x${"77".repeat(32)}`,type:"execution_event",revision:1,keyEpoch:1,authorPolicyVersion:1,authorKeyId:f.keys.memberKeyId}, {status:"success"},new Uint8Array(32).fill(43),f.keys.signingSeed);
    const row={record:encrypted,changeSequence:1,createdAt:"2026-09-10",updatedAt:"2026-09-10"};
    f.setRecord(row);expect((await f.client.record(wid,encrypted.recordId)).record).toEqual(encrypted);
    await expect(f.client.record(wid,`0x${"66".repeat(32)}`)).rejects.toThrow("Invalid workspace record");
    f.setPage({records:[row,row],nextCursor:"cursor",hasMore:false});
    await expect(f.client.records(wid)).rejects.toThrow("ordering");
    f.setPage({records:[row],nextCursor:"cursor",hasMore:false});
    await expect(f.client.records(wid,undefined,"contact")).rejects.toThrow("type");
    expect((await f.client.records(wid)).records).toHaveLength(1);
  });
  it("stops before HTTP when logout occurs during principal refresh",async()=>{
    const f=setup();let release!:(value:string)=>void;
    const client=new WorkspaceClient({apiServer:"https://api.example",principalHash:`0x${"19".repeat(32)}`,keys:f.keys,principalToken:()=>new Promise(resolve=>release=resolve)});
    const pending=client.policy(wid);client.close();release("refreshed-token");
    await expect(pending).rejects.toThrow();expect(f.fetcher).not.toHaveBeenCalled();
  });
});
