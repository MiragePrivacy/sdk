import {afterEach,describe,expect,it,vi} from "vitest";
import {recoverMessageAddress,type Hex} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import vectors from "./fixtures/workspaces.json";
import {supportServer} from "./support-server";
import {WorkspaceClient} from "../src/workspaces/client";
import {createIdentityRotation} from "../src/workspaces/identity";
import {acceptWorkspaceInvite} from "../src/workspaces/invitations";
import {deriveMemberKeys,unlockMember,type MemberKeys} from "../src/workspaces/keys";
import {WorkspaceKeyring,createTeamWorkspace} from "../src/workspaces/personal";
import {CAPS,currentMemberKey,policyAuthorCheck,replayPolicy,type PolicyOp} from "../src/workspaces/policy";
import {RECORD_TYPES,SUPPORT_RECORD_TYPES,openRecord,realmRecordTypes,sealRecord,verifyRecord,type RecordHeader} from "../src/workspaces/records";
import {
  SUPPORT_MEMBER_ID,SUPPORT_REPORT_FIELDS,SUPPORT_REPORT_SECRET_FIELDS,SupportAdmin,anonymousSignerFromPrivateKey,buildSupportReport,createAnonymousSigner,
  fetchSupportConfig,openStaffWorkspace,openSupportWorkspace,parseSupportBody,parseSupportMessage,parseSupportReport,parseSupportTicket,supportIdentityKeys,
  supportTombstone,verifySupportChain,verifySupportConfig,type AnonymousSigner,type SupportConfig,type SupportSession,type StaffWorkspace,
} from "../src/workspaces/support";

afterEach(()=>vi.unstubAllGlobals());
const account=(n:number)=>privateKeyToAccount(`0x${n.toString(16).padStart(2,"0").repeat(32)}`);
const member=(n:number,generation=0)=>unlockMember(account(n),generation);
const hash=(n:number)=>`0x${n.toString(16).padStart(2,"0").repeat(32)}` as Hex;
const iso="2026-11-23T10:00:00.000Z";

describe("workspace realms",()=>{
  const ops=()=>structuredClone(vectors.support.addSupportMember.ops) as PolicyOp[];
  const wid=vectors.support.addSupportMember.ops[0].workspaceId as Hex;
  function setup(realm:"workspaces"|"support"|undefined,token:string){
    const keys=deriveMemberKeys(vectors.unlock[0].signature as Hex),principalHash=hash(0x19),requests:string[]=[];
    vi.stubGlobal("fetch",vi.fn(async(url:string)=>{
      const path=new URL(url).pathname;requests.push(path);
      const value=path.endsWith("/challenge")?{purpose:"session",workspaceId:wid,memberKeyId:keys.memberKeyId,principalHash,nonce:hash(0x20),expiresAt:Math.floor(Date.now()/1000)+300}:
        path.endsWith("/sessions")?{token,workspaceId:wid,memberKeyId:keys.memberKeyId,caps:15,policyVersion:2,expiresAt:Math.floor(Date.now()/1000)+3600}:
        path.endsWith("/policy")?{policy:vectors.support.addSupportMember.states[1],ops:ops().slice(0,2)}:{workspaces:[],nextCursor:"",hasMore:false};
      return new Response(JSON.stringify(value),{status:200});
    }));
    return {keys,requests,client:new WorkspaceClient({apiServer:"https://api.example",keys,principalHash,principalToken:()=>"principal",...(realm?{realm}:{})})};
  }
  it("routes the support realm under /support and leaves the default realm unchanged",async()=>{
    const support=setup("support",`mirage_sp_${"s".repeat(43)}`);
    expect(support.client.realm).toBe("support");
    await support.client.policy(wid);
    expect(support.requests).toEqual([`/support/workspaces/${wid}/challenge`,`/support/workspaces/${wid}/sessions`,`/support/workspaces/${wid}/policy`]);
    await support.client.supportAdmin(wid,"/workspaces?limit=1");
    expect(support.requests.at(-1)).toBe("/support/admin/workspaces");
    await expect(support.client.supportAdmin(wid,"/../workspaces")).rejects.toThrow("Invalid support admin");
    vi.unstubAllGlobals();
    const normal=setup(undefined,`mirage_ws_${"s".repeat(43)}`);
    expect(normal.client.realm).toBe("workspaces");
    await normal.client.policy(wid);
    expect(normal.requests).toEqual([`/workspaces/${wid}/challenge`,`/workspaces/${wid}/sessions`,`/workspaces/${wid}/policy`]);
    await expect(normal.client.supportAdmin(wid,"/workspaces")).rejects.toThrow("Invalid support admin");
  });
  it("binds session tokens to their realm",async()=>{
    await expect(setup("support",`mirage_ws_${"s".repeat(43)}`).client.policy(wid)).rejects.toThrow("Invalid workspace session");
    vi.unstubAllGlobals();
    await expect(setup("workspaces",`mirage_sp_${"s".repeat(43)}`).client.policy(wid)).rejects.toThrow("Invalid workspace session");
    expect(()=>new WorkspaceClient({apiServer:"https://api.example",keys:deriveMemberKeys(vectors.unlock[0].signature as Hex),principalHash:hash(1),principalToken:()=>"",realm:"other" as "support"})).toThrow("realm");
  });
  it("keeps a separate record type list per realm",async()=>{
    expect(realmRecordTypes("workspaces")).toBe(RECORD_TYPES);expect(realmRecordTypes("support")).toBe(SUPPORT_RECORD_TYPES);
    expect(RECORD_TYPES).toEqual(["payment_request","decision","execution_event","contact","payment_template","roster","proposal_cancellation"]);
    expect(SUPPORT_RECORD_TYPES).toEqual(["support_ticket","support_message","support_report","support_feedback","support_identity","roster"]);
    const keys=deriveMemberKeys(vectors.unlock[0].signature as Hex),content=new Uint8Array(32).fill(43),log=ops().slice(0,2);
    const header=(type:RecordHeader["type"]):RecordHeader=>({workspaceId:wid,recordId:hash(0x44),type,revision:1,keyEpoch:1,authorKeyId:keys.memberKeyId,authorPolicyVersion:1});
    await expect(sealRecord(header("support_ticket"),{},content,keys.signingSeed)).rejects.toThrow("Invalid record type");
    await expect(sealRecord(header("payment_request"),{},content,keys.signingSeed,"support")).rejects.toThrow("Invalid record type");
    await expect(sealRecord(header("proposal_cancellation"),{},content,keys.signingSeed,"support")).rejects.toThrow("Invalid record type");
    const ticket=await sealRecord(header("support_ticket"),{a:1},content,keys.signingSeed,"support");
    expect(verifyRecord(ticket,policyAuthorCheck(log,"support"),"support")).toBe(true);
    expect(verifyRecord(ticket,policyAuthorCheck(log))).toBe(false);
    expect(await openRecord(ticket,content,policyAuthorCheck(log,"support"),"support")).toEqual({a:1});
    await expect(openRecord(ticket,content,policyAuthorCheck(log))).rejects.toThrow("Invalid record");
    const payment=await sealRecord(header("payment_request"),{a:1},content,keys.signingSeed);
    expect(verifyRecord(payment,policyAuthorCheck(log))).toBe(true);
    expect(verifyRecord(payment,policyAuthorCheck(log,"support"),"support")).toBe(false);
    const support=setup("support",`mirage_sp_${"s".repeat(43)}`);
    await expect(support.client.records(wid,undefined,"payment_request")).rejects.toThrow("Invalid record type");
    await expect(support.client.put(payment,0)).rejects.toThrow("Invalid record write authority");
    vi.unstubAllGlobals();
    await expect(setup(undefined,`mirage_ws_${"s".repeat(43)}`).client.records(wid,undefined,"support_ticket")).rejects.toThrow("Invalid record type");
  });
  it("reserves support identity and roster records for owners in the support realm",async()=>{
    const log=ops(),at=replayPolicy(log,"support"),key=vectors.support.keys[1];
    const seed=Uint8Array.from(Buffer.from(key.signingSeed.slice(2),"hex")),content=new Uint8Array(32).fill(45);
    const header=(type:RecordHeader["type"]):RecordHeader=>({workspaceId:wid,recordId:hash(0x45),type,revision:1,keyEpoch:3,authorKeyId:key.memberKeyId as Hex,authorPolicyVersion:at.policyVersion});
    const check=policyAuthorCheck(log,"support");
    expect(verifyRecord(await sealRecord(header("support_message"),{},content,seed,"support"),check,"support")).toBe(true);
    for(const type of ["support_identity","roster"] as const)expect(verifyRecord(await sealRecord(header(type),{},content,seed,"support"),check,"support")).toBe(false);
  });
});

describe("support key configuration",()=>{
  async function chain(){
    const [root,next,last,attacker]=await Promise.all([member(0x31),member(0x31,1),member(0x31,2),member(0x66)]);
    const rotations=[createIdentityRotation(root,next,100),createIdentityRotation(next,last,200)];
    const pinned={rootKeyId:root.memberKeyId,rootKem:root.kemPublicKey};
    const config:SupportConfig={...pinned,supportMemberId:SUPPORT_MEMBER_ID,staffWorkspaceId:`0x${"51".repeat(16)}`,rotations,
      current:{memberKeyId:last.memberKeyId,kemPublicKey:last.kemPublicKey,generation:2}};
    return {root,next,last,attacker,rotations,pinned,config};
  }
  const serve=(value:unknown)=>vi.stubGlobal("fetch",vi.fn(async()=>new Response(JSON.stringify(value),{status:200})));
  it("follows the signed rotation chain from the pinned root",async()=>{
    const f=await chain();serve(f.config);
    expect(await fetchSupportConfig("https://api.example/",f.pinned)).toEqual(f.config);
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("https://api.example/support/config");
    expect(verifySupportChain(f.pinned,[])).toEqual({memberKeyId:f.root.memberKeyId,kemPublicKey:f.root.kemPublicKey,generation:0});
    expect(verifySupportChain(f.pinned,f.rotations.slice(0,1)).generation).toBe(1);
  });
  it("rejects a substituted support key",async()=>{
    const f=await chain(),stolen={memberKeyId:f.attacker.memberKeyId,kemPublicKey:f.attacker.kemPublicKey};
    // The server names its own key as current without a pointer signed by the previous generation.
    serve({...f.config,current:{...stolen,generation:2}});
    await expect(fetchSupportConfig("https://api.example",f.pinned)).rejects.toThrow("does not match its rotation chain");
    // A pointer signed by the attacker for both sides does not descend from the root.
    const forged=createIdentityRotation(f.attacker,await member(0x66,1),300);
    expect(()=>verifySupportConfig({...f.config,rotations:[forged],current:{memberKeyId:forged.newKey,kemPublicKey:forged.newKem,generation:1}},f.pinned)).toThrow("Invalid support rotation chain");
    // A genuine pointer with only the KEM key swapped breaks both signatures.
    const swapped={...f.rotations[1],newKem:f.attacker.kemPublicKey};
    expect(()=>verifySupportConfig({...f.config,rotations:[f.rotations[0],swapped],current:{...f.config.current,kemPublicKey:f.attacker.kemPublicKey}},f.pinned)).toThrow("Invalid support rotation chain");
    // A different root, even with an internally consistent chain.
    expect(()=>verifySupportConfig({...f.config,rootKeyId:stolen.memberKeyId,rootKem:stolen.kemPublicKey,rotations:[],current:{...stolen,generation:0}},f.pinned)).toThrow("pinned key");
    expect(()=>verifySupportConfig({...f.config,rootKem:stolen.kemPublicKey},f.pinned)).toThrow("pinned key");
  });
  it("rejects reordered, repeated, truncated and bootstrap-mode responses",async()=>{
    const f=await chain();
    expect(()=>verifySupportChain(f.pinned,[f.rotations[1],f.rotations[0]])).toThrow("Invalid support rotation chain");
    expect(()=>verifySupportChain(f.pinned,[f.rotations[0],f.rotations[0]])).toThrow("Invalid support rotation chain");
    expect(()=>verifySupportConfig({...f.config,rotations:f.rotations.slice(0,1)},f.pinned)).toThrow("rotation chain");
    const truncated={...f.config,rotations:f.rotations.slice(0,1),current:{memberKeyId:f.next.memberKeyId,kemPublicKey:f.next.kemPublicKey,generation:1}};
    expect(verifySupportConfig(truncated,f.pinned).current.generation).toBe(1);
    expect(()=>verifySupportConfig(truncated,f.pinned,2)).toThrow("rolled back");
    expect(()=>verifySupportConfig({...f.config,supportMemberId:`0x${"00".repeat(16)}`},f.pinned)).toThrow("member id");
    serve({rootKeyId:null,rootKem:null,supportMemberId:SUPPORT_MEMBER_ID,staffWorkspaceId:null,rotations:[],current:null});
    await expect(fetchSupportConfig("https://api.example",f.pinned)).rejects.toThrow("pinned key");
  });
});

describe("support record bodies",()=>{
  const ticket={version:1,kind:"support_ticket",subject:"Stuck transfer",category:"transaction",status:"open",createdAt:iso,reportIds:[hash(7)]} as const;
  const message={version:1,kind:"support_message",ticketId:hash(8),text:"hello",sentAt:iso} as const;
  it("accepts the documented shapes",()=>{
    expect(parseSupportTicket({...ticket})).toEqual(ticket);
    expect(parseSupportTicket({...ticket,status:"closed",closedAt:iso,closedBy:"support"}).closedBy).toBe("support");
    expect(parseSupportMessage({...message,staffLabel:"Sam"}).staffLabel).toBe("Sam");
    expect(parseSupportBody("support_identity",{version:1,kind:"support_identity",generations:[{generation:0,privateKey:hash(9),address:`0x${"ab".repeat(20)}`}]})).toBeTruthy();
    expect(parseSupportBody("roster",{version:1,workspaceName:"Mirage Support",memberLabels:{[`0x${"01".repeat(16)}`]:"Sam"}})).toBeTruthy();
  });
  it("rejects unknown fields, wrong kinds and out-of-range values",()=>{
    for(const bad of [
      {...ticket,extra:1},{...ticket,kind:"support_message"},{...ticket,version:2},{...ticket,subject:""},{...ticket,subject:"x".repeat(201)},{...ticket,category:"billing"},
      {...ticket,status:"pending"},{...ticket,createdAt:"yesterday"},{...ticket,createdAt:"2026-11-23"},{...ticket,reportIds:["0x12"]},{...ticket,reportIds:[hash(7),hash(7)]},
      {...ticket,status:"closed"},{...ticket,closedAt:iso},{...ticket,status:"closed",closedAt:iso,closedBy:"admin"},{...ticket,closedBy:"user"},null,[],"text",
    ])expect(()=>parseSupportTicket(bad as never),JSON.stringify(bad)).toThrow("Invalid support ticket");
    for(const bad of [{...message,text:""},{...message,text:"x".repeat(8001)},{...message,ticketId:"0x01"},{...message,sentAt:1},{...message,staffLabel:""},{...message,html:"<b>"}])
      expect(()=>parseSupportMessage(bad as never),JSON.stringify(bad).slice(0,80)).toThrow("Invalid support message");
    expect(parseSupportMessage({...message,text:"x".repeat(8000)}).text).toHaveLength(8000);
    expect(()=>parseSupportBody("support_identity",{version:1,kind:"support_identity",generations:[]})).toThrow();
    expect(()=>parseSupportBody("support_identity",{version:1,kind:"support_identity",generations:[{generation:1,privateKey:hash(9),address:`0x${"ab".repeat(20)}`}]})).toThrow();
    expect(()=>parseSupportBody("roster",{version:1,approvalRules:{}})).toThrow("Invalid support roster");
  });
  it("recognizes tombstones for every support record type",()=>{
    for(const type of SUPPORT_RECORD_TYPES){
      expect(supportTombstone(type)).toEqual({version:1,kind:type,deleted:true});
      expect(parseSupportBody(type,{version:1,kind:type,deleted:true})).toEqual({version:1,kind:type,deleted:true});
      expect(()=>parseSupportBody(type,{version:1,kind:type,deleted:true,subject:"left behind"}),type).toThrow("tombstone");
    }
    expect(()=>parseSupportBody("support_ticket",{version:1,kind:"support_message",deleted:true})).toThrow("tombstone");
    expect(()=>parseSupportBody("support_ticket",{...ticket,deleted:false} as never)).toThrow("Invalid support ticket");
    expect(()=>supportTombstone("payment_request" as never)).toThrow();
  });
});

describe("support diagnostic reports",()=>{
  const approval={version:1,chainId:1,escrowContract:"0xescrow",deploymentTxHash:"0xdeploy",runtimeCodeHash:"0xcode",quoteCommitment:"0xquote",approvedAt:1700000000,signature:"sig"};
  const transaction={
    id:"local-1",date:iso,status:"failed",chainId:1,recipient:"0xrecipient",recipientENS:"sam.eth",amount:"1.5",tokenAddress:"0xtoken",tokenSymbol:"USDC",tokenDecimals:6,
    transfers:[{recipient:"0xrecipient",amount:"1.5",tokenAddress:"0xtoken",decimals:6,symbol:"USDC",note:"private memo"}],
    approveTxHash:"0xa",approveTxHashes:["0xa"],deployTxHash:"0xd",submitTxHash:"0xs",submitTxHashes:["0xs"],cancelTxHash:"0xc",
    escrowAddress:"0xescrow",escrowType:"erc20",nativeEth:false,quoteCommitment:"0xquote",senderAddress:"0xsender",
    depositByAsset:{"0xtoken":"2750000","0x0000000000000000000000000000000000000000":"1"},msgValue:"1",
    seed:"0xseed",selectorMapping:{"0x12345678":"0x9abcdef0"},blindingScalar:"0xscalar",sealedPricingAuthorization:"sealed-blob",
    totalFeeUsd:1.25,networkFeeUsd:0.1,tokenTotalUsd:1.5,transfersTotalUsd:1.5,serviceFeeAsset:"0xtoken",serviceFeeAmount:"1250000",rewardAsset:"0xtoken",sdkRewardAmount:"99",
    userApproveGas:"46000",userDeployGas:"900000",userGasPrice:"1000000000",approval:{...approval,internal:"drop me"},signalSubmitted:true,approveBroadcasted:true,deployedAt:1700000001,fromBlock:"123",
    // Never part of a report.
    workspaceId:`0x${"11".repeat(16)}`,proposalBinding:{proposalId:"p"},proposalExecutionNonce:hash(3),recipientLabel:"Sam",scheduledFor:iso,syncedOnly:false,privateKey:"0xdeadbeef",mnemonic:"abandon abandon",futureField:{nested:true},
  };
  const error={message:"execution reverted",code:"CALL_EXCEPTION",step:"execute"} as const;
  const meta={clientVersion:"1.2.3",userAgent:"vitest"};
  it("drops every field outside the allowlist and keeps the four secret and escrow fields",()=>{
    const report=buildSupportReport(transaction,error,meta);
    expect(Object.keys(report).sort()).toEqual(["clientVersion","error","transaction","userAgent"]);
    for(const field of Object.keys(report.transaction))expect(Object.keys(SUPPORT_REPORT_FIELDS)).toContain(field);
    for(const dropped of ["id","workspaceId","proposalBinding","proposalExecutionNonce","recipientLabel","scheduledFor","syncedOnly","privateKey","mnemonic","futureField"])
      expect(report.transaction,dropped).not.toHaveProperty(dropped);
    expect(SUPPORT_REPORT_SECRET_FIELDS).toEqual(["seed","selectorMapping","blindingScalar","sealedPricingAuthorization"]);
    expect(report.transaction).toMatchObject({seed:"0xseed",selectorMapping:{"0x12345678":"0x9abcdef0"},blindingScalar:"0xscalar",sealedPricingAuthorization:"sealed-blob"});
    expect(report.transaction).toMatchObject({status:"failed",chainId:1,deployTxHash:"0xd",approveTxHashes:["0xa"],submitTxHashes:["0xs"],cancelTxHash:"0xc",escrowAddress:"0xescrow",escrowType:"erc20",
      quoteCommitment:"0xquote",senderAddress:"0xsender",signalSubmitted:true,approveBroadcasted:true,deployedAt:1700000001,fromBlock:"123",userGasPrice:"1000000000"});
    // Every allowlisted field of the fixture survives.
    expect(Object.keys(report.transaction).sort()).toEqual(Object.keys(SUPPORT_REPORT_FIELDS).sort());
    expect(report.transaction.transfers).toEqual([{recipient:"0xrecipient",amount:"1.5",tokenAddress:"0xtoken",decimals:6,symbol:"USDC"}]);
    expect(report.transaction.approval).toEqual(approval);
    expect(report.transaction).toMatchObject({nativeEth:false,msgValue:"1",depositByAsset:{"0xtoken":"2750000","0x0000000000000000000000000000000000000000":"1"}});
    expect(report.transaction).toMatchObject({totalFeeUsd:"1.25",networkFeeUsd:"0.1",tokenTotalUsd:"1.5",transfersTotalUsd:"1.5"});
    expect(report.error).toEqual(error);
  });
  it("drops malformed values instead of passing them through or failing",()=>{
    const report=buildSupportReport({status:{toString:()=>"x"},chainId:"1",seed:42,selectorMapping:{a:{b:1}},blindingScalar:null,totalFeeUsd:Number.NaN,deployedAt:1.5,
      transfers:"all",approval:"yes",signalSubmitted:"true",nativeEth:"no",msgValue:1,depositByAsset:{"0xtoken":5},approveTxHashes:["0xa",7],sealedPricingAuthorization:"ok"},{message:"m".repeat(5000),step:"unknown" as never},meta);
    expect(report.transaction).toEqual({sealedPricingAuthorization:"ok"});
    expect(report.error).toEqual({message:"m".repeat(4000),step:"other"});
    expect(buildSupportReport(null as never,error,meta).transaction).toEqual({});
    const inherited=Object.create({seed:"0xinherited"}) as Record<string,unknown>;
    expect(buildSupportReport(inherited,error,meta).transaction).toEqual({});
  });
  it("applies the allowlist again when a report is read",()=>{
    const body={version:1,kind:"support_report",createdAt:iso,...buildSupportReport(transaction,error,meta)};
    expect(parseSupportReport(structuredClone(body) as never).transaction).toEqual(body.transaction);
    const smuggled=parseSupportReport({...structuredClone(body),transaction:{...body.transaction,mnemonic:"abandon",blindingScalar:"0xscalar"}} as never);
    expect(smuggled.transaction).not.toHaveProperty("mnemonic");expect(smuggled.transaction.blindingScalar).toBe("0xscalar");
    expect(()=>parseSupportReport({...structuredClone(body),extra:true} as never)).toThrow("Invalid support report");
    expect(()=>parseSupportReport({...structuredClone(body),error:{...error,stack:"trace"}} as never)).toThrow("Invalid support report error");
    expect(()=>parseSupportReport({...structuredClone(body),ticketId:"0x01"} as never)).toThrow("Invalid support report");
  });
});

describe("anonymous signer",()=>{
  it("unlocks member keys and signs SIWE text with one throwaway key",async()=>{
    const signer=createAnonymousSigner();
    expect(signer.privateKey).toMatch(/^0x[0-9a-f]{64}$/);
    const restored=anonymousSignerFromPrivateKey(signer.privateKey);
    expect(restored.address).toBe(signer.address);
    expect(await recoverMessageAddress({message:"example.org wants you to sign in",signature:await restored.signMessage("example.org wants you to sign in")})).toBe(signer.address);
    const [first,second,rotated]=await Promise.all([unlockMember(signer),unlockMember(restored),unlockMember(restored,1)]);
    expect(first.memberKeyId).toBe(second.memberKeyId);expect(first.kemPublicKey).toBe(second.kemPublicKey);expect(rotated.memberKeyId).not.toBe(first.memberKeyId);
    expect(createAnonymousSigner().privateKey).not.toBe(signer.privateKey);
    expect(()=>anonymousSignerFromPrivateKey("0x1234")).toThrow();
    expect(()=>anonymousSignerFromPrivateKey(`0x${"AB".repeat(32)}`)).toThrow();
  });
});

/** A bootstrapped deployment: staff workspace, support identity and a signed-in admin. */
async function deployment(){
  const server=supportServer();
  const connect=(keys:MemberKeys,principalHash:Hex)=>new WorkspaceClient({apiServer:server.apiServer,realm:"support",keys,principalHash,principalToken:()=>server.principal(principalHash)});
  const ownerKeys=await member(0x41),ownerClient=connect(ownerKeys,hash(0x41));
  const staffId=await createTeamWorkspace(ownerClient,ownerKeys);
  const staff=await openStaffWorkspace({client:ownerClient,keys:ownerKeys,workspaceId:staffId});
  expect(await staff.identity()).toBeNull();
  const identity=await staff.bootstrapIdentity();
  server.configure(identity.root,staffId);
  const signIn=vi.fn(async(signer:AnonymousSigner)=>{
    // The API reports the principal hash without a 0x prefix.
    const principalHash=`${"00".repeat(12)}${signer.address.slice(2).toLowerCase()}`;
    return {principalHash,token:server.principal(`0x${principalHash}`)};
  });
  const admin=(from:StaffWorkspace=staff,current=identity)=>new SupportAdmin({apiServer:server.apiServer,staff:from,identity:current,signIn,staffLabel:"Sam",retryDelayMs:1});
  const user=async(n:number)=>{const keys=await member(n);return {keys,client:connect(keys,hash(n))};};
  return {server,connect,staff,staffId,identity,signIn,admin,user,ownerKeys};
}
const opened=(session:SupportSession|null):SupportSession=>{if(!session)throw new Error("expected a support session");return session;};

describe("support sessions",()=>{
  it("creates one workspace per user and grants the pinned support key write access only",async()=>{
    const f=await deployment(),u=await f.user(1);
    expect(await openSupportWorkspace({...u,root:f.identity.root,create:false})).toBeNull();
    expect(f.server.realms.support.size).toBe(1);
    const session=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
    expect(session.role).toBe("user");expect(session.tickets()).toEqual([]);
    const stored=f.server.workspace(session.workspaceId),support=stored.policy.members.find(m=>m.memberId===SUPPORT_MEMBER_ID)!;
    expect(stored.ops.map(op=>op.kind)).toEqual(["create","add_support_member"]);
    expect(f.server.requests.some(r=>r.method==="POST"&&r.path===`/support/workspaces/${session.workspaceId}/support-member`)).toBe(true);
    expect(f.server.requests.some(r=>r.path.endsWith("/policy/ops"))).toBe(false);
    expect(stored.policy.personal).toBe(false);expect(stored.policy.approvalThreshold).toBe(0);
    expect(support.caps).toBe(CAPS.WRITE);
    expect(support.keys).toEqual([{...f.identity.current,holdsAdmin:false,addedAtVersion:2,removedAtVersion:null}]);
    expect(f.server.realms.workspaces.size).toBe(0);
    // Discovery proofs are realm-bound; nothing is requested from the default realm's routes.
    expect(f.server.requests.some(r=>r.path==="/support/identity/challenge")).toBe(true);
    expect(f.server.requests.every(r=>r.path.startsWith("/support/"))).toBe(true);
    // The dedicated route is the only way in, and it carries nothing else.
    const provision=stored.ops[1],other=await f.user(2),second=opened(await openSupportWorkspace({...other,root:f.identity.root,create:true}));
    expect(()=>u.client.append(provision)).toThrow("Use addSupportMember");
    const rotation=f.server.workspace(second.workspaceId).ops[0];
    expect(()=>u.client.addSupportMember(rotation)).toThrow("Invalid support member operation");
    expect(()=>new WorkspaceClient({apiServer:f.server.apiServer,keys:u.keys,principalHash:hash(1),principalToken:()=>""}).addSupportMember(provision)).toThrow("Invalid support member operation");
    second.close();
    // Reopening discovers the same workspace instead of creating another.
    const again=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
    expect(again.workspaceId).toBe(session.workspaceId);expect(f.server.realms.support.size).toBe(3);
    await expect(openSupportWorkspace({keys:u.keys,client:new WorkspaceClient({apiServer:f.server.apiServer,keys:u.keys,principalHash:hash(1),principalToken:()=>""}),root:f.identity.root,create:true})).rejects.toThrow("support-realm");
  });
  it("finishes a workspace whose support grant never landed",async()=>{
    const f=await deployment(),u=await f.user(1);
    f.server.failOnce((method,path)=>method==="POST"&&path.endsWith("/support-member"));
    await expect(openSupportWorkspace({...u,root:f.identity.root,create:true})).rejects.toThrow();
    const [id]=[...f.server.realms.support.keys()].filter(key=>key!==f.staffId);
    expect(f.server.workspace(id).ops).toHaveLength(1);
    const session=opened(await openSupportWorkspace({...u,root:f.identity.root,create:false}));
    expect(session.workspaceId).toBe(id);expect(f.server.workspace(id).ops.map(op=>op.kind)).toEqual(["create","add_support_member"]);
  });
  it("refetches the rotation chain when the support key it used is stale",async()=>{
    const f=await deployment(),u=await f.user(1);
    const [old,next]=await Promise.all([supportIdentityKeys(f.identity,0),member(0x52,1)]);
    const pointer=createIdentityRotation(old,next,500);f.server.pointers.set(pointer.oldKey,pointer);
    f.server.serveStaleConfig(1);
    const session=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
    const support=f.server.workspace(session.workspaceId).policy.members.find(m=>m.memberId===SUPPORT_MEMBER_ID)!;
    expect(support.keys.map(key=>key.memberKeyId)).toEqual([next.memberKeyId]);expect(support.keys[0].generation).toBe(1);
    expect(f.server.requests.filter(r=>r.path==="/support/config")).toHaveLength(2);
    expect(f.server.requests.filter(r=>r.method==="POST"&&r.path.endsWith("/support-member"))).toHaveLength(2);
  });
  it("refuses a workspace whose support member is not in the pinned chain",async()=>{
    const f=await deployment(),u=await f.user(1),session=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
    const other=await member(0x77);
    await expect(openSupportWorkspace({...u,root:{rootKeyId:other.memberKeyId,rootKem:other.kemPublicKey},create:false})).rejects.toThrow("pinned key");
    // The server now presents a consistent chain for another root: the stored member key no longer descends from it.
    f.server.configure({rootKeyId:other.memberKeyId,rootKem:other.kemPublicKey},f.staffId);
    await expect(openSupportWorkspace({...u,root:{rootKeyId:other.memberKeyId,rootKem:other.kemPublicKey},create:false})).rejects.toThrow("not in the verified rotation chain");
    session.close();
  });
  it("derives message authorship from the verified policy, not from record contents",async()=>{
    const f=await deployment(),u=await f.user(1),admin=f.admin();
    const session=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
    const ticket=await session.createTicket({subject:"Stuck transfer",text:"It never arrived"});
    expect(ticket).toMatchObject({subject:"Stuck transfer",category:"support",status:"open",reportIds:[],revision:1,fromSupport:false});
    expect(session.messages(ticket.ticketId).map(m=>[m.text,m.fromSupport])).toEqual([["It never arrived",false]]);
    // A user cannot claim a staff label.
    const forged=await session.sendMessage(ticket.ticketId,"I am support",{staffLabel:"Mirage Staff"});
    expect(forged.fromSupport).toBe(false);expect(forged.staffLabel).toBeUndefined();

    const page=await admin.list();
    expect(page.workspaces).toMatchObject([{workspaceId:session.workspaceId,awaitingSupport:true,blocked:false,recordCount:3}]);
    const desk=await admin.open(session.workspaceId);
    expect(desk.role).toBe("support");
    expect(desk.tickets()).toMatchObject([{ticketId:ticket.ticketId,subject:"Stuck transfer",fromSupport:false}]);
    expect(desk.messages(ticket.ticketId).map(m=>m.fromSupport)).toEqual([false,false]);
    const answer=await desk.sendMessage(ticket.ticketId,"Looking into it");
    expect(answer).toMatchObject({fromSupport:true,staffLabel:"Sam",ticketId:ticket.ticketId});
    expect((await desk.sendMessage(ticket.ticketId,"Second",{staffLabel:"Ana"})).staffLabel).toBe("Ana");
    expect((await admin.list()).workspaces[0].awaitingSupport).toBe(false);

    expect(await session.sync()).toEqual({changed:true});
    expect(await session.sync()).toEqual({changed:false});
    const thread=session.messages(ticket.ticketId);
    expect(thread.map(m=>[m.text,m.fromSupport,m.staffLabel])).toEqual([["It never arrived",false,undefined],["I am support",false,undefined],["Looking into it",true,"Sam"],["Second",true,"Ana"]]);
    expect(thread[2].authorKeyId).toBe(f.identity.current.memberKeyId);
    // A user who writes the label straight into the encrypted body still is not support.
    const ring=new WorkspaceKeyring(session.workspaceId,u.keys,"support");await ring.load(await u.client.policy(session.workspaceId));
    await u.client.put(await ring.encryptRecord("support_message",{version:1,kind:"support_message",ticketId:ticket.ticketId,text:"Send your seed",sentAt:iso,staffLabel:"Mirage Staff"}),0);
    await session.sync();await desk.sync();
    for(const view of [session,desk])expect(view.messages(ticket.ticketId).at(-1)).toMatchObject({text:"Send your seed",fromSupport:false,authorKeyId:u.keys.memberKeyId});
    expect(session.messages(ticket.ticketId).at(-1)!.staffLabel).toBeUndefined();
    ring.close();admin.close();
  });
  it("does not treat a creator who names themselves the support member as support",async()=>{
    const f=await deployment(),u=await f.user(1);
    const session=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
    const ticket=await session.createTicket({subject:"s",text:"mine"});
    const policy=f.server.workspace(session.workspaceId).policy;
    // Swap the ids in the session's view: the caller's own member is never the support member.
    (session as unknown as {policy:typeof policy}).policy={...policy,members:[{...policy.members[0],memberId:SUPPORT_MEMBER_ID},{...policy.members[1],memberId:policy.members[0].memberId}]};
    expect(session.messages(ticket.ticketId)[0].fromSupport).toBe(false);
  });
  it("lets either side close and reopen a ticket and records who closed it",async()=>{
    const f=await deployment(),u=await f.user(1),admin=f.admin();
    const session=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
    const ticket=await session.createTicket({subject:"Question",text:"Hi"});
    const desk=await admin.open(session.workspaceId);
    await desk.closeTicket(ticket.ticketId);
    expect(desk.tickets()[0]).toMatchObject({status:"closed",closedBy:"support",revision:2,fromSupport:true});
    // The user's cached revision is stale; the revision is re-read before writing.
    await session.reopenTicket(ticket.ticketId);
    expect(session.tickets()[0]).toMatchObject({status:"open",revision:3,fromSupport:false});
    expect(session.tickets()[0]).not.toHaveProperty("closedAt");expect(session.tickets()[0]).not.toHaveProperty("closedBy");
    await session.reopenTicket(ticket.ticketId);expect(session.tickets()[0].revision).toBe(3);
    await session.closeTicket(ticket.ticketId);
    expect(session.tickets()[0]).toMatchObject({status:"closed",closedBy:"user",revision:4});
    await desk.sync();expect(desk.tickets()[0]).toMatchObject({status:"closed",closedBy:"user"});
    await expect(session.sendMessage(hash(0x99),"nowhere")).rejects.toThrow("Unknown support ticket");
    await expect(session.createTicket({subject:"",text:"x"})).rejects.toThrow("Invalid support ticket");
    await expect(session.createTicket({subject:"ok",text:""})).rejects.toThrow("Invalid support message");
    expect(session.tickets()).toHaveLength(1);admin.close();
  });
  it("submits allowlisted reports, links them to tickets and erases them with a tombstone",async()=>{
    const f=await deployment(),u=await f.user(1),admin=f.admin();
    const session=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
    const input=buildSupportReport({status:"failed",chainId:1,blindingScalar:"0xscalar",seed:"0xseed",mnemonic:"never"},{message:"reverted",step:"deploy"},{clientVersion:"1.0.0",userAgent:"vitest"});
    const feedback=await session.submitFeedback("A suggestion");
    const report=await session.submitReport({...input,note:"My note",transaction:{...input.transaction,smuggled:"x"}});
    expect(report.transaction).toEqual({status:"failed",chainId:1,blindingScalar:"0xscalar",seed:"0xseed"});
    expect(report).toMatchObject({error:{message:"reverted",step:"deploy"},clientVersion:"1.0.0",fromSupport:false});expect(report.ticketId).toBeUndefined();
    const ticket=await session.createTicket({subject:"Deploy failed",text:"See report",reportId:report.reportId});
    expect(ticket.reportIds).toEqual([report.reportId]);
    const second=await session.submitReport(input,ticket.ticketId);
    expect(second.ticketId).toBe(ticket.ticketId);
    expect(session.tickets()[0].reportIds).toEqual([report.reportId,second.reportId]);
    await expect(session.submitReport(input,hash(0x98))).rejects.toThrow("Unknown support ticket");
    await expect(session.submitReport({...input,transaction:{sealedPricingAuthorization:"x".repeat(130_000),seed:"y".repeat(130_000)}})).rejects.toThrow("too large");

    const desk=await admin.open(session.workspaceId);
    expect(desk.feedback()).toEqual([feedback]);
    expect(desk.reports().find(r=>r.reportId===report.reportId)?.note).toBe("My note");
    expect(desk.reports().map(r=>r.reportId).sort()).toEqual([report.reportId,second.reportId].sort());
    expect(desk.reports().find(r=>r.reportId===report.reportId)!.transaction.blindingScalar).toBe("0xscalar");

    await session.deleteRecord("support_report",report.reportId);
    expect(session.reports().map(r=>r.reportId)).toEqual([second.reportId]);
    const row=f.server.workspace(session.workspaceId).records.get(report.reportId)!;
    expect(row.record.revision).toBe(2);
    const ring=new WorkspaceKeyring(session.workspaceId,u.keys,"support");await ring.load(await u.client.policy(session.workspaceId));
    expect(await ring.decryptRecord(row.record)).toEqual({version:1,kind:"support_report",deleted:true});
    await session.deleteRecord("support_report",report.reportId);expect(row.record.revision).toBe(2);
    await expect(session.deleteRecord("support_ticket",second.reportId)).rejects.toThrow("different type");
    expect(await desk.sync()).toEqual({changed:true});expect(desk.reports().map(r=>r.reportId)).toEqual([second.reportId]);
    // A message's second revision is its tombstone; any other second revision is hidden.
    const [first]=session.messages(ticket.ticketId),extra=await session.sendMessage(ticket.ticketId,"typo");
    await session.deleteRecord("support_message",extra.messageId);
    expect(session.messages(ticket.ticketId).map(m=>m.messageId)).toEqual([first.messageId]);
    await u.client.put(await ring.encryptRecord("support_message",{version:1,kind:"support_message",ticketId:ticket.ticketId,text:"rewritten",sentAt:iso},first.messageId,2),1);
    await session.sync();await desk.sync();
    expect(session.messages(ticket.ticketId)).toEqual([]);expect(desk.messages(ticket.ticketId)).toEqual([]);
    await session.deleteRecord("support_ticket",ticket.ticketId);
    expect(session.tickets()).toEqual([]);
    await expect(session.closeTicket(ticket.ticketId)).rejects.toThrow("deleted");
    ring.close();admin.close();
  });
  it("blocks and unblocks through the staff session",async()=>{
    const f=await deployment(),u=await f.user(1),admin=f.admin();
    const session=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
    await admin.block(session.workspaceId);
    expect((await admin.list()).workspaces[0].blocked).toBe(true);
    await expect(session.createTicket({subject:"s",text:"t"})).rejects.toMatchObject({statusCode:403});
    await admin.unblock(session.workspaceId);
    expect((await session.createTicket({subject:"s",text:"t"})).status).toBe("open");
    expect(f.server.requests.some(r=>r.method==="DELETE"&&r.path===`/support/admin/workspaces/${session.workspaceId}/block`)).toBe(true);
    // A user client holds no staff session.
    await expect(u.client.supportAdmin(f.staffId,"/workspaces")).rejects.toMatchObject({statusCode:403});
  });
});

describe("staff workspace",()=>{
  it("bootstraps one random generation-0 identity and reports its root keys",async()=>{
    const f=await deployment();
    expect(f.identity.generations).toHaveLength(1);expect(f.identity.pendingRotation).toBeNull();
    const signer=anonymousSignerFromPrivateKey(f.identity.generations[0].privateKey),keys=await unlockMember(signer,0);
    expect(f.identity.generations[0].address).toBe(signer.address.toLowerCase());
    expect(f.identity.root).toEqual({rootKeyId:keys.memberKeyId,rootKem:keys.kemPublicKey});
    expect(f.identity.current).toEqual({memberKeyId:keys.memberKeyId,kemPublicKey:keys.kemPublicKey,generation:0});
    expect(await f.staff.bootstrapIdentity()).toEqual(f.identity);
    expect(await f.staff.identity()).toEqual(f.identity);
    expect(f.server.workspace(f.staffId).records.size).toBe(1);
    expect(await fetchSupportConfig(f.server.apiServer,f.identity.root)).toMatchObject({staffWorkspaceId:f.staffId,current:f.identity.current,rotations:[]});
    // Without an explicit id the staff workspace comes from the API's support config.
    const located=await openStaffWorkspace({client:f.connect(f.ownerKeys,hash(0x41)),keys:f.ownerKeys});
    expect(located.workspaceId).toBe(f.staffId);expect(located.isOwner).toBe(true);
  });
  it("invites, labels and removes staff through the existing invitation flow",async()=>{
    const f=await deployment(),staffer=await f.user(0x42);
    const invite=await f.staff.invite({label:"Ana"});
    const joined=await acceptWorkspaceInvite(staffer.client,staffer.keys,invite.grantId,invite.secret);
    expect(joined.status).toBe("joined");
    const desk=await openStaffWorkspace({client:staffer.client,keys:staffer.keys,workspaceId:f.staffId});
    expect(desk.isOwner).toBe(false);
    expect(await desk.identity()).toEqual(f.identity);
    await expect(desk.bootstrapIdentity()).resolves.toEqual(f.identity);
    await expect(desk.beginRotation()).rejects.toThrow();
    let members=await f.staff.members();
    expect(members).toHaveLength(2);
    expect(members.find(m=>m.self)).toMatchObject({memberId:f.staff.memberId,isOwner:true,caps:15});
    expect(members.find(m=>!m.self)).toMatchObject({memberId:desk.memberId,isOwner:false,caps:CAPS.WRITE,label:"Ana"});
    await f.staff.setLabel(desk.memberId,"Ana B");await f.staff.setLabel(f.staff.memberId,"Owner");
    members=await f.staff.members();
    expect(members.map(m=>m.label).sort()).toEqual(["Ana B","Owner"]);
    expect([...f.server.workspace(f.staffId).records.values()].filter(row=>row.record.type==="roster")).toHaveLength(1);
    // The staffer can act as the support identity while a member.
    const admin=f.admin(desk);expect((await admin.list()).workspaces).toEqual([]);
    await f.staff.removeMember(desk.memberId);
    expect((await f.staff.members()).map(m=>m.memberId)).toEqual([f.staff.memberId]);
    await expect(admin.list()).rejects.toThrow();
    await expect(desk.identity()).rejects.toThrow();
    admin.close();
  });
});

describe("support key rotation",{timeout:30_000},()=>{
  async function conversations(){
    const f=await deployment(),admin=f.admin(),sessions:SupportSession[]=[],tickets:Hex[]=[];
    for(const n of [1,2,3]){
      const u=await f.user(n),session=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
      const ticket=await session.createTicket({subject:`Ticket ${n}`,text:`from ${n}`});
      await (await admin.open(session.workspaceId)).sendMessage(ticket.ticketId,`reply ${n}`);
      sessions.push(session);tickets.push(ticket.ticketId);
    }
    return {...f,adminBefore:admin,sessions,tickets};
  }
  it("rotates every user workspace to a fresh key and keeps history readable",async()=>{
    const f=await conversations(),progress:[number,number][]=[];
    expect(await f.adminBefore.pendingRotation()).toBeNull();
    await f.adminBefore.rotateSupportKey((done,total)=>progress.push([done,total]));
    expect(progress).toEqual([[0,3],[1,3],[2,3],[3,3]]);
    const identity=(await f.staff.identity())!;
    expect(identity.generations).toHaveLength(2);expect(identity.pendingRotation).toBeNull();
    expect(identity.generations[1].privateKey).not.toBe(identity.generations[0].privateKey);
    expect(identity.root).toEqual(f.identity.root);expect(identity.current.generation).toBe(1);
    const config=await fetchSupportConfig(f.server.apiServer,f.identity.root,{minGeneration:1});
    expect(config.current).toEqual(identity.current);expect(config.rotations).toHaveLength(1);
    for(const session of f.sessions){
      const policy=f.server.workspace(session.workspaceId).policy,support=policy.members.find(m=>m.memberId===SUPPORT_MEMBER_ID)!;
      expect(support.keys.map(key=>[key.generation,key.removedAtVersion===null])).toEqual([[0,false],[1,true]]);
      expect(currentMemberKey(policy,f.identity.current.memberKeyId)).toBeUndefined();
      expect(policy.keyEpoch).toBe(2);expect(f.server.workspace(session.workspaceId).ops.at(-1)!.adminSignature).toBeNull();
    }
    // The retired key can no longer open a session; the new one reads old and new content.
    await expect(f.admin().open(f.sessions[0].workspaceId)).rejects.toThrow("not a member");
    const admin=f.admin(f.staff,identity),desk=await admin.open(f.sessions[0].workspaceId);
    expect(desk.messages(f.tickets[0]).map(m=>[m.text,m.fromSupport])).toEqual([["from 1",false],["reply 1",true]]);
    await desk.sendMessage(f.tickets[0],"after rotation");
    // Users need to do nothing: replies from both generations are still from support.
    await f.sessions[0].sync();
    expect(f.sessions[0].messages(f.tickets[0]).map(m=>[m.text,m.fromSupport])).toEqual([["from 1",false],["reply 1",true],["after rotation",true]]);
    const later=await f.sessions[0].sendMessage(f.tickets[0],"thanks");expect(later.fromSupport).toBe(false);
    expect(f.server.workspace(f.sessions[0].workspaceId).records.get(later.messageId)!.record.keyEpoch).toBe(2);
    // A new user is provisioned with the new generation.
    const u=await f.user(9),fresh=opened(await openSupportWorkspace({...u,root:f.identity.root,create:true}));
    expect(f.server.workspace(fresh.workspaceId).policy.members[1].keys[0].memberKeyId).toBe(identity.current.memberKeyId);
    admin.close();f.adminBefore.close();
  });
  it("resumes an interrupted batch without minting another key or re-registering",async()=>{
    const f=await conversations();
    let appends=0;
    f.server.failOnce((method,path)=>method==="POST"&&path.endsWith("/policy/ops")&&++appends===2);
    await expect(f.adminBefore.rotateSupportKey()).rejects.toMatchObject({statusCode:500});
    const pending=(await f.staff.identity())!;
    expect(pending.generations).toHaveLength(2);expect(pending.pendingRotation).toBe(1);
    expect(await f.adminBefore.pendingRotation()).toEqual({generation:1});
    const rotated=()=>f.sessions.filter(session=>f.server.workspace(session.workspaceId).policy.keyEpoch===2).length;
    expect(rotated()).toBe(1);expect(f.server.pointers.size).toBe(1);
    // Both generations stay usable until the batch finishes.
    const during=f.admin(f.staff,pending);
    for(const session of f.sessions)expect((await during.open(session.workspaceId)).role).toBe("support");
    during.close();
    const progress:[number,number][]=[];
    const resumed=f.admin(f.staff,pending);await resumed.rotateSupportKey((done,total)=>progress.push([done,total]));
    expect(progress.at(-1)).toEqual([3,3]);expect(rotated()).toBe(3);
    const identity=(await f.staff.identity())!;
    expect(identity.generations).toEqual(pending.generations);expect(identity.pendingRotation).toBeNull();
    expect(f.server.pointers.size).toBe(1);
    expect(f.server.requests.filter(r=>r.method==="POST"&&r.path==="/identity/rotations")).toHaveLength(1);
    for(const session of f.sessions)expect(f.server.workspace(session.workspaceId).ops.filter(op=>op.kind==="rotate_member")).toHaveLength(1);
    expect(await resumed.pendingRotation()).toBeNull();
    // The next rotation starts a new generation.
    await f.admin(f.staff,identity).rotateSupportKey();
    expect((await f.staff.identity())!.generations).toHaveLength(3);
    expect((await fetchSupportConfig(f.server.apiServer,f.identity.root)).current.generation).toBe(2);
    resumed.close();f.adminBefore.close();
  });
  it("waits out rate limits and skips workspaces the support member has left",async()=>{
    const f=await conversations(),u=await f.user(2);
    // The second user removes support from their own workspace.
    const ring=new WorkspaceKeyring(f.sessions[1].workspaceId,u.keys,"support");await ring.load(await u.client.policy(f.sessions[1].workspaceId));
    await u.client.append(await ring.prepareRemoveMember(SUPPORT_MEMBER_ID));ring.close();
    f.server.failOnce((method,path)=>method==="POST"&&path.endsWith("/policy/ops"),429);
    // A blocked workspace still accepts the support member's own rotation.
    await f.adminBefore.block(f.sessions[2].workspaceId);
    const progress:number[]=[];
    await f.adminBefore.rotateSupportKey(done=>progress.push(done));
    expect(progress).toEqual([0,1,2,3]);
    expect(f.sessions.map(session=>f.server.workspace(session.workspaceId).ops.some(op=>op.kind==="rotate_member"))).toEqual([true,false,true]);
    expect((await f.staff.identity())!.pendingRotation).toBeNull();
    await expect(openSupportWorkspace({...u,root:f.identity.root,create:false})).rejects.toThrow("removed");
    f.adminBefore.close();
  });
});
