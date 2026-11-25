import {describe,expect,it} from "vitest";
import type {Hex} from "viem";
import vectors from "./fixtures/workspaces.json";
import {openKey} from "../src/workspaces/hpke";
import {deriveMemberKeys,type MemberKeys} from "../src/workspaces/keys";
import {WorkspaceKeyring} from "../src/workspaces/personal";
import {CAPS,SUPPORT_MEMBER_ID,applyPolicyOp,currentMemberKey,policyAuthorCheck,policyOpHash,replayPolicy,signPolicyOp,type Policy,type PolicyOp} from "../src/workspaces/policy";

type SupportOp=Extract<PolicyOp,{kind:"add_support_member"}>;
const support=vectors.support,cases=support.addSupportMember;
const ops=()=>structuredClone(cases.ops) as PolicyOp[];
const state=(n:number)=>replayPolicy(ops().slice(0,n),"support");
const owner=()=>deriveMemberKeys(vectors.unlock[0].signature as Hex);
const admin=()=>new Uint8Array(32).fill(10);
const supportKey=(n:number)=>({memberKeyId:support.keys[n].memberKeyId as Hex,kemPublicKey:support.keys[n].kemPublicKey as Hex,generation:support.keys[n].generation});
const supportKeys=(n:number):MemberKeys=>({...supportKey(n),signingSeed:Uint8Array.from(Buffer.from(support.keys[n].signingSeed.slice(2),"hex")),kemSecret:Uint8Array.from(Buffer.from(support.keys[n].kemSecret.slice(2),"hex"))});
/** Re-signs a mutated copy of the vector's add_support_member as the workspace owner. */
function resigned(mutate:(op:SupportOp)=>void):PolicyOp {
  const op=ops()[2] as SupportOp;mutate(op);
  return signPolicyOp(op,owner(),admin());
}

describe("support realm add_support_member",()=>{
  it("matches the shared vectors for every hash and resulting state",()=>{
    expect(support.realm).toBe("support");expect(support.memberId).toBe(SUPPORT_MEMBER_ID);
    expect(ops().map(op=>op.kind)).toEqual(["create","rotate_content","add_support_member","rotate_member"]);
    let previous:Policy|null=null;
    for(const [index,op] of ops().entries()){
      expect(policyOpHash(op)).toBe(cases.hashes[index]);
      previous=applyPolicyOp(previous,op,"support");
      expect(previous).toEqual(cases.states[index]);
    }
    const added=previous!.members.find(member=>member.memberId===SUPPORT_MEMBER_ID)!;
    expect(added.caps).toBe(CAPS.WRITE);expect(added.keys.every(key=>!key.holdsAdmin)).toBe(true);
    expect(currentMemberKey(previous!,supportKey(1).memberKeyId)).toBeDefined();
    expect(currentMemberKey(previous!,supportKey(0).memberKeyId)).toBeUndefined();
  });
  it("is rejected in the workspaces realm, which stays the default",()=>{
    expect(()=>applyPolicyOp(state(2),ops()[2])).toThrow("support realm");
    expect(()=>applyPolicyOp(state(2),ops()[2],"workspaces")).toThrow("support realm");
    expect(()=>replayPolicy(ops())).toThrow("support realm");
    expect(()=>policyAuthorCheck(ops())).toThrow("support realm");
    expect(replayPolicy(ops().slice(0,2))).toEqual(state(2));
  });
  it("rejects every shared negative vector in both realms",()=>{
    expect(cases.rejected.length).toBeGreaterThan(0);
    for(const vector of cases.rejected){
      const before=state(vector.after),snapshot=structuredClone(before);
      expect(()=>applyPolicyOp(before,structuredClone(vector.op) as unknown as PolicyOp,"support"),vector.name).toThrow();
      expect(()=>applyPolicyOp(before,structuredClone(vector.op) as unknown as PolicyOp,"workspaces"),vector.name).toThrow();
      expect(before,vector.name).toEqual(snapshot);
    }
  });
  it("keeps add_member as invite acceptance only",()=>{
    // The former direct payload under the old kind is no longer a valid operation in any realm.
    const direct={...ops()[2],kind:"add_member",payload:{memberId:SUPPORT_MEMBER_ID,key:supportKey(0),caps:8,envelopes:(ops()[2] as SupportOp).payload.envelopes}} as unknown as PolicyOp;
    const signed=signPolicyOp(direct,owner(),admin());
    for(const realm of ["support","workspaces"] as const)expect(()=>applyPolicyOp(state(2),signed,realm)).toThrow("unexpected or missing fields");
  });
  it("requires the owner, the admin co-signature and an untampered payload",()=>{
    const before=state(2);
    const unsigned=ops()[2];unsigned.adminSignature=null;
    expect(()=>applyPolicyOp(before,unsigned,"support")).toThrow("admin signature");
    expect(()=>applyPolicyOp(before,signPolicyOp(ops()[2],owner(),new Uint8Array(32).fill(99)),"support")).toThrow("admin signature");
    const tampered=ops()[2] as SupportOp;tampered.payload.key.generation=7;
    expect(()=>applyPolicyOp(before,tampered,"support")).toThrow("actor signature");
    expect(()=>applyPolicyOp(state(1),ops()[2],"support")).toThrow("head");
    // The support member itself holds no owner authority, even with a valid admin signature.
    const outsider={...ops()[2],policyVersion:4,prevOpHash:state(3).headHash,signerKeyId:supportKey(0).memberKeyId,payload:{...(ops()[2] as SupportOp).payload,key:supportKey(1)}} as PolicyOp;
    expect(()=>applyPolicyOp(state(3),signPolicyOp(outsider,supportKeys(0),admin()),"support")).toThrow("owner and admin");
  });
  it("rejects caller-chosen ids or capabilities, reused keys and wrong envelope sets",()=>{
    const before=state(2),creator=before.members[0];
    for(const [name,mutate] of [
      ["caller-chosen caps",op=>{(op.payload as unknown as Record<string,unknown>).caps=15;}],
      ["caller-chosen member id",op=>{(op.payload as unknown as Record<string,unknown>).memberId=`0x${"77".repeat(16)}`;}],
      ["owner flag",op=>{(op.payload as unknown as Record<string,unknown>).holdsAdmin=true;}],
      ["missing field",op=>{delete (op.payload as Partial<SupportOp["payload"]>).envelopes;}],
      ["reused key",op=>{op.payload.key={memberKeyId:creator.keys[0].memberKeyId,kemPublicKey:creator.keys[0].kemPublicKey,generation:0};}],
      ["missing epoch",op=>{op.payload.envelopes.pop();}],
      ["duplicate envelope",op=>{op.payload.envelopes[1]=op.payload.envelopes[0];}],
      ["admin envelope",op=>{op.payload.envelopes[0]={...op.payload.envelopes[0],kind:"admin"};}],
      ["foreign recipient",op=>{op.payload.envelopes[0]={...op.payload.envelopes[0],recipientKeyId:creator.keys[0].memberKeyId};}],
      ["bad generation",op=>{op.payload.key.generation=-1;}],
    ] as [string,(op:SupportOp)=>void][]){
      expect(()=>applyPolicyOp(before,resigned(mutate),"support"),name).toThrow();
    }
    expect(applyPolicyOp(before,resigned(()=>undefined),"support").members).toHaveLength(2);
    // Once added, the support member id is taken for good.
    const again={...ops()[2],policyVersion:4,prevOpHash:state(3).headHash,payload:{...(ops()[2] as SupportOp).payload,key:supportKey(1)}} as PolicyOp;
    expect(()=>applyPolicyOp(state(3),signPolicyOp(again,owner(),admin()),"support")).toThrow("already appeared");
  });
  it("leaves the content key, admin key and threshold untouched",()=>{
    const before=state(2),after=state(3);
    for(const field of ["keyEpoch","adminEpoch","adminPublicKey","approvalThreshold","pendingThreshold"] as const)expect(after[field]).toBe(before[field]);
    expect(after.envelopes.slice(0,before.envelopes.length)).toEqual(before.envelopes);
    expect(after.envelopes.slice(before.envelopes.length).map(envelope=>`${envelope.recipientKeyId}:${envelope.kind}:${envelope.epoch}`).sort())
      .toEqual([1,2].map(epoch=>`${supportKey(0).memberKeyId}:content:${epoch}`));
  });
});

describe("keyring support member preparation",()=>{
  it("seals every content epoch the signer holds to the support key",async()=>{
    const before={ops:ops().slice(0,2),policy:state(2)},ring=new WorkspaceKeyring(before.policy.workspaceId,owner(),"support");
    const content=await ring.load(before);
    const op=await ring.prepareAddSupportMember(supportKey(0));
    if(op.kind!=="add_support_member")throw new Error("fixture");
    expect(op.adminSignature).not.toBeNull();
    const after=applyPolicyOp(before.policy,op,"support");
    expect(Object.keys(op.payload).sort()).toEqual(["envelopes","key"]);
    expect(op.payload.envelopes.map(envelope=>envelope.epoch).sort()).toEqual([1,2]);
    for(const envelope of op.payload.envelopes)
      expect(await openKey(envelope,{...envelope,recipientKeyId:supportKey(0).memberKeyId},supportKeys(0).kemSecret)).toEqual(content.get(envelope.epoch));
    expect(after.members[1]).toMatchObject({memberId:SUPPORT_MEMBER_ID,caps:CAPS.WRITE});
    const granted=new WorkspaceKeyring(before.policy.workspaceId,supportKeys(0),"support");
    expect((await granted.load({ops:[...before.ops,op],policy:after})).size).toBe(2);
    await ring.load({ops:[...before.ops,op],policy:after});
    await expect(ring.prepareAddSupportMember(supportKey(1))).rejects.toThrow("already appeared");
    ring.close();granted.close();
  });
  it("refuses to sign outside the support realm and without owner authority",async()=>{
    const before={ops:ops().slice(0,2),policy:state(2)},ring=new WorkspaceKeyring(before.policy.workspaceId,owner());
    await ring.load(before);
    await expect(ring.prepareAddSupportMember(supportKey(0))).rejects.toThrow("support realm");
    ring.close();
    const all={ops:ops(),policy:state(4)},member=new WorkspaceKeyring(all.policy.workspaceId,supportKeys(1),"support");
    await member.load(all);
    await expect(member.prepareAddSupportMember(supportKey(0))).rejects.toThrow("admin authority");
    await expect(new WorkspaceKeyring(all.policy.workspaceId,supportKeys(1)).load(all)).rejects.toThrow("support realm");
    member.close();
  });
});
