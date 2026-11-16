import {describe,it,expect} from "vitest";
import {privateKeyToAccount} from "viem/accounts";
import vectors from "./fixtures/workspaces.json";
import {WorkspaceKeyring} from "../src/workspaces/personal";
import {unlockMember} from "../src/workspaces/keys";
import {createIdentityRotation} from "../src/workspaces/identity";
import {applyPolicyOp,replayPolicy,type PolicyOp} from "../src/workspaces/policy";
const member=(n:number,generation=0)=>unlockMember(privateKeyToAccount(`0x${n.toString().padStart(2,"0").repeat(32)}`),generation);
const response=()=>{const ops=structuredClone(vectors.policy.ops.slice(0,2)) as PolicyOp[];return {ops,policy:replayPolicy(ops)};};
describe("workspace key management",()=>{
  it("revokes a linked owner and seals fresh content/admin keys only to retained keys",async()=>{
    const a=await member(1),b=await member(2),before=response();
    const ring=new WorkspaceKeyring(before.policy.workspaceId,a);const old=(await ring.load(before)).get(1)!;
    const op=await ring.prepareRemoveKey(b.memberKeyId);expect(op!.kind).toBe("unlink_key");expect(op!.adminSignature).not.toBeNull();
    const next={ops:[...before.ops,op!],policy:applyPolicyOp(before.policy,op!)};
    expect(next.policy.adminPublicKey).not.toBe(before.policy.adminPublicKey);expect(next.policy.adminEpoch).toBe(2);
    expect(next.policy.envelopes.filter(e=>e.epoch===2).every(e=>e.recipientKeyId===a.memberKeyId)).toBe(true);
    const content=await ring.load(next);expect(content.get(1)).toBe(old);expect(content.get(2)).not.toEqual(old);
    expect(await ring.prepareRemoveKey(b.memberKeyId)).toBeNull();await expect(ring.prepareRemoveKey(a.memberKeyId)).rejects.toThrow("remaining sign-in");ring.close();
  });
  it("a replacement generation decrypts retained history and fresh owner authority",async()=>{
    const a=await member(1),nextKey=await member(1,1),before=response();
    const ring=new WorkspaceKeyring(before.policy.workspaceId,a);const historical=(await ring.load(before)).get(1)!;
    const pointer=createIdentityRotation(a,nextKey,Math.floor(Date.now()/1000));
    const op=await ring.prepareMemberRotation(nextKey,pointer);expect(op.kind).toBe("rotate_member");
    if(op.kind!=="rotate_member")throw new Error("operation");expect(op.payload.pointer).toEqual(pointer);
    const next={ops:[...before.ops,op],policy:applyPolicyOp(before.policy,op)};
    const replacement=new WorkspaceKeyring(before.policy.workspaceId,nextKey);const content=await replacement.load(next);
    expect(content.get(1)).toEqual(historical);expect(content.get(2)).not.toEqual(historical);
    expect(next.policy.envelopes.filter(e=>e.epoch===2).every(e=>e.recipientKeyId!==a.memberKeyId)).toBe(true);
    await expect(ring.load(next)).rejects.toThrow("revoked");
    expect(historical.every(byte=>byte===0)).toBe(true);
    const remove=await replacement.prepareRemoveKey((await member(2)).memberKeyId);expect(remove!.adminSignature).not.toBeNull();replacement.close();
  });
  it("refuses a pointer for another sign-in or an incorrect generation",async()=>{
    const a=await member(1),next=await member(1,1),b=await member(2),bNext=await member(2,1),before=response();
    const ring=new WorkspaceKeyring(before.policy.workspaceId,a);await ring.load(before);
    await expect(ring.prepareMemberRotation(next,createIdentityRotation(b,bNext,1234))).rejects.toThrow("does not match");
    await expect(ring.prepareMemberRotation(await member(1,2))).rejects.toThrow("increment");ring.close();
  });
});
