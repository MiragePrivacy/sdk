import {describe,it,expect} from "vitest";
import type {Hex} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import vectors from "./fixtures/workspaces.json";
import {linkedKeyBranches,unlinkHash,verifyIdentityUnlink,createIdentityUnlink,type IdentityLinkState,type SignedIdentityUnlink} from "../src/workspaces/identity";
import {unlockMember} from "../src/workspaces/keys";
import {WorkspaceKeyring} from "../src/workspaces/personal";
import {sealKey} from "../src/workspaces/hpke";
import {replayPolicy,signPolicyOp,applyPolicyOp,type PolicyOp} from "../src/workspaces/policy";
const state=():IdentityLinkState=>({link:structuredClone(vectors.policy.ops[1].payload.link),unlinking:false,rotations:[structuredClone(vectors.policy.ops[8].payload.pointer)],workspaceIds:[vectors.policy.ops[0].workspaceId]}) as IdentityLinkState;
describe("identity link lifecycle",()=>{
  it("matches the Rust unlink commitment and binds both branches and the exact link",()=>{
    const proof=vectors.identityLifecycle.unlink as SignedIdentityUnlink;
    expect(unlinkHash(proof)).toBe(vectors.identityLifecycle.unlinkHash);expect(verifyIdentityUnlink(proof)).toBe(true);
    for(const change of [{linkId:`0x${"99".repeat(32)}`},{remainingKey:proof.revokedKey},{revokedKey:`0x${"99".repeat(32)}`},{issuedAt:proof.issuedAt+1}])expect(verifyIdentityUnlink({...proof,...change} as SignedIdentityUnlink)).toBe(false);
  });
  it("verifies replacement generations in a linked sign-in without merging the branches",async()=>{
    const linked=state(),branches=linkedKeyBranches(linked),replacement=await unlockMember(privateKeyToAccount(`0x${"02".repeat(32)}`),1);
    expect(branches.some(branch=>branch.get(replacement.memberKeyId)===replacement.kemPublicKey)).toBe(true);
    const proof=createIdentityUnlink(vectors.identityLifecycle.unlink.linkId as Hex,vectors.policy.ops[0].signerKeyId as Hex,replacement,1234);
    expect(verifyIdentityUnlink(proof)).toBe(true);
    linked.rotations.push(linked.rotations[0]);expect(()=>linkedKeyBranches(linked)).toThrow("rotation");
    const tampered=state();tampered.rotations[0].newKem=`0x${"99".repeat(32)}`;expect(()=>linkedKeyBranches(tampered)).toThrow("rotation");
  });
  it("opens history for a linked replacement and rejects its obsolete generation",async()=>{
    const a=await unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`)),b=await unlockMember(privateKeyToAccount(`0x${"02".repeat(32)}`),1);
    const ops=vectors.identityLifecycle.secondWorkspace as PolicyOp[];
    const creator=new WorkspaceKeyring(ops[0].workspaceId,a);await creator.load({ops:ops.slice(0,1),policy:replayPolicy(ops.slice(0,1))});
    await expect(creator.prepareLinkedKey(state(),await unlockMember(privateKeyToAccount(`0x${"02".repeat(32)}`)))).rejects.toThrow("current workspace sign-ins");
    const member=new WorkspaceKeyring(ops[0].workspaceId,b);
    const keys=await member.load({ops:ops.slice(0,2),policy:replayPolicy(ops.slice(0,2))});expect(keys.get(1)).toEqual(new Uint8Array(32).fill(43));
    const updated=await member.load({ops,policy:replayPolicy(ops)});expect(updated.get(2)).toEqual(new Uint8Array(32).fill(45));
    creator.close();member.close();
  });
  it("lets a rotated signer enroll the other identity from the original cross-signed link",async()=>{
    const a=await unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`)),b=await unlockMember(privateKeyToAccount(`0x${"02".repeat(32)}`),1);
    const create=structuredClone(vectors.policy.ops[0]) as PolicyOp;
    if(create.kind!=="create")throw new Error("fixture");
    create.signerKeyId=b.memberKeyId;create.payload.key={memberKeyId:b.memberKeyId,kemPublicKey:b.kemPublicKey,generation:1};
    create.payload.envelopes=await Promise.all([
      sealKey({workspaceId:create.workspaceId,kind:"content",epoch:1},b.memberKeyId,b.kemPublicKey,new Uint8Array(32).fill(43)),
      sealKey({workspaceId:create.workspaceId,kind:"admin",epoch:1},b.memberKeyId,b.kemPublicKey,new Uint8Array(32).fill(10)),
    ]);
    const first=signPolicyOp(create,b,new Uint8Array(32).fill(10)),policy=replayPolicy([first]);
    const ring=new WorkspaceKeyring(create.workspaceId,b);await ring.load({ops:[first],policy});
    const op=await ring.prepareLinkedKey(state(),a);expect(op!.signerKeyId).toBe(b.memberKeyId);
    const after=applyPolicyOp(policy,op!);expect(after.members[0].keys.some(key=>key.memberKeyId===a.memberKeyId)).toBe(true);ring.close();
  });
  it("replays independent multi-workspace enrollment and revocation vectors",()=>{
    for(const ops of [vectors.identityLifecycle.secondWorkspace,vectors.identityLifecycle.thirdWorkspace]){
      const before=replayPolicy(ops.slice(0,2) as PolicyOp[]),after=replayPolicy(ops as PolicyOp[]);
      expect(before.members[0].keys.filter(k=>k.removedAtVersion===null)).toHaveLength(2);
      expect(after.members[0].keys.filter(k=>k.removedAtVersion===null)).toHaveLength(1);expect(after.keyEpoch).toBe(2);expect(after.adminEpoch).toBe(2);
    }
  });
});
