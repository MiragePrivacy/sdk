import {describe,it,expect,vi} from "vitest";
import {privateKeyToAccount} from "viem/accounts";
import type {Hex} from "viem";
import {ApiError} from "../src/errors";
import {unlockMember,type MemberKeys} from "../src/workspaces/keys";
import {unlinkOtherIdentity,linkIdentities,replaceIdentity} from "../src/workspaces/management";
import {findOrCreatePersonalWorkspaces,WorkspaceKeyring} from "../src/workspaces/personal";
import {currentMemberKey} from "../src/workspaces/policy";
import {createIdentityLink,type SignedIdentityLink,type SignedIdentityRotation} from "../src/workspaces/identity";
import {applyPolicyOp,replayPolicy,type PolicyOp} from "../src/workspaces/policy";
import type {WorkspaceClient,PolicyResponse} from "../src/workspaces/client";
import type {IdentityLinkState} from "../src/workspaces/identity";
import vectors from "./fixtures/workspaces.json";
async function setup(){
  const keys=await unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`));
  let ops=structuredClone(vectors.policy.ops.slice(0,2)) as PolicyOp[],policy=replayPolicy(ops),deleted=false,frozen=false;
  const peer=policy.members[0].keys.find(key=>key.memberKeyId!==keys.memberKeyId)!.memberKeyId;
  const link={link:vectors.policy.ops[1].payload.link,rotations:[],workspaceIds:[policy.workspaceId]} as Omit<IdentityLinkState,"unlinking">;
  const client={
    links:vi.fn(async()=>deleted?[]:[{...link,unlinking:frozen}]),
    deleteLink:vi.fn(async(_state:IdentityLinkState,target:Hex)=>{expect(target).toBe(peer);frozen=true;if(policy.members[0].keys.some(key=>key.memberKeyId===peer&&key.removedAtVersion===null))throw new ApiError(409,"pending");deleted=true;}),
    policy:vi.fn(async():Promise<PolicyResponse>=>({policy:structuredClone(policy),ops:structuredClone(ops)})),
    append:vi.fn(async(op:PolicyOp)=>{expect(frozen).toBe(true);policy=applyPolicyOp(policy,op);ops.push(op);return{policy:structuredClone(policy),ops:structuredClone(ops)};}),
  };
  return {identity:{keys,client:client as unknown as WorkspaceClient},client,peer,policy:()=>policy,deleted:()=>deleted,frozen:()=>frozen};
}
describe("linked identity removal",()=>{
  it("freezes first and retries a concurrent policy update before global deletion",async()=>{
    const f=await setup(),progress=vi.fn();
    f.client.append.mockRejectedValueOnce(new ApiError(409,"changed"));
    await unlinkOtherIdentity([f.identity],progress);
    expect(f.deleted()).toBe(true);expect(f.client.append).toHaveBeenCalledTimes(2);
    expect(f.policy().adminEpoch).toBe(2);expect(f.policy().members[0].keys.find(k=>k.memberKeyId===f.peer)!.removedAtVersion).toBe(3);
    expect(progress).toHaveBeenLastCalledWith({completed:1,total:1});
    expect(f.identity.keys.signingSeed.some(byte=>byte!==0)).toBe(true);
  });
  it("leaves unlink frozen and incomplete when a workspace requires another owner's help",async()=>{
    const f=await setup();f.client.policy.mockRejectedValue(new ApiError(403,"revoked"));
    await expect(unlinkOtherIdentity([f.identity])).rejects.toMatchObject({statusCode:409});
    expect(f.frozen()).toBe(true);expect(f.deleted()).toBe(false);expect(f.client.append).not.toHaveBeenCalled();
  });
  it("can resume after partial work without enrolling or deleting unrelated identities",async()=>{
    const f=await setup();f.client.append.mockRejectedValueOnce(new Error("connection interrupted"));
    await expect(unlinkOtherIdentity([f.identity])).rejects.toThrow("interrupted");expect(f.frozen()).toBe(true);
    await unlinkOtherIdentity([f.identity]);expect(f.deleted()).toBe(true);
    const writes=f.client.append.mock.calls.length;await unlinkOtherIdentity([f.identity]);expect(f.client.append).toHaveBeenCalledTimes(writes);
  });
});

async function linkingSetup(){
  const records=new Map<Hex,PolicyResponse>(),pointers=new Map<Hex,SignedIdentityRotation>();let state:IdentityLinkState|undefined;
  const members=await Promise.all([1,2,3].map(n=>unlockMember(privateKeyToAccount(`0x${n.toString().padStart(2,"0").repeat(32)}`))));
  const makeIdentity=(keys:MemberKeys)=>{
    const client={
      discover:vi.fn(async()=>({workspaceIds:[...records].filter(([,r])=>currentMemberKey(r.policy,keys.memberKeyId)).map(([id])=>id),rotations:pointers.has(keys.memberKeyId)?[pointers.get(keys.memberKeyId)!]:[]})),
      links:vi.fn(async()=>state?[structuredClone(state)]:[]),
      registerRotation:vi.fn(async(pointer:SignedIdentityRotation)=>{pointers.set(pointer.oldKey,pointer);return pointer;}),
      registerLink:vi.fn(async(link:SignedIdentityLink)=>{state={link,rotations:[],workspaceIds:[...records.keys()],unlinking:false};}),
      create:vi.fn(async(op:PolicyOp)=>{const response={ops:[op],policy:replayPolicy([op])};records.set(response.policy.workspaceId,response);return structuredClone(response);}),
      policy:vi.fn(async(id:Hex)=>{const response=records.get(id)!;if(!currentMemberKey(response.policy,keys.memberKeyId))throw new ApiError(403,"not enrolled");return structuredClone(response);}),
      append:vi.fn(async(op:PolicyOp)=>{const before=records.get(op.workspaceId)!;const response={ops:[...before.ops,op],policy:applyPolicyOp(before.policy,op)};records.set(op.workspaceId,response);return structuredClone(response);}),
    };
    return {keys,client:client as unknown as WorkspaceClient,mock:client};
  };
  const identities=members.map(makeIdentity);
  for(const who of identities.slice(0,2))await findOrCreatePersonalWorkspaces(who.client,who.keys);
  return {identities,records,makeIdentity,pointers,setState:(value:IdentityLinkState)=>{state=value;}};
}
describe("linked identity enrollment",()=>{
  it("joins both existing personal histories and grants decryption without merging workspaces",async()=>{
    const f=await linkingSetup(),[a,b]=f.identities,ids=[...f.records.keys()],progress=vi.fn();
    await linkIdentities([a],[b],progress);
    expect([...f.records.keys()]).toEqual(ids);expect(a.mock.registerLink).toHaveBeenCalledTimes(1);
    for(const [id,policy] of f.records){
      const left=new WorkspaceKeyring(id,a.keys),right=new WorkspaceKeyring(id,b.keys);
      expect(await left.load(policy)).toEqual(await right.load(policy));left.close();right.close();
      expect(policy.policy.policyVersion).toBe(2);
    }
    expect(progress).toHaveBeenLastCalledWith({completed:2,total:2});
    await linkIdentities([a],[b]);expect(a.mock.registerLink).toHaveBeenCalledTimes(1);
    expect([...f.records.values()].every(r=>r.policy.policyVersion===2)).toBe(true);
  });
  it("resumes enrollment after one history was shared and the other write failed",async()=>{
    const f=await linkingSetup(),[a,b]=f.identities;
    b.mock.append.mockRejectedValueOnce(new Error("connection interrupted"));
    await expect(linkIdentities([a],[b])).rejects.toThrow("interrupted");
    expect([...f.records.values()].map(r=>r.policy.policyVersion)).toEqual([2,1]);
    b.mock.append.mockRejectedValueOnce(new ApiError(409,"changed"));
    await linkIdentities([a],[b]);
    expect([...f.records.values()].map(r=>r.policy.policyVersion)).toEqual([2,2]);
    expect(a.mock.registerLink).toHaveBeenCalledTimes(1);
  });
  it("rejects an existing link to another sign-in before granting access",async()=>{
    const f=await linkingSetup(),[a,b,c]=f.identities;
    f.setState({link:createIdentityLink(a.keys,c.keys,1234),rotations:[],workspaceIds:[],unlinking:false});
    await expect(linkIdentities([a],[b])).rejects.toThrow("elsewhere");
    expect(a.mock.append).not.toHaveBeenCalled();expect(b.mock.append).not.toHaveBeenCalled();
  });
  it("validates the registration winner before resuming a concurrent link",async()=>{
    const f=await linkingSetup(),[a,b,c]=f.identities;
    a.mock.registerLink.mockImplementationOnce(async()=>{
      f.setState({link:createIdentityLink(a.keys,c.keys,1234),rotations:[],workspaceIds:[],unlinking:false});
      throw new ApiError(409,"already registered");
    });
    await expect(linkIdentities([a],[b])).rejects.toThrow("elsewhere");
    expect(a.mock.append).not.toHaveBeenCalled();expect(b.mock.append).not.toHaveBeenCalled();
  });
  it("refuses enrollment while global unlink is frozen",async()=>{
    const f=await linkingSetup(),[a,b]=f.identities;
    f.setState({link:createIdentityLink(a.keys,b.keys,1234),rotations:[],workspaceIds:[...f.records.keys()],unlinking:true});
    await expect(linkIdentities([a],[b])).rejects.toThrow("Finish unlinking");
    expect(a.mock.append).not.toHaveBeenCalled();expect(b.mock.append).not.toHaveBeenCalled();
  });
});

describe("sign-in generation replacement",()=>{
  it("revokes the old key across both linked personal histories and retains decryption",async()=>{
    const f=await linkingSetup(),[a,b]=f.identities;await linkIdentities([a],[b]);
    const next=f.makeIdentity(await unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`),1));
    await replaceIdentity([a],next);
    expect((await a.client.discover()).workspaceIds).toEqual([]);expect((await next.client.discover()).workspaceIds).toHaveLength(2);
    for(const [id,policy] of f.records){
      expect(policy.policy.keyEpoch).toBe(2);expect(policy.policy.adminEpoch).toBe(2);
      const ring=new WorkspaceKeyring(id,next.keys);expect((await ring.load(policy)).size).toBe(2);ring.close();
    }
  });
  it("resumes a published replacement after a failed workspace write",async()=>{
    const f=await linkingSetup(),[a]=f.identities,next=f.makeIdentity(await unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`),1));
    a.mock.append.mockRejectedValueOnce(new Error("interrupted"));
    await expect(replaceIdentity([a],next)).rejects.toThrow("interrupted");expect(f.pointers.size).toBe(1);
    await replaceIdentity([a],next);expect(a.mock.registerRotation).toHaveBeenCalledTimes(1);expect((await a.client.discover()).workspaceIds).toEqual([]);
  });
  it("does not report completion when session denial leaves an old membership active",async()=>{
    const f=await linkingSetup(),[a]=f.identities,next=f.makeIdentity(await unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`),1));
    a.mock.policy.mockRejectedValue(new ApiError(403,"permission unavailable"));
    await expect(replaceIdentity([a],next)).rejects.toThrow("incomplete");expect(f.pointers.size).toBe(1);
  });
});
