import {describe,it,expect,vi} from "vitest";
import {privateKeyToAccount} from "viem/accounts";
import vectors from "./fixtures/workspaces.json";
import {WorkspaceKeyring,findOrCreatePersonalWorkspaces} from "../src/workspaces/personal";
import {unlockMember} from "../src/workspaces/keys";
import {replayPolicy,applyPolicyOp,type PolicyOp} from "../src/workspaces/policy";
import type {WorkspaceClient,PolicyResponse} from "../src/workspaces/client";
import type {SignedIdentityLink} from "../src/workspaces/identity";
import {ApiError} from "../src/errors";
const keys=()=>unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`));
function response(n=1):PolicyResponse {
  const ops=structuredClone(vectors.policy.ops.slice(0,n)) as PolicyOp[];
  return {ops,policy:replayPolicy(ops)};
}
describe("personal workspace keys",()=>{
  it("seals a linked sign-in the same history and owner authority",async()=>{
    const member=await keys(),peer=await unlockMember(privateKeyToAccount(`0x${"02".repeat(32)}`)),first=response();
    const ring=new WorkspaceKeyring(first.policy.workspaceId,member);const original=await ring.load(first);
    const link=vectors.policy.ops[1].payload.link as SignedIdentityLink;
    const operation=await ring.prepareLinkedKey(link,peer);expect(operation).not.toBeNull();expect(operation!.adminSignature).toBeNull();
    const next={ops:[...first.ops,operation!],policy:applyPolicyOp(first.policy,operation!)};
    const linked=new WorkspaceKeyring(first.policy.workspaceId,peer);const opened=await linked.load(next);
    expect(opened.get(1)).toEqual(original.get(1));
    await ring.load(next);expect(await ring.prepareLinkedKey(link,peer)).toBeNull();
    ring.close();linked.close();
  });
  it("opens signed envelopes, retains historical content, and wipes keys on close",async()=>{
    const member=await keys(),first=response(),ring=new WorkspaceKeyring(first.policy.workspaceId,member);
    const content=await ring.load(first);const original=content.get(1)!;expect(original.some(n=>n!==0)).toBe(true);
    const refreshed=await ring.load(response(7));expect(refreshed.get(1)).toBe(original);expect(refreshed.size).toBe(3);
    const held=[...refreshed.values()];ring.close();expect(held.every(key=>key.every(n=>n===0))).toBe(true);
    await expect(ring.load(first)).rejects.toThrow("closed");
    expect(member.signingSeed.some(n=>n!==0)).toBe(true);
  });
  it("refuses snapshot forgery and rollback without replacing verified keys",async()=>{
    const member=await keys(),first=response(),ring=new WorkspaceKeyring(first.policy.workspaceId,member);
    const opened=await ring.load(response(7));const original=opened.get(1)!;
    await expect(ring.load(first)).rejects.toThrow("rollback");
    const forged=response(7);forged.policy.approvalThreshold=99;
    await expect(ring.load(forged)).rejects.toThrow("Invalid keyring policy");
    expect((await ring.load(response(7))).get(1)).toBe(original);ring.close();
  });
  it("wipes previously opened history when the current key is revoked",async()=>{
    const member=await keys(),first=response(),ring=new WorkspaceKeyring(first.policy.workspaceId,member);
    const retained=(await ring.load(first)).get(1)!;
    await expect(ring.load(response(8))).rejects.toThrow("revoked");expect(retained.every(n=>n===0)).toBe(true);
  });
  it("creates a replayable personal policy whose creator can decrypt and administer it",async()=>{
    const member=await keys();let created:PolicyResponse|undefined;
    const client={discover:vi.fn(async()=>({workspaceIds:[],rotations:[]})),create:vi.fn(async(op:PolicyOp)=>{created={ops:[op],policy:replayPolicy([op])};return created;})};
    const selected=await findOrCreatePersonalWorkspaces(client as unknown as WorkspaceClient,member);
    expect(created!.policy.personal).toBe(true);expect(selected.workspaceIds).toEqual([created!.policy.workspaceId]);
    const ring=new WorkspaceKeyring(selected.primary,member);expect((await ring.load(created!)).size).toBe(1);ring.close();
  });
  it("rediscovers the winner of a simultaneous personal workspace creation",async()=>{
    const member=await keys(),existing=response();
    const discover=vi.fn().mockResolvedValueOnce({workspaceIds:[],rotations:[]}).mockResolvedValue({workspaceIds:[existing.policy.workspaceId],rotations:[]});
    const client={discover,policy:vi.fn(async()=>existing),create:vi.fn(async()=>{throw new ApiError(409,"already created");})};
    const selected=await findOrCreatePersonalWorkspaces(client as unknown as WorkspaceClient,member);
    expect(selected.primary).toBe(existing.policy.workspaceId);expect(client.create).toHaveBeenCalledTimes(1);
  });
  it("requires following rotations before creating an empty personal history",async()=>{
    const member=await keys(),client={discover:vi.fn(async()=>({workspaceIds:[],rotations:[{}]})),create:vi.fn()};
    await expect(findOrCreatePersonalWorkspaces(client as unknown as WorkspaceClient,member)).rejects.toThrow("rotation pointers");expect(client.create).not.toHaveBeenCalled();
  });
});
