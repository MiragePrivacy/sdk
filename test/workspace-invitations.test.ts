import {describe,expect,it,vi} from "vitest";
import {privateKeyToAccount} from "viem/accounts";
import {applyPolicyOp,inviteAcceptanceHash,inviteGrantHash,replayPolicy,ZERO_HASH,type InviteAcceptance,type InviteGrant,type PolicyOp} from "../src/workspaces/policy";
import {unlockMember} from "../src/workspaces/keys";
import {createTeamWorkspace,WorkspaceKeyring} from "../src/workspaces/personal";
import {acceptWorkspaceInvite,createWorkspaceInvite,finalizePendingInvite} from "../src/workspaces/invitations";
import type {InviteBundle,PolicyResponse,WorkspaceClient} from "../src/workspaces/client";
import {createIdentityLink} from "../src/workspaces/identity";

const account=(n:number)=>privateKeyToAccount(`0x${n.toString(16).padStart(2,"0").repeat(32)}`);

async function setup(){
  const owner=await unlockMember(account(1));let response:PolicyResponse|undefined,bundle:InviteBundle|undefined;
  const client={
    create:vi.fn(async(op:PolicyOp)=>response={ops:[op],policy:replayPolicy([op])}),
    append:vi.fn(async(op:PolicyOp)=>response={ops:[...response!.ops,op],policy:applyPolicyOp(response!.policy,op)}),
    createInvite:vi.fn(async(_workspace:unknown,grant:InviteBundle["grant"],ciphertext:InviteBundle["ciphertext"],policyOp?:PolicyOp)=>{if(policyOp)response={ops:[...response!.ops,policyOp],policy:applyPolicyOp(response!.policy,policyOp)};return bundle={grant,ciphertext,policy:structuredClone(response!)};}),
  };
  const workspaceId=await createTeamWorkspace(client as unknown as WorkspaceClient,owner);
  const ring=new WorkspaceKeyring(workspaceId,owner);await ring.load(response!);
  return {owner,client,ring,response:()=>response!,bundle:()=>bundle!};
}

describe("team invitations",()=>{
  it("pins the grant and acceptance hashes shared with the API",()=>{
    const grant:InviteGrant={workspaceId:`0x${"01".repeat(16)}`,grantId:`0x${"02".repeat(16)}`,invitePublicKey:`0x${"03".repeat(32)}`,caps:15,holdsAdmin:false,policyVersion:4,adminEpoch:2,keyEpoch:3,contentEpochs:[2,3],ciphertextHash:`0x${"04".repeat(32)}`,issuedAt:100,expiresAt:200,signature:ZERO_HASH};
    const acceptance:InviteAcceptance={grantHash:inviteGrantHash(grant),memberId:`0x${"05".repeat(16)}`,acceptingKeyId:`0x${"06".repeat(32)}`,keys:[{memberKeyId:`0x${"06".repeat(32)}`,kemPublicKey:`0x${"07".repeat(32)}`,generation:0}],identityProofs:[],envelopes:[],inviteSignature:ZERO_HASH};
    expect(inviteGrantHash(grant)).toBe("0x7eb76da35a93c6011b990d295d8abe283f14501e692c10a149c93a60b7d99657");
    expect(inviteAcceptanceHash(acceptance)).toBe("0x9496693a72680096d555451fb0380108dded46441e3247074a2b43dd3f1d873d");
  });
  it.each(["all","from_invitation"] as const)("grants %s history and consumes the signed membership operation",async history=>{
    const state=await setup();
    const created=await createWorkspaceInvite({client:state.client as unknown as WorkspaceClient,keyring:state.ring,history});
    const invitee=await unlockMember(account(2));let accepted:PolicyResponse|undefined;
    const client={
      invite:vi.fn(async()=>structuredClone(state.bundle())),
      links:vi.fn(async()=>[]),
      acceptInvite:vi.fn(async(_grant:unknown,op:PolicyOp)=>accepted={ops:[...state.response().ops,op],policy:applyPolicyOp(state.response().policy,op)}),
    };
    await acceptWorkspaceInvite(client as unknown as WorkspaceClient,invitee,created.grantId,created.secret);
    const member=accepted!.policy.members.find(item=>item.keys.some(key=>key.memberKeyId===invitee.memberKeyId));
    expect(member?.caps).toBe(15);expect(member?.keys[0].holdsAdmin).toBe(false);
    const inviteeRing=new WorkspaceKeyring(accepted!.policy.workspaceId,invitee),opened=await inviteeRing.load(accepted!);
    expect([...opened.keys()]).toEqual(history==="all"?[1]:[2]);
    expect(state.client.createInvite.mock.calls[0][3]).toEqual(history==="all"?undefined:expect.objectContaining({kind:"rotate_content"}));
    state.ring.close();inviteeRing.close();
  });
  it("detects a changed ciphertext before decrypting or enrolling",async()=>{
    const state=await setup(),created=await createWorkspaceInvite({client:state.client as unknown as WorkspaceClient,keyring:state.ring,history:"all"});
    const changed=structuredClone(state.bundle());changed.ciphertext.ciphertext=`0x00${changed.ciphertext.ciphertext.slice(4)}`;
    const client={invite:vi.fn(async()=>changed),links:vi.fn(async()=>[]),acceptInvite:vi.fn()};
    await expect(acceptWorkspaceInvite(client as unknown as WorkspaceClient,await unlockMember(account(2)),created.grantId,created.secret)).rejects.toThrow("grant");
    expect(client.acceptInvite).not.toHaveBeenCalled();state.ring.close();
  });
  it("holds a from-acceptance join until the owner rotates to a new epoch",async()=>{
    const state=await setup(),created=await createWorkspaceInvite({client:state.client as unknown as WorkspaceClient,keyring:state.ring,history:"from_acceptance"});
    const invitee=await unlockMember(account(2));let pending:any;
    const joining={invite:vi.fn(async()=>structuredClone(state.bundle())),links:vi.fn(async()=>[]),submitPendingInvite:vi.fn(async(_id:unknown,value:unknown)=>{pending={grant:state.bundle().grant,acceptance:value};})};
    expect(await acceptWorkspaceInvite(joining as unknown as WorkspaceClient,invitee,created.grantId,created.secret)).toEqual({status:"pending",workspaceId:state.response().policy.workspaceId});
    expect(state.response().policy.members).toHaveLength(1);
    let finalized:PolicyResponse|undefined;
    const ownerClient={policy:vi.fn(async()=>state.response()),finalizeInvite:vi.fn(async(_id:unknown,op:PolicyOp)=>finalized={ops:[...state.response().ops,op],policy:applyPolicyOp(state.response().policy,op)})};
    await finalizePendingInvite(ownerClient as unknown as WorkspaceClient,state.ring,pending);
    const inviteeRing=new WorkspaceKeyring(finalized!.policy.workspaceId,invitee),opened=await inviteeRing.load(finalized!);
    expect([...opened.keys()]).toEqual([2]);expect(finalized!.policy.members).toHaveLength(2);
    state.ring.close();inviteeRing.close();
  });
  it("enrolls the complete cross-signed login pair into one membership",async()=>{
    const state=await setup(),created=await createWorkspaceInvite({client:state.client as unknown as WorkspaceClient,keyring:state.ring,history:"all"});
    const invitee=await unlockMember(account(2)),peer=await unlockMember(account(3)),link=createIdentityLink(invitee,peer,100);let accepted:PolicyResponse|undefined;
    const client={invite:vi.fn(async()=>structuredClone(state.bundle())),links:vi.fn(async()=>[{link,rotations:[],unlinking:false,workspaceIds:[]}]),acceptInvite:vi.fn(async(_grant:unknown,op:PolicyOp)=>accepted={ops:[...state.response().ops,op],policy:applyPolicyOp(state.response().policy,op)})};
    await acceptWorkspaceInvite(client as unknown as WorkspaceClient,invitee,created.grantId,created.secret);
    expect(accepted!.policy.members[1].keys).toHaveLength(2);
    for(const member of [invitee,peer]){const ring=new WorkspaceKeyring(accepted!.policy.workspaceId,member);expect([...(await ring.load(accepted!)).keys()]).toEqual([1]);ring.close();}
    state.ring.close();
  });
});
