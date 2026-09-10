import {readFileSync,writeFileSync} from "node:fs";
import {privateKeyToAccount} from "viem/accounts";
import {bytesToHex} from "viem";
import {ed25519} from "@noble/curves/ed25519.js";
import {unlockMember,sealKey,signPolicyOp,replayPolicy,WorkspaceKeyring,createIdentityUnlink,unlinkHash,linkHash} from "../dist/workspaces/index.js";
const path=new URL("../test/fixtures/workspaces.json",import.meta.url);
const fixture=JSON.parse(readFileSync(path,"utf8"));
const a=await unlockMember(privateKeyToAccount(`0x${"01".repeat(32)}`));
const b=await unlockMember(privateKeyToAccount(`0x${"02".repeat(32)}`));
const replacement=await unlockMember(privateKeyToAccount(`0x${"02".repeat(32)}`),1);
async function workspace(byte){
  const workspaceId=`0x${byte.repeat(16)}`;
  const create=structuredClone(fixture.policy.ops[0]);create.workspaceId=workspaceId;create.payload.personal=false;
  create.payload.envelopes=await Promise.all([
    sealKey({workspaceId,kind:"content",epoch:1},a.memberKeyId,a.kemPublicKey,new Uint8Array(32).fill(43)),
    sealKey({workspaceId,kind:"admin",epoch:1},a.memberKeyId,a.kemPublicKey,new Uint8Array(32).fill(10)),
  ]);
  const first=signPolicyOp(create,a,new Uint8Array(32).fill(10));
  const ring=new WorkspaceKeyring(workspaceId,a);await ring.load({ops:[first],policy:replayPolicy([first])});
  const linkState={link:fixture.policy.ops[1].payload.link,unlinking:false,rotations:[fixture.policy.ops[8].payload.pointer],workspaceIds:[]};
  const pending=await ring.prepareLinkedKey(linkState,replacement);
  const obsolete=await ring.prepareLinkedKey(fixture.policy.ops[1].payload.link,b);
  obsolete.issuedAt=first.issuedAt+1;const obsoleteLink=signPolicyOp(obsolete,a,null);
  pending.issuedAt=first.issuedAt+1;const linked=signPolicyOp(pending,a,null);ring.close();
  const previous=replayPolicy([first,linked]);
  const unlink=structuredClone(fixture.policy.ops[7]);unlink.signerKeyId=replacement.memberKeyId;unlink.workspaceId=workspaceId;unlink.policyVersion=3;unlink.prevOpHash=previous.headHash;unlink.issuedAt=first.issuedAt+2;
  unlink.payload.rotation={newEpoch:2,newAdminPublicKey:bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(12))),envelopes:await Promise.all([
    sealKey({workspaceId,kind:"content",epoch:2},replacement.memberKeyId,replacement.kemPublicKey,new Uint8Array(32).fill(45)),
    sealKey({workspaceId,kind:"admin",epoch:2},replacement.memberKeyId,replacement.kemPublicKey,new Uint8Array(32).fill(12)),
  ])};
  const removed=signPolicyOp(unlink,replacement,new Uint8Array(32).fill(10));replayPolicy([first,linked,removed]);
  return {ops:[first,linked,removed],obsoleteLink};
}
const proof=createIdentityUnlink(linkHash(fixture.policy.ops[1].payload.link),a.memberKeyId,b,fixture.policy.ops[0].issuedAt+100);
const second=await workspace("13"),third=await workspace("14");
fixture.identityLifecycle={secondWorkspace:second.ops,thirdWorkspace:third.ops,obsoleteThirdLink:third.obsoleteLink,unlink:proof,unlinkHash:unlinkHash(proof)};
writeFileSync(path,JSON.stringify(fixture,null,2)+"\n");
