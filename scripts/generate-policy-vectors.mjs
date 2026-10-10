// Public test material only. Extends the reviewed crypto fixture without changing it.
import {readFileSync,writeFileSync} from "node:fs";
import {privateKeyToAccount} from "viem/accounts";
import {bytesToHex} from "viem";
import {ed25519} from "@noble/curves/ed25519.js";
import {unlockMember,sealKey,createIdentityLink,createIdentityRotation,ZERO_HASH,signPolicyOp,applyPolicyOp,policyOpHash} from "../dist/workspaces/index.js";
const path = new URL("../test/fixtures/workspaces.json",import.meta.url);
const vectors = JSON.parse(readFileSync(path,"utf8"));
const account = n => privateKeyToAccount(`0x${n.toString(16).padStart(2,"0").repeat(32)}`);
const a = await unlockMember(account(1));
const b = await unlockMember(account(2));
const b1 = await unlockMember(account(2),1);
const c = await unlockMember(account(3));
const workspaceId = `0x${"31".repeat(16)}`;
const memberId = `0x${"41".repeat(16)}`;
const seed = n => new Uint8Array(32).fill(n);
const pub = n => bytesToHex(ed25519.getPublicKey(seed(n)));
const initial = key => ({memberKeyId:key.memberKeyId,kemPublicKey:key.kemPublicKey,generation:key.generation});
const envelope = (key,kind,epoch,secret) => sealKey({workspaceId,kind,epoch},key.memberKeyId,key.kemPublicKey,secret);
const content = (keys,epoch) => Promise.all(keys.map(k => envelope(k,"content",epoch,seed(42+epoch))));
const admins = (keys,epoch,admin) => Promise.all(keys.map(k => envelope(k,"admin",epoch,seed(admin))));
const rotate = async(keys,epoch,admin) => ({newEpoch:epoch,newAdminPublicKey:admin === null ? null : pub(admin),
  envelopes:[...await content(keys,epoch),...(admin === null ? [] : await admins(keys,epoch,admin))]});
const ops = [], states = [], hashes = [];
let policy = null;
function append(kind,payload,actor,admin) {
  const unsigned = {workspaceId,policyVersion:ops.length+1,prevOpHash:policy?.headHash ?? ZERO_HASH,kind,payload,
    issuedAt:1788998500+ops.length,signerKeyId:actor.memberKeyId,signature:`0x${"00".repeat(64)}`,adminSignature:null};
  const op = signPolicyOp(unsigned,actor,admin === null ? null : seed(admin));
  policy = applyPolicyOp(policy,op); ops.push(op); states.push(policy); hashes.push(policyOpHash(op));
}
append("create",{memberId,key:initial(a),adminPublicKey:pub(10),personal:true,envelopes:[...await content([a],1),...await admins([a],1,10)]},a,10);
append("link_key",{memberId,generation:0,link:createIdentityLink(a,b,1788998501),envelopes:[...await content([b],1),...await admins([b],1,10)]},a,null);
append("set_caps",{memberId,caps:13},a,10);
append("set_caps",{memberId,caps:15},a,10);
append("set_threshold",{approvalThreshold:0},a,10);
append("rotate_content",{rotation:await rotate([a,b],2,null)},a,10);
append("rotate_admin",{rotation:await rotate([a,b],3,11)},a,10);
append("unlink_key",{memberId,keyId:a.memberKeyId,rotation:await rotate([b],4,12)},b,11);
const replacement = await rotate([b1],5,13);
for (const epoch of [1,2,3,4]) replacement.envelopes.push(...await content([b1],epoch));
append("rotate_member",{memberId,pointer:createIdentityRotation(b,b1,1788998508),rotation:replacement},b,12);
const cEnvelopes = [];
for (const epoch of [1,2,3,4,5]) cEnvelopes.push(...await content([c],epoch));
cEnvelopes.push(...await admins([c],5,13));
append("link_key",{memberId,generation:0,link:createIdentityLink(b1,c,1788998509),envelopes:cEnvelopes},b1,null);
append("remove_key",{memberId,keyId:c.memberKeyId,rotation:await rotate([b1],6,14)},b1,13);
vectors.policy = {ops,states,hashes};
writeFileSync(path,JSON.stringify(vectors,null,2)+"\n");
