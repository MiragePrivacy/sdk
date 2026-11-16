// Test secrets only. Run after building, then regenerate the Rust envelope and copy
// api/tests/vectors/workspaces.json back here as documented in docs/workspaces-wire.md.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";
import { bytesToHex, concatBytes } from "viem";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { deriveMemberKeys, unlockMessage, createIdentityLink, createIdentityRotation,
  sealKey, sealRecord, recordAad, recordHash, linkHash, rotationHash } from "../dist/workspaces/index.js";

const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
const other = privateKeyToAccount(`0x${"02".repeat(32)}`);
const unlock = [];
const keys = [];
for (const generation of [0, 1]) {
  const signature = await account.signTypedData(unlockMessage(generation));
  const member = deriveMemberKeys(signature, generation);
  keys.push(member);
  unlock.push({ generation, signature, signingSeed:bytesToHex(member.signingSeed), kemSecret:bytesToHex(member.kemSecret), memberKeyId:member.memberKeyId, kemPublicKey:member.kemPublicKey });
}
const second = deriveMemberKeys(await other.signTypedData(unlockMessage(0)));
const link = createIdentityLink(keys[0], second, 1788998400);
const rotation = createIdentityRotation(keys[0], keys[1], 1788998401);
const contentKey = new Uint8Array(32).fill(42);
const context = { workspaceId:`0x${"11".repeat(16)}`, kind:"content", epoch:1 };
const envelope = await sealKey(context, keys[0].memberKeyId, keys[0].kemPublicKey, contentKey);
const body = { memo:"Completed transfer — 東京", chain_id:31337, amount:"1000000000000000000", results:[{ hash:`0x${"ab".repeat(32)}`, status:"delivered" }] };
const record = await sealRecord({ workspaceId:context.workspaceId, recordId:`0x${"22".repeat(32)}`, type:"execution_event", revision:1, keyEpoch:1, authorKeyId:keys[0].memberKeyId, authorPolicyVersion:1 }, body, contentKey, keys[0].signingSeed);
const path = new URL("../test/fixtures/workspaces.json", import.meta.url);
// A mixed-order R satisfies cofactored verification, but is outside our profile.
const torsion = ed25519.Point.fromHex(`ec${"ff".repeat(30)}7f`);
const rejectedR = ed25519.Point.BASE.multiply(2n).add(torsion).toBytes();
const rejectedKey = ed25519.Point.BASE.toBytes();
const rejectedHash = new Uint8Array(32).fill(7);
const challenge = sha512(concatBytes([rejectedR, rejectedKey, rejectedHash]));
const challengeScalar = BigInt(bytesToHex(challenge.reverse()));
const order = 2n ** 252n + 27742317777372353535851937790883648493n;
const scalar = (challengeScalar + 2n) % order;
const rejectedS = Uint8Array.from(scalar.toString(16).padStart(64,"0").match(/../g).map(v => parseInt(v,16))).reverse();
const rejectedSignature = concatBytes([rejectedR, rejectedS]);
if (!ed25519.verify(rejectedSignature, rejectedHash, rejectedKey, {zip215:false})) throw new Error("Invalid rejection-vector construction");
let previous = {};
try { previous = JSON.parse(readFileSync(path, "utf8")); } catch {}
mkdirSync(new URL("../test/fixtures/", import.meta.url), { recursive:true });
writeFileSync(path, JSON.stringify({ ...previous, version:1, testOnly:true, unlockSigner:account.address, unlock,
  ed25519Rejected:{ key:bytesToHex(rejectedKey), hash:bytesToHex(rejectedHash), signature:bytesToHex(rejectedSignature) },
  link:{ value:link, hash:linkHash(link) }, rotation:{ value:rotation, hash:rotationHash(rotation) },
  envelopeJs:{ value:envelope, key:bytesToHex(contentKey) }, ...(previous.envelopeRust ? { envelopeRust:previous.envelopeRust } : {}),
  record:{ value:record, key:bytesToHex(contentKey), body, aad:recordAad(record), hash:recordHash(record) } }, null, 2) + "\n");
