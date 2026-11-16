import { describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import vectors from "./fixtures/workspaces.json";
import { bytes, buffer, canonicalJson, utf8 } from "../src/workspaces/encoding";
import { verifyEd25519 } from "../src/workspaces/signatures";
import { deriveMemberKeys, disposeMemberKeys, unlockMember, unlockMessage } from "../src/workspaces/keys";
import { envelopeInfo, openKey, sealKey, type KeyEnvelope } from "../src/workspaces/hpke";
import { createIdentityLink, createIdentityRotation, followIdentityRotations, linkHash, rotationHash, verifyIdentityLink, verifyIdentityRotation, type SignedIdentityLink, type SignedIdentityRotation } from "../src/workspaces/identity";
import { openRecord, recordAad, recordHash, sealRecord, verifyRecord, type EncryptedRecord } from "../src/workspaces/records";

const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
const member = () => deriveMemberKeys(vectors.unlock[0].signature as Hex);
const record = () => structuredClone(vectors.record.value) as EncryptedRecord;
const contentKey = () => bytes(vectors.record.key as Hex, 32);
const authorize = (header: { authorKeyId: Hex; authorPolicyVersion: number }, cap: number) =>
  header.authorKeyId === vectors.unlock[0].memberKeyId && header.authorPolicyVersion === 1 && cap === 8;
const resign = (value: EncryptedRecord) => ({ ...value, signature:bytesToHex(ed25519.sign(bytes(recordHash(value)), member().signingSeed)) });

describe("member identity", () => {
  it("rejects the mixed-order signature accepted by cofactored Ed25519 verification", () => {
    const vector = vectors.ed25519Rejected;
    expect(ed25519.verify(bytes(vector.signature as Hex), bytes(vector.hash as Hex), bytes(vector.key as Hex), {zip215:false})).toBe(true);
    expect(verifyEd25519(vector.signature as Hex, vector.hash as Hex, vector.key as Hex)).toBe(false);
  });
  it.each([0, 1])("pins unlock signature and independently derived generation %s", async generation => {
    const vector = vectors.unlock[generation];
    const signature = await account.signTypedData(unlockMessage(generation));
    expect(signature).toBe(vector.signature);
    const keys = await unlockMember(account, generation);
    expect(bytesToHex(keys.signingSeed)).toBe(vector.signingSeed);
    expect(bytesToHex(keys.kemSecret)).toBe(vector.kemSecret);
    expect(keys.memberKeyId).toBe(vector.memberKeyId);
    expect(keys.kemPublicKey).toBe(vector.kemPublicKey);
    expect(keys.signingSeed).not.toEqual(keys.kemSecret);
  });
  it("rejects a changed signer and invalid generations without signing", async () => {
    const signTypedData = vi.fn(account.signTypedData);
    await expect(unlockMember({ address:`0x${"ff".repeat(20)}`, signTypedData })).rejects.toThrow("signer changed");
    signTypedData.mockClear();
    for (const generation of [-1, 2 ** 32, 0.5, NaN]) await expect(unlockMember({address:account.address,signTypedData}, generation)).rejects.toThrow();
    expect(signTypedData).not.toHaveBeenCalled();
  });
  it("normalizes parity encoding and zeroes owned buffers", () => {
    const vector = vectors.unlock[0];
    const signature = bytes(vector.signature as Hex); signature[64] -= 27;
    expect(deriveMemberKeys(bytesToHex(signature)).memberKeyId).toBe(vector.memberKeyId);
    const keys = member(); disposeMemberKeys(keys);
    expect(keys.signingSeed.every(v => v === 0)).toBe(true);
    expect(keys.kemSecret.every(v => v === 0)).toBe(true);
  });
  it("rejects high-S and malformed unlock signatures", () => {
    const signature = vectors.unlock[0].signature;
    const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const highS = (order - BigInt(`0x${signature.slice(66,130)}`)).toString(16).padStart(64,"0");
    expect(() => deriveMemberKeys(`${signature.slice(0,66)}${highS}${signature.slice(130)}` as Hex)).toThrow("low-S");
    expect(() => deriveMemberKeys("0x00")).toThrow();
    expect(() => deriveMemberKeys(`0x${"00".repeat(64)}1b`)).toThrow();
  });
});

describe("HPKE interoperability", () => {
  it.each(["envelopeJs", "envelopeRust"] as const)("opens the recorded %s envelope", async name => {
    const vector = vectors[name];
    const envelope = vector.value as KeyEnvelope;
    expect(bytesToHex(await openKey(envelope, envelope, member().kemSecret))).toBe(vector.key);
  });
  it("isolates concurrent seals and rejects the wrong recipient", async () => {
    const keys = member(); const context = vectors.envelopeJs.value as KeyEnvelope;
    const envelopes = await Promise.all(Array.from({length:4}, () => sealKey(context, keys.memberKeyId, keys.kemPublicKey, contentKey())));
    expect(new Set(envelopes.map(e => e.enc)).size).toBe(4);
    for (const envelope of envelopes) expect(await openKey(envelope, envelope, keys.kemSecret)).toEqual(contentKey());
    await expect(openKey(envelopes[0], envelopes[0], new Uint8Array(32).fill(9))).rejects.toThrow();
    await expect(sealKey(context, keys.memberKeyId, `0x${"00".repeat(32)}`, contentKey())).rejects.toThrow();
  });
  it("binds workspace, key kind, epoch and expected recipient", async () => {
    const envelope = vectors.envelopeJs.value as KeyEnvelope;
    for (const patch of [{workspaceId:`0x${"99".repeat(16)}`}, {kind:"admin"}, {epoch:2}, {recipientKeyId:`0x${"99".repeat(32)}`}]) {
      const moved = {...envelope,...patch} as KeyEnvelope;
      await expect(openKey(moved, envelope, member().kemSecret)).rejects.toThrow();
      if (!("recipientKeyId" in patch)) await expect(openKey(moved, moved, member().kemSecret)).rejects.toThrow();
    }
    expect(() => envelopeInfo({...envelope,epoch:0})).toThrow();
    const ciphertext = bytes(envelope.ciphertext); ciphertext[0] ^= 1;
    await expect(openKey({...envelope,ciphertext:bytesToHex(ciphertext)}, envelope, member().kemSecret)).rejects.toThrow();
  });
});

describe("encrypted records", () => {
  it("matches Rust hashes and decrypts only after historical author authorization", async () => {
    expect(recordAad(record())).toBe(vectors.record.aad);
    expect(recordHash(record())).toBe(vectors.record.hash);
    expect(await openRecord(record(), contentKey(), authorize)).toEqual(vectors.record.body);
    await expect(openRecord(record(), contentKey(), () => false)).rejects.toThrow("author policy");
    expect(Object.keys(record())).not.toContain("content_hash");
  });
  it("encrypts equal bodies independently and preserves the body on re-encryption", async () => {
    const first = await sealRecord(record(), vectors.record.body, contentKey(), member().signingSeed);
    const second = await sealRecord({...record(),revision:2,keyEpoch:2}, vectors.record.body, new Uint8Array(32).fill(5), member().signingSeed);
    expect(first.nonce).not.toBe(second.nonce);
    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(await openRecord(second, new Uint8Array(32).fill(5), authorize)).toEqual(vectors.record.body);
  });
  it.each([
    {workspaceId:`0x${"99".repeat(16)}`}, {recordId:`0x${"99".repeat(32)}`},
    {type:"contact"}, {revision:2}, {keyEpoch:2}, {authorPolicyVersion:2},
  ])("rejects tampered AAD even if an author re-signs it: %j", async patch => {
    const moved = {...record(),...patch} as EncryptedRecord;
    expect(verifyRecord(moved, () => true)).toBe(false);
    const signed = resign(moved);
    expect(verifyRecord(signed, () => true)).toBe(true);
    await expect(openRecord(signed, contentKey(), () => true)).rejects.toThrow();
  });
  it("rejects changes to author, nonce, ciphertext and signature before policy lookup", () => {
    for (const field of ["authorKeyId","nonce","ciphertext","signature"] as const) {
      const changed = record(); const raw = bytes(changed[field]); raw[0] ^= 1; changed[field] = bytesToHex(raw);
      const check = vi.fn(() => true);
      expect(verifyRecord(changed, check)).toBe(false);
      expect(check).not.toHaveBeenCalled();
    }
  });
  it("rejects an author-signed body whose encrypted inner hash is false", async () => {
    const changed = record();
    const key = await crypto.subtle.importKey("raw", buffer(contentKey()), "AES-GCM", false, ["encrypt"]);
    const inner = utf8(JSON.stringify({body:{memo:"forged"},content_hash:`0x${"00".repeat(32)}`}));
    changed.ciphertext = bytesToHex(new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:buffer(bytes(changed.nonce)),additionalData:buffer(bytes(recordAad(changed)))}, key, buffer(inner))));
    await expect(openRecord(resign(changed), contentKey(), authorize)).rejects.toThrow("content hash");
  });
  it("rejects invalid bounds, unknown types and mismatched authors", async () => {
    for (const patch of [{revision:0},{revision:2**53},{keyEpoch:0},{authorPolicyVersion:0},{type:"unknown"}])
      expect(verifyRecord({...record(),...patch} as EncryptedRecord, () => true)).toBe(false);
    await expect(sealRecord(record(), {}, contentKey(), new Uint8Array(32).fill(4))).rejects.toThrow("author");
  });
});

describe("linked identities and generation discovery", () => {
  it("pins cross-signed link and rotation hashes", () => {
    const link = vectors.link.value as SignedIdentityLink;
    const rotation = vectors.rotation.value as SignedIdentityRotation;
    expect(linkHash(link)).toBe(vectors.link.hash); expect(verifyIdentityLink(link)).toBe(true);
    expect(rotationHash(rotation)).toBe(vectors.rotation.hash); expect(verifyIdentityRotation(rotation)).toBe(true);
    for (const patch of [{kemA:`0x${"99".repeat(32)}`},{kemB:`0x${"99".repeat(32)}`},{issuedAt:link.issuedAt+1},{signatureA:link.signatureB}])
      expect(verifyIdentityLink({...link,...patch} as SignedIdentityLink)).toBe(false);
    for (const patch of [{oldKem:`0x${"99".repeat(32)}`},{newKem:`0x${"99".repeat(32)}`},{generation:2},{signatureNew:rotation.signatureOld}])
      expect(verifyIdentityRotation({...rotation,...patch} as SignedIdentityRotation)).toBe(false);
  });
  it("finds the next generation and refuses forged, skipped or unrelated pointers", async () => {
    const pointer = vectors.rotation.value as SignedIdentityRotation;
    const initial = member();
    const found = await followIdentityRotations(account, initial, [pointer]);
    expect(found.memberKeyId).toBe(vectors.unlock[1].memberKeyId);
    expect(initial.signingSeed.some(v => v !== 0)).toBe(true); // Caller owns the initial key.
    await expect(followIdentityRotations(account, initial, [{...pointer,generation:2}])).rejects.toThrow("chain");
    await expect(followIdentityRotations(account, initial, [pointer,pointer])).rejects.toThrow("chain");
    const unrelated = await unlockMember(privateKeyToAccount(`0x${"03".repeat(32)}`), 1);
    const crossSigned = createIdentityRotation(initial, unrelated, pointer.issuedAt);
    await expect(followIdentityRotations(account, initial, [crossSigned])).rejects.toThrow("Re-derived");
  });
  it("canonicalizes link order and refuses self-link and skipped rotations", async () => {
    const first = member(); const second = await unlockMember(privateKeyToAccount(`0x${"02".repeat(32)}`));
    expect(createIdentityLink(first, second, vectors.link.value.issuedAt)).toEqual(createIdentityLink(second, first, vectors.link.value.issuedAt));
    expect(() => createIdentityLink(first, first, 1)).toThrow();
    expect(() => createIdentityRotation(first, {...second,generation:2}, 1)).toThrow();
  });
});

describe("canonical content encoding", () => {
  it("sorts nested object keys without changing array order or Unicode", () => {
    expect(canonicalJson({z:[{b:2,a:1},"東京"],a:null})).toBe('{"a":null,"z":[{"a":1,"b":2},"東京"]}');
  });
  it("rejects cycles, accessors and array properties that JSON would silently discard", () => {
    const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic;
    expect(() => canonicalJson(cyclic as never)).toThrow();
    const accessor = Object.defineProperty({},"value",{enumerable:true,get:() => 1});
    expect(() => canonicalJson(accessor)).toThrow();
    expect(() => canonicalJson(Object.assign([1],{extra:2}))).toThrow();
  });
  it.each([NaN, Infinity, -0, 0.1, Number.MAX_SAFE_INTEGER+1, undefined, 1n, new Date(), "\ud800", {x:undefined}, [,]])("rejects ambiguous/non-JSON input %s", input => {
    expect(() => canonicalJson(input as never)).toThrow();
  });
});
