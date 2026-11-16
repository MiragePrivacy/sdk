import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, encodeAbiParameters, keccak256, type Hex } from "viem";
import { buffer, bytes, canonicalJson, randomBytes, uint, utf8, type Json } from "./encoding";
import { verifyEd25519 } from "./signatures";

export const RECORD_TYPES = ["payment_request", "decision", "execution_event", "contact", "payment_template", "roster"] as const;
export type RecordType = typeof RECORD_TYPES[number];
export interface RecordHeader {
  workspaceId: Hex;
  recordId: Hex;
  type: RecordType;
  revision: number;
  keyEpoch: number;
  authorKeyId: Hex;
  authorPolicyVersion: number;
}
export interface EncryptedRecord extends RecordHeader { nonce: Hex; ciphertext: Hex; signature: Hex }
/** Must consult a verified policy log at the requested historical version. */
export type AuthorPolicyCheck = (header: Readonly<RecordHeader>, requiredCapability: number) => boolean;
export const RECORD_AAD_TYPE = "MirageRecordAAD(bytes16 workspaceId,bytes32 recordId,string recordType,uint64 revision,uint32 keyEpoch,uint64 authorPolicyVersion)";
export const RECORD_SIGNATURE_TYPE = "MirageRecord(bytes32 aadHash,bytes32 authorKeyId,bytes12 nonce,bytes32 ciphertextHash)";
export const MAX_RECORD_BYTES = 1024 * 1024;

export function recordAad(header: RecordHeader): Hex {
  bytes(header.workspaceId, 16); bytes(header.recordId, 32); bytes(header.authorKeyId, 32);
  if (!RECORD_TYPES.includes(header.type)) throw new Error("Invalid record type");
  uint(header.revision, 53, 1); uint(header.keyEpoch, 32, 1); uint(header.authorPolicyVersion, 53, 1);
  return encodeAbiParameters(
    [{type:"bytes32"},{type:"bytes16"},{type:"bytes32"},{type:"bytes32"},{type:"uint64"},{type:"uint32"},{type:"uint64"}],
    [keccak256(utf8(RECORD_AAD_TYPE)), header.workspaceId, header.recordId, keccak256(utf8(header.type)),
      BigInt(header.revision), header.keyEpoch, BigInt(header.authorPolicyVersion)],
  );
}

export function recordHash(record: Omit<EncryptedRecord, "signature">): Hex {
  bytes(record.nonce, 12);
  if (record.ciphertext.length > MAX_RECORD_BYTES * 2 + 2) throw new Error("Workspace record too large");
  const ciphertext = bytes(record.ciphertext);
  if (ciphertext.length < 16) throw new Error("Invalid record ciphertext");
  return keccak256(encodeAbiParameters(
    [{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"bytes12"},{type:"bytes32"}],
    [keccak256(utf8(RECORD_SIGNATURE_TYPE)), keccak256(recordAad(record)), record.authorKeyId, record.nonce, keccak256(ciphertext)],
  ));
}

export function verifyRecord(record: EncryptedRecord, authorize: AuthorPolicyCheck): boolean {
  try {
    const hash = recordHash(record);
    if (!verifyEd25519(record.signature, hash, record.authorKeyId)) return false;
    const capability = record.type === "payment_request" ? 1 : record.type === "decision" ? 2 : 8;
    return authorize(Object.freeze({ workspaceId: record.workspaceId, recordId: record.recordId, type: record.type,
      revision: record.revision, keyEpoch: record.keyEpoch, authorKeyId: record.authorKeyId,
      authorPolicyVersion: record.authorPolicyVersion }), capability) === true;
  } catch { return false; }
}

async function aesKey(key: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  if (key.length !== 32) throw new Error("Workspace content key must be 32 bytes");
  return globalThis.crypto.subtle.importKey("raw", buffer(key), "AES-GCM", false, [usage]);
}

export async function sealRecord(header: RecordHeader, body: Json, contentKey: Uint8Array, signingSeed: Uint8Array): Promise<EncryptedRecord> {
  // Copy metadata before the first await so callers cannot change what was encrypted.
  const snapshot = { workspaceId: header.workspaceId, recordId: header.recordId, type: header.type,
    revision: header.revision, keyEpoch: header.keyEpoch, authorKeyId: header.authorKeyId,
    authorPolicyVersion: header.authorPolicyVersion };
  const aad = bytes(recordAad(snapshot));
  if (bytesToHex(ed25519.getPublicKey(signingSeed)) !== snapshot.authorKeyId) throw new Error("Record author does not match signing key");
  const canonicalBody = canonicalJson(body);
  const contentHash = bytesToHex(sha256(utf8(canonicalBody)));
  const plaintext = utf8(`{"body":${canonicalBody},"content_hash":"${contentHash}"}`);
  if (plaintext.length + 16 > MAX_RECORD_BYTES) throw new Error("Workspace record too large");
  const nonce = randomBytes(12);
  const key = await aesKey(contentKey, "encrypt");
  const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name:"AES-GCM", iv:buffer(nonce), additionalData:buffer(aad), tagLength:128 }, key, buffer(plaintext)));
  plaintext.fill(0);
  const record = { ...snapshot, nonce:bytesToHex(nonce), ciphertext:bytesToHex(ciphertext) };
  return { ...record, signature:bytesToHex(ed25519.sign(bytes(recordHash(record)), signingSeed)) };
}

export async function openRecord(record: EncryptedRecord, contentKey: Uint8Array, authorize: AuthorPolicyCheck): Promise<Json> {
  const snapshot = { ...record };
  if (!verifyRecord(snapshot, authorize)) throw new Error("Invalid record signature or author policy");
  const key = await aesKey(contentKey, "decrypt");
  const plaintext = new Uint8Array(await globalThis.crypto.subtle.decrypt({ name:"AES-GCM", iv:buffer(bytes(snapshot.nonce, 12)), additionalData:buffer(bytes(recordAad(snapshot))), tagLength:128 }, key, buffer(bytes(snapshot.ciphertext))));
  try {
    const inner = JSON.parse(new TextDecoder("utf-8", { fatal:true }).decode(plaintext));
    if (inner === null || typeof inner !== "object" || Array.isArray(inner) ||
        Object.keys(inner).sort().join(",") !== "body,content_hash" ||
        bytesToHex(sha256(utf8(canonicalJson(inner.body)))) !== inner.content_hash) throw new Error("Invalid encrypted content hash");
    return inner.body;
  } finally { plaintext.fill(0); }
}
