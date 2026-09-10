import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
import { bytesToHex, concat, type Hex } from "viem";
import { buffer, bytes, uint, utf8 } from "./encoding";

export interface EnvelopeContext { workspaceId: Hex; kind: "content" | "admin"; epoch: number }
export interface KeyEnvelope extends EnvelopeContext { recipientKeyId: Hex; enc: Hex; ciphertext: Hex }
const suite = new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Aes256Gcm });

export function envelopeInfo(context: EnvelopeContext): Uint8Array<ArrayBuffer> {
  const epoch = new Uint8Array(4);
  new DataView(epoch.buffer).setUint32(0, uint(context.epoch, 32, 1), false);
  if (context.kind !== "content" && context.kind !== "admin") throw new Error("Invalid envelope kind");
  return new Uint8Array(concat([utf8("mirage-envelope-v1"), bytes(context.workspaceId, 16), utf8(context.kind), epoch]));
}

/** A fresh one-message HPKE context for every key; no sender contexts are shared. */
export async function sealKey(context: EnvelopeContext, recipientKeyId: Hex, kemPublicKey: Hex, key: Uint8Array): Promise<KeyEnvelope> {
  const snapshot = { workspaceId:context.workspaceId, kind:context.kind, epoch:context.epoch };
  bytes(recipientKeyId, 32);
  if (key.length !== 32) throw new Error("Workspace keys must be 32 bytes");
  const info = buffer(envelopeInfo(snapshot));
  const plaintext = new Uint8Array(key);
  try {
  const recipientPublicKey = await suite.kem.importKey("raw", buffer(bytes(kemPublicKey, 32)));
  const sender = await suite.createSenderContext({ recipientPublicKey, info });
  const ciphertext = await sender.seal(plaintext.buffer);
  return { ...snapshot, recipientKeyId, enc: bytesToHex(new Uint8Array(sender.enc)), ciphertext: bytesToHex(new Uint8Array(ciphertext)) };
  } finally { plaintext.fill(0); }
}

export async function openKey(envelope: KeyEnvelope, expected: EnvelopeContext & { recipientKeyId: Hex }, kemSecret: Uint8Array): Promise<Uint8Array> {
  if (envelope.workspaceId !== expected.workspaceId || envelope.kind !== expected.kind ||
      envelope.epoch !== expected.epoch || envelope.recipientKeyId !== expected.recipientKeyId)
    throw new Error("Workspace envelope context mismatch");
  bytes(envelope.recipientKeyId, 32);
  if (kemSecret.length !== 32) throw new Error("Invalid member KEM key");
  const info = buffer(envelopeInfo(envelope));
  const enc = buffer(bytes(envelope.enc, 32));
  const ciphertext = buffer(bytes(envelope.ciphertext, 48));
  const recipientKey = await suite.kem.importKey("raw", buffer(kemSecret), false);
  const recipient = await suite.createRecipientContext({ recipientKey, enc, info });
  return new Uint8Array(await recipient.open(ciphertext));
}
