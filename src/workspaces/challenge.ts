import {ed25519} from "@noble/curves/ed25519.js";
import {bytesToHex,encodeAbiParameters,keccak256,type Hex} from "viem";
import {bytes,uint,utf8} from "./encoding";
import type {MemberKeys} from "./keys";

export const CHALLENGE_TYPE="MirageWorkspaceChallenge(string purpose,bytes16 workspaceId,bytes32 memberKeyId,bytes32 principalHash,bytes32 nonce,uint64 expiresAt)";
export interface WorkspaceChallenge {
  purpose:"session"|"discovery";
  workspaceId:Hex|null;
  memberKeyId:Hex;
  principalHash:Hex;
  nonce:Hex;
  expiresAt:number;
}
export function challengeHash(challenge:WorkspaceChallenge):Hex {
  if(Object.keys(challenge).sort().join(",")!=="expiresAt,memberKeyId,nonce,principalHash,purpose,workspaceId") throw new Error("Invalid workspace challenge fields");
  if(!((challenge.purpose==="session"&&challenge.workspaceId!==null)||(challenge.purpose==="discovery"&&challenge.workspaceId===null)))throw new Error("Invalid workspace challenge purpose");
  if(challenge.workspaceId!==null)bytes(challenge.workspaceId,16);
  bytes(challenge.memberKeyId,32);bytes(challenge.principalHash,32);bytes(challenge.nonce,32);uint(challenge.expiresAt,53,1);
  return keccak256(encodeAbiParameters(
    [{type:"bytes32"},{type:"bytes32"},{type:"bytes16"},{type:"bytes32"},{type:"bytes32"},{type:"bytes32"},{type:"uint64"}],
    [keccak256(utf8(CHALLENGE_TYPE)),keccak256(utf8(challenge.purpose)),challenge.workspaceId??`0x${"00".repeat(16)}`,challenge.memberKeyId,challenge.principalHash,challenge.nonce,BigInt(challenge.expiresAt)],
  ));
}
export function signWorkspaceChallenge(challenge:WorkspaceChallenge,keys:MemberKeys,expected:{purpose:WorkspaceChallenge["purpose"];workspaceId:Hex|null;principalHash:Hex}):Hex {
  const now=Math.floor(Date.now()/1000);
  if(challenge.purpose!==expected.purpose||challenge.workspaceId!==expected.workspaceId||challenge.principalHash!==expected.principalHash||challenge.memberKeyId!==keys.memberKeyId)
    throw new Error("Workspace challenge context mismatch");
  if(challenge.expiresAt<=now||challenge.expiresAt>now+330)throw new Error("Workspace challenge expired or has excessive lifetime");
  if(bytesToHex(ed25519.getPublicKey(keys.signingSeed))!==keys.memberKeyId)throw new Error("Workspace signing key unavailable");
  return bytesToHex(ed25519.sign(bytes(challengeHash(challenge)),keys.signingSeed));
}
