import {readFileSync,writeFileSync} from "node:fs";
import {ed25519} from "@noble/curves/ed25519.js";
import {bytesToHex,hexToBytes} from "viem";
import {challengeHash} from "../dist/workspaces/index.js";
const path=new URL("../test/fixtures/workspaces.json",import.meta.url);
const vectors=JSON.parse(readFileSync(path,"utf8"));
vectors.challenges=["session","discovery"].map(purpose=>{
  const value={purpose,workspaceId:purpose==="session"?`0x${"31".repeat(16)}`:null,memberKeyId:vectors.unlock[0].memberKeyId,
    principalHash:`0x${"19".repeat(32)}`,nonce:`0x${"20".repeat(32)}`,expiresAt:1788998800};
  const hash=challengeHash(value);
  return{value,hash,signature:bytesToHex(ed25519.sign(hexToBytes(hash),hexToBytes(vectors.unlock[0].signingSeed)))};
});
writeFileSync(path,JSON.stringify(vectors,null,2)+"\n");
