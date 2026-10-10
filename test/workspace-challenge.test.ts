import {afterEach,describe,it,expect,vi} from "vitest";
import type {Hex} from "viem";
import vectors from "./fixtures/workspaces.json";
import {challengeHash,signWorkspaceChallenge,type WorkspaceChallenge} from "../src/workspaces/challenge";
import {deriveMemberKeys,disposeMemberKeys} from "../src/workspaces/keys";
afterEach(()=>vi.useRealTimers());
describe("workspace session and discovery proofs",()=>{
  it.each([0,1])("matches Rust challenge %s",index=>{
    const vector=vectors.challenges[index];const value=vector.value as WorkspaceChallenge;
    vi.useFakeTimers();vi.setSystemTime((value.expiresAt-30)*1000);
    const keys=deriveMemberKeys(vectors.unlock[0].signature as Hex);
    expect(challengeHash(value)).toBe(vector.hash);
    expect(signWorkspaceChallenge(value,keys,value)).toBe(vector.signature);
  });
  it("refuses switched principals, workspaces, purpose, keys and invalid lifetimes",()=>{
    const original=vectors.challenges[0].value as WorkspaceChallenge;
    vi.useFakeTimers();vi.setSystemTime((original.expiresAt-30)*1000);
    const keys=deriveMemberKeys(vectors.unlock[0].signature as Hex);
    for(const patch of [{principalHash:`0x${"99".repeat(32)}`},{workspaceId:`0x${"99".repeat(16)}`},{purpose:"discovery",workspaceId:null},
      {memberKeyId:`0x${"99".repeat(32)}`},{expiresAt:original.expiresAt-30},{expiresAt:original.expiresAt+301}])
      expect(()=>signWorkspaceChallenge({...original,...patch} as WorkspaceChallenge,keys,original)).toThrow();
    expect(()=>challengeHash({...original,workspaceId:null})).toThrow("purpose");
    disposeMemberKeys(keys);expect(()=>signWorkspaceChallenge(original,keys,original)).toThrow("unavailable");
  });
});
