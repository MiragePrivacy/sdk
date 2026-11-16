import {describe,expect,it} from "vitest";
import {privateKeyToAccount} from "viem/accounts";
import type {Hex} from "viem";
import vectors from "./fixtures/workspaces.json";
import {applyPolicyOp,currentMemberKey,policyAuthorCheck,policyOpHash,replayPolicy,signPolicyOp,type Policy,type PolicyOp} from "../src/workspaces/policy";
import {unlockMember} from "../src/workspaces/keys";

const ops = () => structuredClone(vectors.policy.ops) as PolicyOp[];
const account = (n: number) => privateKeyToAccount(`0x${n.toString(16).padStart(2,"0").repeat(32)}`);
const actor = (n = 1,generation = 0) => unlockMember(account(n),generation);
const admin = (n = 10) => new Uint8Array(32).fill(n);
const state = (n: number) => replayPolicy(ops().slice(0,n));

describe("workspace policy replay",() => {
  it("pins every operation hash and resulting state for Rust replay",() => {
    let previous: Policy | null = null;
    for (const [i,op] of ops().entries()) {
      expect(policyOpHash(op)).toBe(vectors.policy.hashes[i]);
      previous = applyPolicyOp(previous,op);
      expect(previous).toEqual(vectors.policy.states[i]);
    }
  });
  it("refuses forged policy data and stale or forked heads", async () => {
    const original = ops()[4];
    for (const patch of [{policyVersion:4},{prevOpHash:`0x${"ff".repeat(32)}`},{workspaceId:`0x${"ff".repeat(16)}`}]) {
      const tampered = signPolicyOp({...original,...patch} as PolicyOp,await actor(),admin());
      expect(() => applyPolicyOp(state(4),tampered)).toThrow("head");
    }
    const tampered = ops()[4]; tampered.issuedAt += 1;
    expect(() => applyPolicyOp(state(4),tampered)).toThrow("actor signature");
    expect(() => replayPolicy([])).toThrow("empty");
    expect(() => replayPolicy(ops().slice(1))).toThrow("missing create");
  });
  it("requires creator, owner and current admin proofs",async () => {
    const create = ops()[0]; create.adminSignature = null;
    expect(() => applyPolicyOp(null,create)).toThrow("admin signature");
    const bad = signPolicyOp(ops()[4],await actor(),admin(99));
    expect(() => applyPolicyOp(state(4),bad)).toThrow("admin signature");
    const linked = signPolicyOp(ops()[1],await actor(),admin());
    expect(() => applyPolicyOp(state(1),linked)).toThrow("unexpected admin");
  });
  it("requires complete, unique creator envelopes and rejects unrecognized fields",async () => {
    for (const mutate of [
      (op: any) => op.payload.envelopes.pop(),
      (op: any) => op.payload.envelopes.push(op.payload.envelopes[0]),
      (op: any) => {op.payload.unknown = 1;},
      (op: any) => {op.payload.key.generation = -1;},
      (op: any) => {op.payload.personal = "true";},
    ]) {
      const op = ops()[0]; mutate(op);
      expect(() => applyPolicyOp(null,signPolicyOp(op,awaitedActor,admin()))).toThrow();
    }
  });
  it("does not mutate previous state after rejecting an incomplete rotation",async () => {
    const previous = state(7); const snapshot = structuredClone(previous);
    const op = ops()[7]; if (op.kind !== "unlink_key") throw Error("fixture");
    op.payload.rotation.envelopes.pop();
    const signed = signPolicyOp(op,await actor(2),admin(11));
    expect(() => applyPolicyOp(previous,signed)).toThrow("envelope");
    expect(previous).toEqual(snapshot);
  });
  it("owner unlink atomically revokes the old key and replaces admin/content authority",async () => {
    const after = state(8);
    expect(currentMemberKey(after,vectors.unlock[0].memberKeyId as Hex)).toBeUndefined();
    expect(after.keyEpoch).toBe(4); expect(after.adminEpoch).toBe(4);
    for (const mutate of [
      (op: any) => {op.payload.rotation.newAdminPublicKey = null;},
      (op: any) => {op.payload.rotation.newAdminPublicKey = state(7).adminPublicKey;},
      (op: any) => {op.payload.rotation.newEpoch = 3;},
      (op: any) => {op.payload.keyId = op.signerKeyId;},
    ]) {
      const op = ops()[7]; mutate(op);
      const signed = signPolicyOp(op,await actor(2),admin(11));
      expect(() => applyPolicyOp(state(7),signed)).toThrow();
    }
    const op = ops()[7]; op.adminSignature = null;
    expect(() => applyPolicyOp(state(7),op)).toThrow("admin signature");
    const future = {...ops()[4],policyVersion:9,prevOpHash:after.headHash};
    expect(() => applyPolicyOp(after,signPolicyOp(future,awaitedActor,admin(11)))).toThrow("actor revoked");
  });
  it("rotation carries historical keys to the next generation and retires the previous generation",async () => {
    const before = state(8); const after = state(9); const pointer = ops()[8];
    if (pointer.kind !== "rotate_member") throw Error("fixture");
    expect(currentMemberKey(after,pointer.payload.pointer.oldKey)).toBeUndefined();
    const replacement = currentMemberKey(after,pointer.payload.pointer.newKey)!;
    expect(replacement.key.generation).toBe(1); expect(replacement.key.holdsAdmin).toBe(true);
    expect(after.envelopes.filter(e => e.recipientKeyId === replacement.key.memberKeyId && e.kind === "content").map(e => e.epoch).sort()).toEqual([1,2,3,4,5]);
    pointer.payload.rotation.envelopes = pointer.payload.rotation.envelopes.filter(e => e.epoch !== 1);
    expect(() => applyPolicyOp(before,signPolicyOp(pointer,awaitedB,admin(12)))).toThrow("envelope");
  });
  it("preserves invalidation versions when VOTE is restored, and rejects impossible thresholds",async () => {
    expect(state(3).members[0].voteInvalidatedAtVersion).toBe(3);
    expect(state(4).members[0].voteInvalidatedAtVersion).toBe(3);
    const op = ops()[4]; if (op.kind !== "set_threshold") throw Error("fixture"); op.payload.approvalThreshold = 1;
    expect(() => applyPolicyOp(state(4),signPolicyOp(op,awaitedActor,admin()))).toThrow("threshold");
  });
  it("requires the author to have authority and the relevant epoch at the historical version",() => {
    const check = policyAuthorCheck(ops());
    const header = {workspaceId:ops()[0].workspaceId,recordId:`0x${"aa".repeat(32)}` as Hex,type:"execution_event" as const,
      revision:1,keyEpoch:1,authorKeyId:vectors.unlock[0].memberKeyId as Hex,authorPolicyVersion:1};
    expect(check(header,8)).toBe(true);
    expect(check({...header,authorPolicyVersion:8},8)).toBe(false);
    expect(check({...header,keyEpoch:2},8)).toBe(false);
    expect(check({...header,authorPolicyVersion:3},2)).toBe(false);
    expect(check({...header,workspaceId:`0x${"aa".repeat(16)}`},8)).toBe(false);
  });
});

// Test-only deterministic signers. No workspace private keys persist in production.
const awaitedActor = await actor();
const awaitedB = await actor(2);
