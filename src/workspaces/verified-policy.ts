import type { Hex } from "viem";
import type { PolicyResponse } from "./client";
import { canonicalJson, type Json } from "./encoding";
import { applyPolicyOp, policyOpHash } from "./policy";
import { recordAuthorsAtVersion } from "./record-authors";
import type { AuthorPolicyCheck, Realm } from "./records";

/** Internal, client-owned copies. Never return these objects directly to callers. */
export interface VerifiedPolicy extends PolicyResponse {
  authors: AuthorPolicyCheck[];
  realm: Realm;
}

const views = new WeakMap<VerifiedPolicy, PolicyResponse>();
const verifiedViews = new WeakMap<PolicyResponse, VerifiedPolicy>();

/** Only used on owned JSON data, prior to publishing a shared read-only view. */
export function freezeJson<T>(data: T): T {
  if (data && typeof data === "object" && !Object.isFrozen(data)) {
    for (const child of Object.values(data)) freezeJson(child);
    Object.freeze(data);
  }
  return data;
}

export function policyView(log: VerifiedPolicy): PolicyResponse {
  let view = views.get(log);
  if (!view) {
    view = freezeJson({ policy: log.policy, ops: log.ops });
    views.set(log, view);
    verifiedViews.set(view, log);
  }
  return view;
}

export const verifiedView = (response: PolicyResponse) => verifiedViews.get(response);

const equal = (left: unknown, right: unknown) =>
  canonicalJson(left as Json) === canonicalJson(right as Json);

export function verifyPolicyResponse(
  workspace: Hex, response: PolicyResponse, previous?: VerifiedPolicy,
  mismatch = "Server policy does not match signed log", realm: Realm = "workspaces",
): VerifiedPolicy {
  const known = verifiedView(response);
  if (known?.realm === realm) {
    if (known.policy.workspaceId !== workspace) throw new Error(mismatch);
    if (previous && known !== previous && (known.ops.length < previous.ops.length ||
        policyOpHash(known.ops[previous.ops.length - 1]) !== previous.policy.headHash)) {
      throw new Error("Workspace policy rollback or fork");
    }
    return known;
  }
  const ops = response.ops;
  if (!Array.isArray(ops) || !ops.length) throw new Error("Empty workspace policy log");
  // Exact signed bytes matter: the operation hash alone omits its signatures.
  if (previous) {
    if (ops.length < previous.ops.length) throw new Error("Workspace policy rollback or fork");
    if (!equal(ops.slice(0, previous.ops.length), previous.ops)) {
      // A different signature for the same operation must still be verified.
      // Only an independently valid log extending the pinned head may replace it.
      const verified = verifyPolicyResponse(workspace, response, undefined, mismatch, realm);
      if (policyOpHash(ops[previous.ops.length - 1]) !== previous.policy.headHash) {
        throw new Error("Workspace policy rollback or fork");
      }
      return verified;
    }
  }
  let policy = previous?.policy ?? null;
  const authors = previous?.authors.slice() ?? [];
  for (const op of ops.slice(authors.length)) {
    policy = applyPolicyOp(policy, op, realm);
    authors.push(recordAuthorsAtVersion(policy, realm));
  }
  if (!policy || policy.workspaceId !== workspace || !equal(policy, response.policy)) {
    throw new Error(mismatch);
  }
  if (previous && policy === previous.policy) return previous;
  return { policy, ops: structuredClone(ops), authors, realm };
}

export function copyPolicy({ policy, ops }: PolicyResponse): PolicyResponse {
  return structuredClone({ policy, ops });
}

export function verifiedAuthor(log: VerifiedPolicy): AuthorPolicyCheck {
  return (header, capability) => log.authors[header.authorPolicyVersion - 1]?.(header, capability) === true;
}
