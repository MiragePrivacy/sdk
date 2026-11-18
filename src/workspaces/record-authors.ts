import type { Hex } from "viem";
import type { Policy } from "./policy";
import type { AuthorPolicyCheck } from "./records";

/** Historical record checks need capabilities and content grants, not envelope ciphertext. */
export function recordAuthorsAtVersion(policy: Policy): AuthorPolicyCheck {
  const { workspaceId, policyVersion, keyEpoch } = policy;
  const authors = new Map<Hex, { caps: number; epochs: Set<number> }>();
  for (const member of policy.members) {
    if (member.removedAtVersion !== null) continue;
    for (const key of member.keys) {
      if (key.removedAtVersion === null) authors.set(key.memberKeyId, { caps: member.caps, epochs: new Set() });
    }
  }
  for (const envelope of policy.envelopes) {
    if (envelope.kind === "content") authors.get(envelope.recipientKeyId)?.epochs.add(envelope.epoch);
  }
  return (header,capability) => {
    const author = authors.get(header.authorKeyId);
    return header.workspaceId === workspaceId && header.authorPolicyVersion === policyVersion && header.keyEpoch <= keyEpoch
      && !!author && (author.caps & capability) === capability && author.epochs.has(header.keyEpoch);
  };
}
