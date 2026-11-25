# Workspace wire format: realms and support

Additions to the version 1 workspace wire format for the support realm. Every
signed format (policy operation hash, challenge, record AAD and signature,
key envelope, identity link and rotation) is byte-identical in both realms.
Realms differ only in routing, session tokens, accepted record types and one
policy operation.

## Realms

`Realm` is `"workspaces"` (default) or `"support"`. `WorkspaceClient`,
`WorkspaceKeyring`, `applyPolicyOp`, `replayPolicy`, `policyAuthorCheck`,
`verifyInviteBundle` and the record functions take it as an optional last
argument. Omitting it gives the existing behaviour.

| | `workspaces` | `support` |
| --- | --- | --- |
| Workspace and invite routes | `/workspaces...`, `/invites...` | `/support/workspaces...`, `/support/invites...` |
| Discovery challenge | `/identity/challenge` | `/support/identity/challenge` |
| Identity registry | `/identity/links`, `/identity/rotations` | the same, shared |
| Session token | `mirage_ws_` + 43 base64url characters | `mirage_sp_` + 43 base64url characters |
| Record types | `payment_request`, `decision`, `execution_event`, `contact`, `payment_template`, `roster` | `support_ticket`, `support_message`, `support_report`, `support_feedback`, `support_identity`, `roster` |
| `add_support_member` | rejected | accepted, through its own route |
| Personal workspaces | yes | no |

A client rejects a session token with the other realm's prefix, a record whose
type is not in its realm's list, and a policy log that contains
`add_support_member` unless it replays in the support realm. A workspace id exists in
one realm only.

Staff routes live under `/support/admin` and are authorized by a `mirage_sp_`
session for the staff workspace: `GET /support/admin/workspaces?since=&limit=`
and `POST` or `DELETE /support/admin/workspaces/{id}/block`.

## Policy operation `add_support_member`

`add_member` is invite acceptance only, in both realms, and is unchanged.
Provisioning the support key is its own kind:

```text
kind: "add_support_member"
payload: { key: { memberKeyId, kemPublicKey, generation }, envelopes: [Envelope...] }
```

The payload carries no member id and no capabilities. Replay always adds
member id `0x6d69726167652d737570706f72740000` (ASCII `mirage-support` and
two zero bytes) with `caps` 8 and no admin. Replay rules:

- The kind is accepted only in the support realm.
- The signer is a current key with `holdsAdmin`, and the operation carries a
  valid admin co-signature over the operation hash.
- The support member id has never appeared in the workspace and
  `key.memberKeyId` has never appeared in the workspace. `key` passes the
  same validation as a creator key.
- `envelopes` are exactly one `content` envelope addressed to the new key for
  each content epoch the signer key holds an envelope for. An admin envelope,
  a missing epoch, a duplicate or another recipient rejects the operation.
- The content epoch, admin key, admin epoch and thresholds do not change.

The resulting member is `{memberId, caps: 8, addedAtVersion: policyVersion,
removedAtVersion: null, voteInvalidatedAtVersion: 0}` with the single key
`{...key, holdsAdmin: false, addedAtVersion: policyVersion,
removedAtVersion: null}`.

The signed operation is submitted to
`POST /support/workspaces/{ws}/support-member`, with the same authorization
and response as `policy/ops`. That route accepts no other kind, and
`policy/ops` does not accept this one. The API admits it only when `key` is
the current support key; a stale generation is answered with 409, after which
the client refetches the rotation chain and retries.

Shared vectors: `test/fixtures/workspaces.json`, key `support`, copied
verbatim from the API repository.

## Support key chain

`GET /support/config` returns `{rootKeyId, rootKem, supportMemberId,
staffWorkspaceId, rotations, current}`. Clients pin the generation-0 pair
`{rootKeyId, rootKem}` at build time and verify the response before use:

- `rootKeyId` and `rootKem` equal the pinned pair.
- `rotations` is a contiguous chain of cross-signed `MirageIdentityRotation`
  pointers starting at the root: each `oldKey` and `oldKem` equal the previous
  key pair, generations increase by one from 1, no key repeats, at most 64.
- `current` equals the tip of that chain.

A caller can pass the highest generation it has seen to refuse a truncated
chain. Each support generation is an independent random secp256k1 key whose
member keys come from the ordinary unlock signature for that generation.

## Support record types

All require the `WRITE` capability (8). In the support realm `support_identity`
and `roster` additionally require the author key to hold admin at
`authorPolicyVersion`. Bodies are canonical JSON, validated after decryption;
unknown fields are rejected unless noted.

```text
support_ticket   { version: 1, kind, subject (1..200 chars), category: support (legacy: transaction|bug|feedback|other),
                   status: open|closed, createdAt: ISO, closedAt?: ISO, closedBy?: user|support,
                   reportIds: bytes32[] }
support_message  { version: 1, kind, ticketId: bytes32, text (1..8000 chars), sentAt: ISO, staffLabel? }
support_report   { version: 1, kind, ticketId?: bytes32, createdAt: ISO, clientVersion, userAgent, note?: text (1..8000 chars),
                   error: { message, code?, step: approve|deploy|execute|cancel|other },
                   transaction: { allowlisted fields } }
support_feedback { version: 1, kind, text (1..8000 chars), createdAt: ISO }
support_identity { version: 1, kind, generations: [{ generation, privateKey: bytes32, address }],
                   pendingRotation?: generation }
roster           { version: 1, workspaceName?, memberLabels?: { memberId: label },
                   invitationLabels?: { grantId: label } }
tombstone        { version: 1, kind: <record type>, deleted: true }
```

Device signers sign the SIWE statement `Submit encrypted feedback and reports to Mirage.` to obtain a support-only principal. Its workspace sessions use the `mirage_sp_guest_` prefix and can write `support_feedback` and `support_report`. A regular wallet or email sign-in is required for ticket and message writes.

- `closedAt` and `closedBy` are present exactly when `status` is `closed`.
- ISO timestamps are the `Date.prototype.toISOString` form.
- A `support_message` is written once. Its only later revision is revision 2,
  a tombstone; any other later revision is hidden by clients.
- `staffLabel` is displayed only when the author is the support member.
- A tombstone replaces the stored revision, which erases the earlier content
  from the server because only the latest revision is kept.
- `support_identity` lives in the staff workspace under the fixed record id
  `sha256("mirage-support-identity-v1")`. `generations` is contiguous from 0.
  `pendingRotation` names the newest generation while its rollout to user
  workspaces is unfinished.

"From support" is decided from the verified policy log, never from the body:
a record is from support when its `authorKeyId` is one of the keys, current or
retired, of the support member. A user's own member is never the support
member.

### Report transaction allowlist

`transaction` carries only these fields of the local transaction record.
Other fields, and listed fields with an unexpected type, are dropped when the
report is built and again when it is read.

- Transfer: `status`, `chainId`, `date`, `recipient`, `recipientENS`,
  `amount`, `tokenAddress`, `tokenSymbol`, `tokenDecimals`, `transfers`
  (rows of `recipient`, `recipientENS`, `amount`, `tokenAddress`, `decimals`,
  `symbol`).
- Transactions: `approveTxHash`, `approveTxHashes`, `deployTxHash`,
  `submitTxHash`, `submitTxHashes`, `cancelTxHash`.
- Escrow: `escrowAddress`, `escrowType`, `quoteCommitment`, `senderAddress`,
  `nativeEth`, `deployedAt`, `fromBlock`.
- Funding: `depositByAsset` (raw units keyed by asset address), `msgValue`.
- Secrets, sent nowhere else: `seed`, `selectorMapping`, `blindingScalar`,
  `sealedPricingAuthorization`.
- Fees and gas: `totalFeeUsd`, `networkFeeUsd`, `tokenTotalUsd`,
  `transfersTotalUsd` (decimal strings), `serviceFeeAsset`,
  `serviceFeeAmount`, `rewardAsset`, `sdkRewardAmount`, `userApproveGas`,
  `userDeployGas`, `userGasPrice`.
- Progress: `approval` (`version`, `chainId`, `escrowContract`,
  `deploymentTxHash`, `runtimeCodeHash`, `quoteCommitment`, `approvedAt`,
  `signature`), `signalSubmitted`, `approveBroadcasted`.
