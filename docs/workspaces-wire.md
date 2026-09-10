# Workspace wire cryptography, version 1

This is the first phase-1 implementation increment, exported separately as
`@mirageprivacy/sdk/workspaces`. It implements member keys, HPKE key envelopes,
encrypted records, cross-signed links and generation discovery. Personal-workspace
unlock, completed-history mapping and sync orchestration are implemented.
The frontend has a durable outbox and an explicit local-history import choice;
linked-identity Settings and the remaining team flows are still in progress.
Phase-1 policy replay is implemented as described below. The live Privy determinism
check remains a release prerequisite.

## Encoding

Wire objects use camelCase except encrypted inner `content_hash`. Hex is lowercase
with a `0x` prefix. Workspace IDs are 16 bytes; record IDs and signing/KEM public
keys are 32 bytes. New record IDs are random 32 bytes; the history adapter will use
the specified SHA-256 import ID. Epochs and generations are uint32; revisions,
policy versions and Unix-second timestamps use uint64 ABI words but must fit
JavaScript's safe-integer range. Generations start at 0; epochs, revisions and
policy versions start at 1.

Digests use `keccak256(abi.encode(typeHash, fields...))`, with the type hash equal
to keccak256 of the exact UTF-8 type declaration exported from each module.
Dynamic strings are represented by their keccak256 hash. This is typed ABI
hashing, without an EIP-191/EIP-712 domain prefix; Ed25519 signs the 32 digest
bytes directly. Only the wallet unlock uses EIP-712.

Ed25519 public keys and signature R points must have canonical encodings, be
nonzero and belong to the prime-order subgroup. Both implementations enforce
this explicitly before library verification. A shared mixed-order rejection
vector pins this requirement; selecting `zip215: false` alone is insufficient.

Unlock uses the spec's domain and message. Derivation consumes a 65-byte RSV
signature, normalizing recovery parity 0/1 to 27/28 and requiring valid low-S
secp256k1 scalars. HKDF-SHA256 uses UTF-8 salt `mirage-member-v1`, with `sign` and
`kem` info labels and 32-byte outputs. Generation is bound by the signed unlock
message. `unlockMember` verifies the returned signature against the requested
wallet address. `deriveMemberKeys` is the low-level derivation primitive and
requires a signature over that generation's unlock message.

Private keys stay in caller-owned memory. Call `disposeMemberKeys` on logout and
discard every workspace key. JavaScript zeroization is best effort; signatures
and runtime copies cannot be reliably erased. Never log or serialize the root
signature or private arrays. No module here writes browser storage or sends HTTP.

## Envelopes

HPKE base mode uses DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM.
Info is UTF-8 `mirage-envelope-v1`, followed by the raw 16-byte workspace ID,
ASCII `content` or `admin`, and a 4-byte big-endian epoch. HPKE AAD is empty.
Plaintext is exactly 32 bytes: an epoch content key or an Ed25519 admin seed.
`enc` is 32 bytes and ciphertext is 48 bytes, including the GCM tag.

Every seal uses a fresh one-message sender context. `openKey` takes expected
workspace/kind/epoch/recipient metadata and rejects mismatches. The caller must
authenticate the envelope through the verified policy log and its committed
recipient signing/KEM pair; recipient metadata alone is not an authorization
proof. No Rust production API opens envelopes; its HPKE dependency is test-only.

The maintained implementation is [hpke-js](https://github.com/dajiaji/hpke-js).
Its locked `@hpke/core` version is newer than the fix for the
[concurrent-context nonce-reuse advisory](https://github.com/dajiaji/hpke-js/security/advisories/GHSA-73g8-5h73-26h4).

## Records

Body encoding is deterministic JSON: UTF-16-sorted object keys, original array
order, ordinary JSON string escaping and valid Unicode. Values are null,
booleans, strings, safe integers, arrays and plain objects. Fractional numbers,
negative zero, large numeric values, sparse arrays, non-JSON values, accessors,
cycles, discarded array properties and excessive nesting are rejected. Encode
amounts and arbitrary-precision quantities as decimal strings.

AES-256-GCM encrypts `{body,content_hash}` with a random 12-byte nonce and a
128-bit tag. The inner hash is SHA-256 of the canonical UTF-8 body. It is never a
public field. Identical bodies keep the same encrypted inner hash when they are
re-encrypted, but fresh nonces produce different ciphertext. The ciphertext size
limit is 1 MiB including the tag.

AAD is the ABI encoding of the type hash and fields in this declaration:

```text
MirageRecordAAD(bytes16 workspaceId,bytes32 recordId,string recordType,uint64 revision,uint32 keyEpoch,uint64 authorPolicyVersion)
```

The author signs the typed hash of:

```text
MirageRecord(bytes32 aadHash,bytes32 authorKeyId,bytes12 nonce,bytes32 ciphertextHash)
```

`aadHash` and `ciphertextHash` are keccak256 hashes. Server creation/update times
are not part of the signed record. They cannot be used as sync cursors.

`openRecord` requires a historical-author authorization callback, verifies the
Ed25519 signature using strict verification, checks authorization, decrypts,
then verifies the inner content hash. The callback must use a verified policy
log, including the author's membership, capability and epoch at
`authorPolicyVersion`. It must also check the expected workspace, record and
revision from the caller's sync context. Required capability is PROPOSE for
payment requests, VOTE for decisions and WRITE for other record types. The API
signature helper deliberately does not claim to validate policy, freshness,
current write access or append-only history rules; storage must enforce those.

## Links and rotation pointers

Links sort distinct signing keys in ascending byte order. Both keys sign the
same hash, which binds each signing/KEM pair and issue time. Rotations bind old
and new signing/KEM pairs, the new generation and issue time. Both old and new
signing keys sign the pointer. Exact declarations:

```text
MirageIdentityLink(bytes32 keyA,bytes32 kemA,bytes32 keyB,bytes32 kemB,uint64 issuedAt)
MirageIdentityRotation(bytes32 oldKey,bytes32 oldKem,bytes32 newKey,bytes32 newKem,uint32 generation,uint64 issuedAt)
```

Discovery requires a contiguous generation chain, starting from the caller's
known key. It re-derives and checks each replacement signing and KEM key. The
helper bounds a response at 64 pointers; longer histories require a subsequent
discovery request. It discards intermediate derived private keys, leaving the
caller responsible for the initial and final keys. Neither a link nor a pointer
grants workspace membership, envelope access or a session. Those require signed
policy transitions and current membership checks in the next increment.

## Policy operations

Phase-1 operations use the exact outer declaration:

```text
MiragePolicyOp(bytes16 workspaceId,uint64 policyVersion,bytes32 prevOpHash,string kind,bytes32 payloadHash,uint64 issuedAt,bytes32 signerKeyId)
```

`payloadHash` is keccak256 of the canonical JSON payload after strict schema
validation. An actor signature covers this typed hash. Owner operations also
carry a current-admin co-signature over the same hash; a link uses the actor's
signature and the independently cross-signed link. The creator proves possession
of both the initial member and admin keys. Unknown fields and operations fail
closed. Future invitation/recovery operations will extend the payload schemas.

Every epoch change increments once and includes exactly one current-content
envelope per remaining key. Revoking owner authority also changes the admin
public key and supplies exactly one replacement admin envelope per remaining
owner key. Content-only rotations preserve `adminEpoch`; newly linked owner keys
receive that admin envelope even when its epoch is older than the content epoch.
Linked keys inherit the actor key's authority and all content epochs granted to
that key. Member-generation replacement preserves those historical grants and
revokes the old generation. The DB reserves personal workspace keys to prevent
two simultaneous devices creating separate personal workspaces for one identity.

`policyAuthorCheck` first verifies the entire log, then checks membership,
capabilities and epoch grants at the author's recorded policy version. A client
must additionally pin its known policy head and expected record context to reject
rollback; current writes require current authority at the API transaction boundary.

## Shared vectors

`test/fixtures/workspaces.json` is byte-identical to
`api/tests/vectors/workspaces.json`. All contained signatures, seeds and keys are
public test material. The two generation signatures are pinned to the disposable
`0x0101…0101` wallet. Rust independently checks HKDF, both public keys, record
AAD/hashes/decryption and link/rotation signatures. Both languages open envelopes
produced by each implementation. Tests alter every AAD field and check that
re-signing a moved ciphertext still cannot make GCM accept it.

Run `npm test`, `npm run check`, `npm run build`, then:

```sh
node scripts/check-workspace-vectors.mjs /path/to/api/tests/vectors/workspaces.json
```

Regeneration is explicit and changes ciphertext because the JS producer uses
fresh randomness:

1. Build the SDK and run `node scripts/generate-workspace-vectors.mjs`.
2. Copy its fixture to `api/tests/vectors/workspaces.json`.
3. In the API, run `MIRAGE_REGENERATE_WORKSPACE_VECTORS=1 cargo test --lib workspaces::tests::rust_envelope_vector_is_reproducible`.
4. Copy the resulting API fixture back to the SDK verbatim and run both suites.

The API's `Workspace interoperability` workflow accepts an explicit SDK ref,
diffs the files and runs both languages' tests. It uses the repository's existing
SSH key with read access to the paired repositories. Trigger it once both refs
are pushed; local worktree tests do not verify that hosted CI configuration.

## Identity lifecycle commitments

Global unlink uses the typed declaration
`MirageIdentityUnlink(bytes32 linkId,bytes32 remainingKey,bytes32 revokedKey,uint64 issuedAt)`.
The remaining key signs its ABI digest; a discovery signature cannot authorize
deletion. `linkId` is `linkHash` of the original cross-signed link. Either key
may refer to a verified replacement generation in its respective branch.
`linkedKeyBranches` rejects forged, disconnected, overlapping or cyclic
generation chains before the client trusts link membership metadata.

The SDK `links()` method consumes a discovery challenge. `deleteLink()` signs
an unlink proof and accepts the API's 204 success; 409 means revocations are
still required. The API sets `unlinking` on the first authorized request,
freezing new enrollment while the client completes affected workspaces.
Workspace IDs in link metadata confer no record or session authority.

`scripts/generate-identity-lifecycle-vectors.mjs` adds independent sealed
workspaces and the unlink hash/signature to the shared fixture. Rebuild the
SDK before running it, copy the reviewed fixture verbatim to the API, then run
the comparison script and both test suites.

`link_key` retains its original fields and optionally includes a nonempty
`rotations` array of signed identity pointers. Both policy replayers verify
complete, disjoint chains starting at the cross-signed link roots. The actor
may be a verified generation in its branch; the enrolled peer must be the
provided opposite branch's final key, KEM key and generation. The API also
requires all pointers to match the registry and rejects targets with a known
successor. This keeps previously committed policies replayable while refusing
new enrollment based on an obsolete global snapshot. `prepareLinkedKey`
accepts either the original link or its verified `IdentityLinkState`; use the
latter when either sign-in has rotated.

`WorkspaceKeyring.prepareRemoveKey` creates complete replacement content/admin
envelopes and a signed revocation operation. `prepareMemberRotation` also seals
retained history to the new generation. Pass the same signed rotation pointer
to every affected workspace; it is a global identity commitment. Both methods
return public signed operations and wipe temporary private key material.

`unlinkOtherIdentity` accepts the caller-owned unlocked generations of one
sign-in. It freezes enrollment before workspace updates, verifies the updated
link state, retries policy-head conflicts, and completes global deletion only
after server authorization checks pass. Missing workspace authority leaves the
unlink pending for another owner's assistance. Aborted runs resume from the
signed server state; the coordinator does not own or persist member secrets.
