import { concatHex, keccak256, pad, toHex, type Address } from "viem";

/**
 * Byte-exact encoders for the ZK receipt protocol, mirroring
 * `nomad-types::zk`. The escrow recomputes the statement from its own storage
 * and the circuit reproves the relation, so a single byte of disagreement
 * makes every proof fail with no indication of which side is wrong. Widths are
 * fixed by the protocol spec and are not negotiable per call site.
 */

/**
 * Protocol relation version committed by the intent commitment. Bumping this
 * invalidates every previously generated proof.
 */
export const RELATION_VERSION = 2;

/** Domain tag separating salt derivation from every other use of the scalar. */
const SALT_DOMAIN = "mirage/zk/intent-salt/v1";

/** Settlement asset class committed inside the intent commitment. */
export const ASSET_KIND_NATIVE = 0;
export const ASSET_KIND_ERC20 = 1;

/**
 * Classifies a settlement asset. The zero address is native by convention
 * everywhere in the protocol. The commitment carries an explicit byte rather
 * than inferring native settlement from a zero token address, so a native row
 * can never be read as an ERC-20 row whose token encodes as zero.
 */
export function assetKind(asset: Address): number {
  return /^0x0{40}$/i.test(asset) ? ASSET_KIND_NATIVE : ASSET_KIND_ERC20;
}

/** Private opening of one settlement row. Never leaves the client or enclave. */
export interface IntentOpening {
  instanceDomain: `0x${string}`;
  chainId: number;
  /** Predicted escrow address, fixed so a proof cannot be replayed elsewhere. */
  escrow: Address;
  requestId: `0x${string}`;
  rowIndex: number;
  /** Settlement token, or the zero address for native ETH. */
  asset: Address;
  recipient: Address;
  amount: bigint;
  salt: `0x${string}`;
}

function uint32(value: number): `0x${string}` {
  return pad(toHex(value), { size: 4 });
}

/**
 * Derives the commitment salt from material both sides already hold.
 *
 * The salt must be secret, and both the depositor and the enclave must arrive
 * at the same value. Deriving it from the blinding scalar avoids threading a
 * new field through the SDK, the API, and the Signal envelope. The instance
 * domain and request id are folded in so a scalar reused across deployments
 * still yields distinct salts.
 */
export function deriveSalt(
  blindingScalar: `0x${string}`,
  instanceDomain: `0x${string}`,
  requestId: `0x${string}`,
  rowIndex: number,
): `0x${string}` {
  return keccak256(
    concatHex([
      toHex(SALT_DOMAIN),
      pad(blindingScalar, { size: 32 }),
      pad(instanceDomain, { size: 32 }),
      pad(requestId, { size: 32 }),
      uint32(rowIndex),
    ]),
  );
}

/** Exact commitment preimage, exposed so fixtures can compare bytes. */
export function intentPreimage(opening: IntentOpening): `0x${string}` {
  return concatHex([
    pad(toHex(RELATION_VERSION), { size: 1 }),
    pad(opening.instanceDomain, { size: 32 }),
    pad(toHex(opening.chainId), { size: 32 }),
    opening.escrow,
    pad(opening.requestId, { size: 32 }),
    uint32(opening.rowIndex),
    pad(toHex(assetKind(opening.asset)), { size: 1 }),
    opening.asset,
    opening.recipient,
    pad(toHex(opening.amount), { size: 32 }),
    pad(opening.salt, { size: 32 }),
  ]);
}

/** Value stored on the escrow and recomputed inside the circuit. */
export function intentCommitment(opening: IntentOpening): `0x${string}` {
  return keccak256(intentPreimage(opening));
}

/** Fresh 32-byte random value for the per-deployment domain and request id. */
export function randomBytes32(): `0x${string}` {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `0x${Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")}`;
}
