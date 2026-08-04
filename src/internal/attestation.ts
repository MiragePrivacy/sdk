import { sha256 } from "@noble/hashes/sha2.js";
import { MirageError } from "../errors.js";
import type { AttestationPayload, AttestationVerification, TcbStatus } from "../types.js";

/** TCB states accepted by default. Anything else is a stale or revoked platform. */
const DEFAULT_ALLOWED_TCB: TcbStatus[] = ["UpToDate", "SWHardeningNeeded"];

/** Offsets of the flag bytes the enclave packs into the 64-byte report data. */
const REPORT_DATA_LEN = 64;
const IS_METRICS_OFFSET = 61;
const IS_DEBUG_OFFSET = 62;
const IS_GLOBAL_OFFSET = 63;

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new MirageError("INVALID_ATTESTATION", `Expected hex, got "${hex}"`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function u64BigEndian(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

/**
 * Canonical payload commitment, matching the enclave's
 * `sha256(public_key . chain_id_be . max_balance_usd_be . compliance_keys)`.
 *
 * Compliance keys are hashed in the order given; the enclave sorts and
 * deduplicates them when constructing the payload, so the served order is
 * already canonical and must not be re-sorted here.
 */
export function hashAttestationPayload(payload: AttestationPayload): Uint8Array {
  const publicKey = hexToBytes(payload.publicKey);
  if (publicKey.length !== 33) {
    throw new MirageError(
      "INVALID_ATTESTATION",
      `Expected a 33-byte compressed public key, got ${publicKey.length} bytes`,
    );
  }

  const keys = (payload.complianceKeys ?? []).map((key) => {
    const bytes = hexToBytes(key);
    if (bytes.length !== 32) {
      throw new MirageError(
        "INVALID_ATTESTATION",
        `Expected a 32-byte compliance key, got ${bytes.length} bytes`,
      );
    }
    return bytes;
  });

  const parts = [
    publicKey,
    u64BigEndian(BigInt(payload.chainId)),
    u64BigEndian(BigInt(payload.maxBalanceUsd ?? 0)),
    ...keys,
  ];

  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const buffer = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    buffer.set(part, offset);
    offset += part.length;
  }

  return sha256(buffer);
}

/** Decode the enclave's report body from the quote's 64-byte report data. */
export function parseReportData(reportData: Uint8Array): {
  payloadHash: Uint8Array;
  timestamp: number;
  isMetrics: boolean;
  isDebug: boolean;
  isGlobal: boolean;
} {
  if (reportData.length !== REPORT_DATA_LEN) {
    throw new MirageError(
      "INVALID_ATTESTATION",
      `Expected ${REPORT_DATA_LEN} bytes of report data, got ${reportData.length}`,
    );
  }

  let timestamp = 0n;
  for (let i = 32; i < 40; i++) {
    timestamp = (timestamp << 8n) | BigInt(reportData[i]);
  }

  return {
    payloadHash: reportData.slice(0, 32),
    timestamp: Number(timestamp),
    isMetrics: reportData[IS_METRICS_OFFSET] !== 0,
    isDebug: reportData[IS_DEBUG_OFFSET] !== 0,
    isGlobal: reportData[IS_GLOBAL_OFFSET] !== 0,
  };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export interface VerifyAttestationOptions {
  /**
   * Reject the quote unless MRSIGNER matches one of these (hex). This is the
   * signing identity, which is stable across enclave releases; MRENCLAVE is
   * deliberately not pinned, since it changes on every rebuild.
   */
  expectedMrSigner?: string[];
  /** Accepted TCB states. Defaults to UpToDate and SWHardeningNeeded. */
  allowedTcbStatus?: TcbStatus[];
  /** Reject Intel advisories not included in this allowlist. */
  allowedAdvisoryIds?: string[];
  /** Reject enclaves whose verified ISVSVN is below this value. */
  minimumIsvSvn?: number;
  /** Accept debug-mode enclaves. Never enable against production nodes. */
  allowDebug?: boolean;
  /** Require the attestation to be for the global key. Defaults to true. */
  requireGlobal?: boolean;
  /** Reject a report older than this. Defaults to 24 hours; 0 disables. */
  maxAgeSecs?: number;
  /** Verification time, for reproducible tests. Defaults to now. */
  nowSecs?: number;
}

const DEFAULT_MAX_AGE_SECS = 86_400;
/**
 * Tolerance for clock differences between the quoting platform and the client.
 * Anything further ahead is rejected: a future timestamp would otherwise
 * produce a negative age and defeat the freshness check entirely.
 */
const MAX_CLOCK_SKEW_SECS = 300;

/**
 * Verify an SGX quote and bind it to the served attestation payload.
 *
 * Establishes that the enclave measurement is signed by Intel, that its TCB is
 * acceptable, and that the public key used to encrypt signals is the one the
 * enclave committed to. Without this the key is merely asserted by whatever
 * host answered the request.
 */
export async function verifyAttestation(
  attestation: { quote: string; collateral: unknown },
  payload: AttestationPayload,
  options: VerifyAttestationOptions = {},
): Promise<AttestationVerification> {
  const {
    expectedMrSigner,
    allowedTcbStatus = DEFAULT_ALLOWED_TCB,
    allowedAdvisoryIds,
    minimumIsvSvn,
    allowDebug = false,
    requireGlobal = true,
    maxAgeSecs = DEFAULT_MAX_AGE_SECS,
    nowSecs = Math.floor(Date.now() / 1000),
  } = options;

  if (
    minimumIsvSvn !== undefined &&
    (!Number.isInteger(minimumIsvSvn) || minimumIsvSvn < 0 || minimumIsvSvn > 65_535)
  ) {
    throw new MirageError(
      "INVALID_ATTESTATION_POLICY",
      "minimumIsvSvn must be an integer between 0 and 65535",
      { meta: { minimumIsvSvn } },
    );
  }

  const { QuoteVerifier } = await import("@phala/dcap-qvl");

  const quoteBytes = hexToBytes(attestation.quote);

  let verified;
  try {
    verified = QuoteVerifier.newProd()
      .allowDebug(allowDebug)
      .verify(quoteBytes, attestation.collateral as never, nowSecs);
  } catch (cause) {
    throw new MirageError("ATTESTATION_VERIFICATION_FAILED", "SGX quote verification failed", {
      cause,
    });
  }

  if (!allowedTcbStatus.includes(verified.status as TcbStatus)) {
    throw new MirageError(
      "ATTESTATION_TCB_REJECTED",
      `Enclave TCB status "${verified.status}" is not accepted`,
      { meta: { status: verified.status, advisoryIds: verified.advisory_ids } },
    );
  }

  const advisoryIds = verified.advisory_ids ?? [];
  if (allowedAdvisoryIds !== undefined) {
    const allowed = new Set(allowedAdvisoryIds);
    const disallowedAdvisoryIds = advisoryIds.filter((id: string) => !allowed.has(id));
    if (disallowedAdvisoryIds.length > 0) {
      throw new MirageError(
        "ATTESTATION_TCB_REJECTED",
        `Enclave TCB reported disallowed advisories: ${disallowedAdvisoryIds.join(", ")}`,
        {
          meta: {
            status: verified.status,
            advisoryIds,
            disallowedAdvisoryIds,
            allowedAdvisoryIds,
          },
        },
      );
    }
  }

  const sgx = verified.report.asSgx();
  if (!sgx) {
    throw new MirageError(
      "ATTESTATION_VERIFICATION_FAILED",
      "Expected an SGX enclave report, got a TDX report",
    );
  }

  const mrEnclave = bytesToHex(sgx.mrEnclave);
  const mrSigner = bytesToHex(sgx.mrSigner);
  const isvSvn = sgx.isvSvn;

  if (minimumIsvSvn !== undefined && isvSvn < minimumIsvSvn) {
    throw new MirageError(
      "ATTESTATION_TCB_REJECTED",
      `Enclave ISVSVN ${isvSvn} is below the required minimum ${minimumIsvSvn}`,
      {
        meta: {
          status: verified.status,
          advisoryIds,
          isvSvn,
          minimumIsvSvn,
        },
      },
    );
  }

  // MRSIGNER identifies who signed the enclave and survives rebuilds, so it is
  // the measurement worth pinning. MRENCLAVE is reported but not checked: it
  // changes with every release, and pinning it would break on each upgrade.
  if (expectedMrSigner?.length) {
    const expected = expectedMrSigner.map((v) => v.replace(/^0x/, "").toLowerCase());
    if (!expected.includes(mrSigner)) {
      throw new MirageError("ATTESTATION_MEASUREMENT_MISMATCH", `Unexpected MRSIGNER ${mrSigner}`, {
        meta: { mrSigner, expected: expectedMrSigner },
      });
    }
  }

  const report = parseReportData(sgx.reportData);

  // The quote commits only to this hash, so the served payload is untrusted
  // until it reproduces it. This is what binds the public key to the enclave.
  if (!equalBytes(report.payloadHash, hashAttestationPayload(payload))) {
    throw new MirageError(
      "ATTESTATION_PAYLOAD_MISMATCH",
      "Attestation payload does not match the hash committed in the quote",
    );
  }

  if (report.isDebug && !allowDebug) {
    throw new MirageError(
      "ATTESTATION_DEBUG_ENCLAVE",
      "Enclave is running in debug mode; its memory is not protected",
    );
  }

  if (requireGlobal && !report.isGlobal) {
    throw new MirageError(
      "ATTESTATION_NOT_GLOBAL",
      "Attestation is not for the global key used to encrypt signals",
    );
  }

  if (report.isMetrics) {
    throw new MirageError(
      "ATTESTATION_NOT_GLOBAL",
      "Attestation is a metrics snapshot, not a key attestation",
    );
  }

  if (maxAgeSecs > 0) {
    const age = nowSecs - report.timestamp;
    if (age < -MAX_CLOCK_SKEW_SECS) {
      throw new MirageError(
        "ATTESTATION_STALE",
        `Attestation is dated ${-age}s in the future, exceeding the ${MAX_CLOCK_SKEW_SECS}s clock skew allowance`,
        { meta: { timestamp: report.timestamp, nowSecs, maxClockSkewSecs: MAX_CLOCK_SKEW_SECS } },
      );
    }
    if (age > maxAgeSecs) {
      throw new MirageError(
        "ATTESTATION_STALE",
        `Attestation is ${age}s old, exceeding the ${maxAgeSecs}s limit`,
        { meta: { timestamp: report.timestamp, maxAgeSecs } },
      );
    }
  }

  return {
    verified: true,
    tcbStatus: verified.status as TcbStatus,
    advisoryIds,
    mrenclave: mrEnclave,
    mrsigner: mrSigner,
    isvSvn,
    debug: report.isDebug,
    timestamp: report.timestamp,
  };
}
