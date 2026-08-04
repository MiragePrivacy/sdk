import { describe, it, expect, vi } from "vitest";
import { hashAttestationPayload, parseReportData } from "../src/internal/attestation.js";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Deterministic 33-byte compressed key, matching the Rust reference generator.
const PUBLIC_KEY = `0x${Array.from({ length: 33 }, (_, i) => ((i * 7 + 2) & 0xff).toString(16).padStart(2, "0")).join("")}`;

describe("hashAttestationPayload", () => {
  // Vectors produced by the enclave's own sha2 implementation:
  //   sha256(public_key . chain_id_be . max_balance_usd_be . compliance_keys)
  // A mismatch here rejects every otherwise-valid attestation.
  it("matches the enclave hash with no compliance keys", () => {
    expect(toHex(hashAttestationPayload({ publicKey: PUBLIC_KEY, chainId: 1 }))).toBe(
      "15a37d547941561793cf8912ef339dfe33467ef0e1130134bdb81eb28cfa84a7",
    );
  });

  it("matches the enclave hash with a chain id and max balance", () => {
    expect(
      toHex(
        hashAttestationPayload({
          publicKey: PUBLIC_KEY,
          chainId: 42431,
          maxBalanceUsd: 5000,
        }),
      ),
    ).toBe("952c5a6e03291b922c494297c1b9157a25b338deccfaa81f5e6a1884dec2427e");
  });

  it("matches the enclave hash with compliance keys appended in order", () => {
    expect(
      toHex(
        hashAttestationPayload({
          publicKey: PUBLIC_KEY,
          chainId: 1,
          complianceKeys: [`0x${"11".repeat(32)}`, `0x${"ab".repeat(32)}`],
        }),
      ),
    ).toBe("a43b16d9af6946efbfa6fcef0cc7c2dca952bce8ef68c540309309d6eaf693e2");
  });

  it("treats a missing maxBalanceUsd as zero", () => {
    const withDefault = hashAttestationPayload({ publicKey: PUBLIC_KEY, chainId: 1 });
    const explicit = hashAttestationPayload({
      publicKey: PUBLIC_KEY,
      chainId: 1,
      maxBalanceUsd: 0,
    });
    expect(toHex(withDefault)).toBe(toHex(explicit));
  });

  it("accepts a key without the 0x prefix", () => {
    expect(toHex(hashAttestationPayload({ publicKey: PUBLIC_KEY.slice(2), chainId: 1 }))).toBe(
      "15a37d547941561793cf8912ef339dfe33467ef0e1130134bdb81eb28cfa84a7",
    );
  });

  it("does not reorder compliance keys, which the enclave already sorted", () => {
    const ascending = hashAttestationPayload({
      publicKey: PUBLIC_KEY,
      chainId: 1,
      complianceKeys: [`0x${"11".repeat(32)}`, `0x${"ab".repeat(32)}`],
    });
    const reversed = hashAttestationPayload({
      publicKey: PUBLIC_KEY,
      chainId: 1,
      complianceKeys: [`0x${"ab".repeat(32)}`, `0x${"11".repeat(32)}`],
    });
    expect(toHex(ascending)).not.toBe(toHex(reversed));
  });

  it("rejects a public key of the wrong length", () => {
    expect(() => hashAttestationPayload({ publicKey: "0xdeadbeef", chainId: 1 })).toThrow(
      /33-byte/,
    );
  });

  it("rejects a malformed compliance key", () => {
    expect(() =>
      hashAttestationPayload({
        publicKey: PUBLIC_KEY,
        chainId: 1,
        complianceKeys: ["0x1234"],
      }),
    ).toThrow(/32-byte/);
  });

  it("rejects non-hex input", () => {
    expect(() => hashAttestationPayload({ publicKey: "0xzz", chainId: 1 })).toThrow(/hex/);
  });
});

describe("parseReportData", () => {
  function reportData(options: {
    payloadHash?: Uint8Array;
    timestamp?: bigint;
    isMetrics?: boolean;
    isDebug?: boolean;
    isGlobal?: boolean;
  }): Uint8Array {
    const buf = new Uint8Array(64);
    if (options.payloadHash) buf.set(options.payloadHash, 0);
    let ts = options.timestamp ?? 0n;
    for (let i = 39; i >= 32; i--) {
      buf[i] = Number(ts & 0xffn);
      ts >>= 8n;
    }
    buf[61] = options.isMetrics ? 1 : 0;
    buf[62] = options.isDebug ? 1 : 0;
    buf[63] = options.isGlobal ? 1 : 0;
    return buf;
  }

  it("decodes the enclave's report body layout", () => {
    const hash = new Uint8Array(32).fill(0x5a);
    const parsed = parseReportData(
      reportData({ payloadHash: hash, timestamp: 1_770_000_000n, isDebug: true, isGlobal: true }),
    );

    expect(toHex(parsed.payloadHash)).toBe("5a".repeat(32));
    expect(parsed.timestamp).toBe(1_770_000_000);
    expect(parsed.isDebug).toBe(true);
    expect(parsed.isGlobal).toBe(true);
    expect(parsed.isMetrics).toBe(false);
  });

  it("distinguishes the three flag bytes", () => {
    expect(parseReportData(reportData({ isMetrics: true })).isMetrics).toBe(true);
    expect(parseReportData(reportData({ isMetrics: true })).isDebug).toBe(false);
    expect(parseReportData(reportData({ isGlobal: true })).isGlobal).toBe(true);
    expect(parseReportData(reportData({ isGlobal: true })).isDebug).toBe(false);
  });

  it("reads the timestamp as big endian", () => {
    expect(parseReportData(reportData({ timestamp: 1n })).timestamp).toBe(1);
    expect(parseReportData(reportData({ timestamp: 256n })).timestamp).toBe(256);
  });

  it("rejects report data of the wrong length", () => {
    expect(() => parseReportData(new Uint8Array(32))).toThrow(/64 bytes/);
  });
});

describe("verifyAttestation", () => {
  const PAYLOAD = { publicKey: PUBLIC_KEY, chainId: 1 };

  /** Stub the verifier so the surrounding policy checks can be exercised. */
  async function withStub(
    report: {
      status?: string;
      mrEnclave?: Uint8Array;
      mrSigner?: Uint8Array;
      isvSvn?: number;
      advisoryIds?: string[];
      reportData?: Uint8Array;
    },
    run: (verify: typeof import("../src/internal/attestation.js").verifyAttestation) => Promise<void>,
  ) {
    const sgx = {
      mrEnclave: report.mrEnclave ?? new Uint8Array(32).fill(0xaa),
      mrSigner: report.mrSigner ?? new Uint8Array(32).fill(0xbb),
      isvSvn: report.isvSvn ?? 2,
      reportData: report.reportData ?? new Uint8Array(64),
    };

    vi.doMock("@phala/dcap-qvl", () => ({
      QuoteVerifier: {
        newProd: () => ({
          allowDebug: () => ({
            verify: () => ({
              status: report.status ?? "UpToDate",
              advisory_ids: report.advisoryIds ?? [],
              report: { asSgx: () => sgx },
            }),
          }),
        }),
      },
    }));

    vi.resetModules();
    const mod = await import("../src/internal/attestation.js");
    await run(mod.verifyAttestation);
    vi.doUnmock("@phala/dcap-qvl");
    vi.resetModules();
  }

  function committedReportData(payload = PAYLOAD, flags: { isGlobal?: boolean } = {}) {
    const buf = new Uint8Array(64);
    buf.set(hashAttestationPayload(payload), 0);
    // Recent timestamp so the staleness check passes.
    let ts = BigInt(Math.floor(Date.now() / 1000));
    for (let i = 39; i >= 32; i--) {
      buf[i] = Number(ts & 0xffn);
      ts >>= 8n;
    }
    buf[63] = flags.isGlobal === false ? 0 : 1;
    return buf;
  }

  const quote = { quote: "0x00", collateral: {} };

  it("accepts a quote whose report data commits to the served payload", async () => {
    await withStub({ reportData: committedReportData() }, async (verify) => {
      const result = await verify(quote, PAYLOAD);
      expect(result.verified).toBe(true);
      expect(result.tcbStatus).toBe("UpToDate");
      expect(result.mrenclave).toBe("aa".repeat(32));
      expect(result.isvSvn).toBe(2);
    });
  });

  it("rejects a payload that does not reproduce the committed hash", async () => {
    await withStub({ reportData: committedReportData() }, async (verify) => {
      // A substituted key is exactly what this check exists to catch.
      await expect(
        verify(quote, { ...PAYLOAD, publicKey: `0x${"02".repeat(33)}` }),
      ).rejects.toMatchObject({ code: "ATTESTATION_PAYLOAD_MISMATCH" });
    });
  });

  it("rejects an out-of-date TCB", async () => {
    await withStub(
      { status: "OutOfDate", reportData: committedReportData() },
      async (verify) => {
        await expect(verify(quote, PAYLOAD)).rejects.toMatchObject({
          code: "ATTESTATION_TCB_REJECTED",
        });
      },
    );
  });

  it("accepts SWHardeningNeeded by default", async () => {
    await withStub(
      { status: "SWHardeningNeeded", reportData: committedReportData() },
      async (verify) => {
        await expect(verify(quote, PAYLOAD)).resolves.toMatchObject({
          tcbStatus: "SWHardeningNeeded",
        });
      },
    );
  });

  it("accepts an explicitly allowed TCB status, advisory set, and ISVSVN", async () => {
    await withStub(
      {
        status: "ConfigurationAndSWHardeningNeeded",
        advisoryIds: ["INTEL-SA-00289", "INTEL-SA-00615"],
        isvSvn: 2,
        reportData: committedReportData(),
      },
      async (verify) => {
        await expect(
          verify(quote, PAYLOAD, {
            allowedTcbStatus: ["ConfigurationAndSWHardeningNeeded"],
            allowedAdvisoryIds: ["INTEL-SA-00289", "INTEL-SA-00615"],
            minimumIsvSvn: 2,
          }),
        ).resolves.toMatchObject({
          tcbStatus: "ConfigurationAndSWHardeningNeeded",
          advisoryIds: ["INTEL-SA-00289", "INTEL-SA-00615"],
          isvSvn: 2,
        });
      },
    );
  });

  it("rejects an advisory outside the configured allowlist", async () => {
    await withStub(
      {
        status: "ConfigurationAndSWHardeningNeeded",
        advisoryIds: ["INTEL-SA-00289", "INTEL-SA-00615", "INTEL-SA-99999"],
        reportData: committedReportData(),
      },
      async (verify) => {
        await expect(
          verify(quote, PAYLOAD, {
            allowedTcbStatus: ["ConfigurationAndSWHardeningNeeded"],
            allowedAdvisoryIds: ["INTEL-SA-00289", "INTEL-SA-00615"],
          }),
        ).rejects.toMatchObject({
          code: "ATTESTATION_TCB_REJECTED",
          meta: { disallowedAdvisoryIds: ["INTEL-SA-99999"] },
        });
      },
    );
  });

  it("rejects an enclave below the configured minimum ISVSVN", async () => {
    await withStub(
      { isvSvn: 1, reportData: committedReportData() },
      async (verify) => {
        await expect(
          verify(quote, PAYLOAD, { minimumIsvSvn: 2 }),
        ).rejects.toMatchObject({
          code: "ATTESTATION_TCB_REJECTED",
          meta: { isvSvn: 1, minimumIsvSvn: 2 },
        });
      },
    );
  });

  it("rejects an invalid minimum ISVSVN policy", async () => {
    await withStub({ reportData: committedReportData() }, async (verify) => {
      await expect(
        verify(quote, PAYLOAD, { minimumIsvSvn: Number.NaN }),
      ).rejects.toMatchObject({ code: "INVALID_ATTESTATION_POLICY" });
    });
  });

  it("rejects an unexpected MRSIGNER", async () => {
    await withStub({ reportData: committedReportData() }, async (verify) => {
      await expect(
        verify(quote, PAYLOAD, { expectedMrSigner: [`0x${"cc".repeat(32)}`] }),
      ).rejects.toMatchObject({ code: "ATTESTATION_MEASUREMENT_MISMATCH" });
    });
  });

  it("accepts a pinned MRSIGNER regardless of prefix or case", async () => {
    await withStub({ reportData: committedReportData() }, async (verify) => {
      await expect(
        verify(quote, PAYLOAD, { expectedMrSigner: [`0x${"BB".repeat(32)}`] }),
      ).resolves.toMatchObject({ verified: true });
    });
  });

  it("reports MRENCLAVE without pinning it, since it changes each release", async () => {
    await withStub(
      { mrEnclave: new Uint8Array(32).fill(0x99), reportData: committedReportData() },
      async (verify) => {
        // A differing MRENCLAVE must not by itself fail verification.
        await expect(
          verify(quote, PAYLOAD, { expectedMrSigner: [`0x${"bb".repeat(32)}`] }),
        ).resolves.toMatchObject({ mrenclave: "99".repeat(32) });
      },
    );
  });

  it("rejects an attestation that is not for the global key", async () => {
    await withStub(
      { reportData: committedReportData(PAYLOAD, { isGlobal: false }) },
      async (verify) => {
        await expect(verify(quote, PAYLOAD)).rejects.toMatchObject({
          code: "ATTESTATION_NOT_GLOBAL",
        });
      },
    );
  });

  it("rejects a stale report", async () => {
    const buf = committedReportData();
    // Backdate well beyond the default 24h window.
    let ts = BigInt(Math.floor(Date.now() / 1000) - 200_000);
    for (let i = 39; i >= 32; i--) {
      buf[i] = Number(ts & 0xffn);
      ts >>= 8n;
    }
    await withStub({ reportData: buf }, async (verify) => {
      await expect(verify(quote, PAYLOAD)).rejects.toMatchObject({ code: "ATTESTATION_STALE" });
    });
  });

  it("rejects a debug enclave unless explicitly allowed", async () => {
    const buf = committedReportData();
    buf[62] = 1;
    await withStub({ reportData: buf }, async (verify) => {
      await expect(verify(quote, PAYLOAD)).rejects.toMatchObject({
        code: "ATTESTATION_DEBUG_ENCLAVE",
      });
      await expect(verify(quote, PAYLOAD, { allowDebug: true })).resolves.toMatchObject({
        debug: true,
      });
    });
  });
});
