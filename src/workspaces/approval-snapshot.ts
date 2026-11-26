import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, type Hex } from "viem";
import { ApiError } from "../errors.js";
import type { PolicyResponse, RecordRow } from "./client";
import { bytes, uint, utf8 } from "./encoding";
import { verifyRecord } from "./records";
import { freezeJson, policyView, verifiedAuthor, type VerifiedPolicy } from "./verified-policy";

/** The signed policy and encrypted rows are deeply frozen and shared across unchanged reads. */
export interface ApprovalSnapshot {
  readonly policy: PolicyResponse;
  readonly records: readonly RecordRow[];
  readonly inventoryHash: Hex;
  readonly upper: number;
}

export interface ApprovalSnapshotPage {
  policy: PolicyResponse | null;
  policyHead: Hex;
  upper: number;
  next: number;
  hasMore: boolean;
  inventoryHash: Hex;
  records: RecordRow[];
}

const types = new Set(["payment_request", "decision", "payment_template", "proposal_cancellation", "roster"]);

function inventoryHash(rows: Map<Hex, RecordRow>): Hex {
  const hash = sha256.create();
  for (const id of [...rows.keys()].sort()) {
    hash.update(utf8(`${id}:${rows.get(id)!.record.signature}\n`));
  }
  return bytesToHex(hash.digest());
}

/** One authenticated, verified inventory per live workspace client. */
export class ApprovalSnapshotReader {
  private rows = new Map<Hex, RecordRow>();
  private records: readonly RecordRow[] = Object.freeze([]);
  private upper = 0;
  private digest = inventoryHash(this.rows);
  private pending: Promise<void> = Promise.resolve();

  constructor(
    private readonly workspace: Hex,
    private readonly fetchPage: (query: URLSearchParams) => Promise<ApprovalSnapshotPage>,
    private readonly pinned: () => VerifiedPolicy | undefined,
    private readonly acceptPolicy: (response: PolicyResponse) => VerifiedPolicy,
    private readonly ensureLive: () => void,
  ) {}

  read(): Promise<ApprovalSnapshot> {
    // Each caller performs an online check after invocation, even if a UI poll
    // is already running. Publish only after every page and the inventory match.
    const work = this.pending.then(async () => {
      for (let attempt = 0; ; attempt++) {
        try { return await this.readPages(); }
        catch (error) {
          if (!(error instanceof ApiError) || error.statusCode !== 409 || attempt >= 2) throw error;
        }
      }
    });
    this.pending = work.then(() => {}, () => {});
    return work;
  }

  private async readPages(): Promise<ApprovalSnapshot> {
    let verified = this.pinned();
    let since = this.upper;
    let upper: number | undefined;
    let digest: Hex | undefined;
    // Copy on the first delta. An unchanged check only compares the saved digest.
    let changes: Map<Hex, RecordRow> | undefined;
    const seen = new Set<Hex>();
    for (let index = 0; index < 1000; index++) {
      this.ensureLive();
      const query = new URLSearchParams({ since: String(since) });
      const requested = verified?.policy.headHash;
      if (requested) query.set("policyHead", requested);
      if (upper !== undefined) query.set("at", String(upper));
      const page = await this.fetchPage(query);
      this.ensureLive();
      bytes(page.policyHead, 32); bytes(page.inventoryHash, 32);
      uint(page.upper); uint(page.next);
      if (!Array.isArray(page.records) || page.records.length > 100 || typeof page.hasMore !== "boolean"
          || page.upper < since || page.next < since || page.next > page.upper) {
        throw new Error("Invalid approval snapshot page");
      }
      if (upper !== undefined && (upper !== page.upper || page.inventoryHash !== digest || page.policyHead !== requested)) {
        throw new Error("Approval snapshot changed during pagination");
      }
      upper = page.upper; digest = page.inventoryHash;
      const current = this.pinned();
      if (page.policy !== null) {
        verified = this.acceptPolicy(page.policy);
      } else if (!verified || requested !== page.policyHead || current?.policy.headHash !== requested) {
        throw new Error("Approval snapshot omitted its current signed policy");
      }
      if (verified.policy.headHash !== page.policyHead) throw new Error("Approval snapshot policy head mismatch");
      const authorize = verifiedAuthor(verified);
      let last = since;
      for (const row of page.records) {
        const record = row.record;
        uint(row.changeSequence, 53, 1);
        if (row.changeSequence <= last || row.changeSequence > page.next || seen.has(record.recordId)
            || !types.has(record.type) || record.workspaceId !== this.workspace || !verifyRecord(record, authorize)) {
          throw new Error("Invalid approval snapshot record or order");
        }
        const old = this.rows.get(record.recordId)?.record;
        if ((record.type !== "roster" && record.revision !== 1) ||
            (old && (old.type !== record.type || record.type !== "roster" || record.revision <= old.revision))) {
          throw new Error("Approval snapshot record changed or rolled back");
        }
        seen.add(record.recordId);
        changes ??= new Map(this.rows);
        changes.set(record.recordId, freezeJson(row));
        last = row.changeSequence;
      }
      if (page.hasMore) {
        if (!page.records.length || page.next !== last || page.next >= upper) throw new Error("Approval snapshot did not advance");
        since = page.next;
        continue;
      }
      if (page.next !== upper || (changes ? inventoryHash(changes) : this.digest) !== digest) {
        throw new Error("Approval snapshot inventory is incomplete or changed");
      }
      if (changes) {
        this.rows = changes;
        this.records = Object.freeze([...changes.values()]);
      }
      this.upper = upper;
      this.digest = digest;
      return Object.freeze({ policy: policyView(verified), records: this.records, inventoryHash: digest, upper });
    }
    throw new Error("Approval snapshot exceeded its page limit");
  }
}
