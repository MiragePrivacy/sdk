import { beforeEach, describe, expect, it, vi } from "vitest";
import { screenAddresses, fetchTransferPreflight, fetchPricingPreview, fetchComplianceApproval } from "../src/internal/api.js";
const A = "0x1111111111111111111111111111111111111111" as const;
const B = "0x2222222222222222222222222222222222222222" as const;
const H = `0x${"11".repeat(32)}` as const;
beforeEach(() => vi.restoreAllMocks());
describe("role-free screening", () => {
  it("makes one separate request per distinct address without roles or plan identifiers", async () => {
    globalThis.fetch = vi.fn(async (_url, init) => ({ ok:true, json:async () => ({
      version:1, chain_id:JSON.parse(String(init?.body)).chain_id,
      issued_at:Math.floor(Date.now()/1000), expires_at:Math.floor(Date.now()/1000)+300,
    }) })) as any;
    const receipts = await screenAddresses("https://api.test", 1, [A, B, A]);
    expect(receipts).toHaveLength(2);
    const calls = vi.mocked(fetch).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls.map(([url]) => url)).toEqual(Array(2).fill("https://api.test/compliance/screen"));
    const bodies = calls.map(([, init]) => JSON.parse(String(init?.body)));
    expect(bodies.map(body => body.address).sort()).toEqual([A, B]);
    bodies.forEach(body => expect(Object.keys(body).sort()).toEqual(["address", "chain_id"]));
  });
  it("rejects expired screening receipts", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ok:true,json:async()=>({version:1,chain_id:1,expires_at:1})});
    await expect(screenAddresses("https://api.test",1,[A])).rejects.toMatchObject({code:"INVALID_SCREENING_RECEIPT"});
  });
  it("sends the execution receipts to the approval endpoint", async () => {
    globalThis.fetch=vi.fn().mockResolvedValue({ok:true,json:async()=>({})});
    await fetchComplianceApproval("https://api.test", {txHash:H,chainId:1,seed:H,escrowType:"batch",quoteCommitment:H,screeningReceipts:[]});
    const [url,init]=vi.mocked(fetch).mock.calls[0];
    expect(url).toBe("https://api.test/execution/approve");
    expect(JSON.parse(String(init?.body))).toEqual({tx_hash:H,chain_id:1,seed:H,escrow_type:"batch",quote_commitment:H,screening_receipts:[]});
  });
});
it("copies only amount fields into preflight even when extra participant fields are supplied", async () => {
  globalThis.fetch=vi.fn().mockResolvedValue({ok:true,json:async()=>({})});
  await fetchTransferPreflight("https://api.test",{chainId:1,escrowType:"batch",signals:[{asset:A,execution_mode:"private",amounts:["1"],sender:A,recipient:B} as any]});
  const [url,init]=vi.mocked(fetch).mock.calls[0];
  expect(url).toBe("https://api.test/transfers/preflight");
  expect(JSON.parse(String(init?.body))).toEqual({chain_id:1,escrow_type:"batch",signals:[{asset:A,execution_mode:"private",amounts:["1"]}]});
});
it("strips recipient fields from pricing previews", async () => {
  globalThis.fetch=vi.fn().mockResolvedValue({ok:true,json:async()=>({chain_id:1,service_fee:{asset:A,amount:"1"},deployment:{reward_asset:A,reward_amount:"1",deposit_by_asset:{[A]:"2"},msg_value:"0"}})});
  await fetchPricingPreview("https://api.test",{chainId:1,escrowType:"erc20",signals:[{asset:A,execution_mode:"private",items:[{client_row_id:"row",recipient:B,amount:"1"}]}]});
  const [,init]=vi.mocked(fetch).mock.calls[0];
  expect(JSON.stringify(JSON.parse(String(init?.body)))).not.toContain(B);
  expect(JSON.parse(String(init?.body)).signals[0].items[0]).toEqual({client_row_id:"row",amount:"1"});
});
