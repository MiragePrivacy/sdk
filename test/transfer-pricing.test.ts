import { beforeEach, describe, expect, it, vi } from "vitest";
import { getContractAddress, hashDomain, getTypesForEIP712Domain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { fetchCamouflage } from "../src/internal/api.js";
import * as bond from "../src/internal/bond.js";
import { deriveSalt, intentCommitment } from "../src/internal/zk.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { prepareTransfer, previewTransfer } from "../src/transfer.js";
import { recoverDeployment } from "../src/recoverDeployment.js";
import type { PendingDeployment } from "../src/types.js";
import { createNetworkConfig } from "../src/networks.js";
import { NATIVE_TOKEN_ADDRESS } from "../src/token.js";
import { complianceKey, signedAdmission } from "./helpers/admission.js";

const SENDER = "0x0000000000000000000000000000000000000001" as const;
const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;
const RECIPIENT_A = "0x0000000000000000000000000000000000000011" as const;
const RECIPIENT_B = "0x0000000000000000000000000000000000000012" as const;
const COMMITMENT = `0x${"11".repeat(32)}` as `0x${string}`;
const DEPLOY_HASH = `0x${"22".repeat(32)}` as `0x${string}`;

const VALID_RESUME = {
  escrowAddress: SENDER,
  escrowType: "erc20" as const,
  blindingScalar: `0x${"33".repeat(32)}` as `0x${string}`,
  seed: `0x${"44".repeat(32)}`,
  deployHash: DEPLOY_HASH,
  deployedAt: 1_700_000_000,
  rewardAmount: 25n,
  rewardAsset: USDC,
  quoteCommitment: COMMITMENT,
  sealedPricingAuthorization: "0xabcd" as `0x${string}`,
  serviceFee: { asset: USDC, amount: 25n },
  depositByAsset: { [USDC]: 125n },
  msgValue: 0n,
  senderAddress: SENDER,
};

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

const networkKey = `0x${toHex(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true))}`;
let pricingBody: any;
let camouflageBody: any;
let quotedEscrowType: "erc20" | "native" | "batch" | undefined;
let attestedChainId: number;
let attestUrl: string | undefined;
let forceUnsignedQuote: boolean;
let signedFundingOverride: Record<string, string> | undefined;
let quoteTtl: number | undefined;
let supportsReceiptFunding: boolean;

beforeEach(() => {
  pricingBody = undefined;
  camouflageBody = undefined;
  quotedEscrowType = undefined;
  attestedChainId = 31337;
  attestUrl = undefined;
  forceUnsignedQuote = false;
  signedFundingOverride = undefined;
  quoteTtl = 300;
  supportsReceiptFunding = true;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/compliance/screen")) {
      const body = JSON.parse(String(init?.body));
      return { ok: true, json: async () => ({ version: 1, chain_id: body.chain_id,
        address_hash: COMMITMENT, policy_hash: COMMITMENT, screened: false,
        issued_at: Math.floor(Date.now()/1000), expires_at: Math.floor(Date.now()/1000)+300,
        signature: "0x00" }) } as Response;
    }
    if (url.endsWith("/attest")) {
      attestUrl = url;
      return {
        ok: true,
        json: async () => ({
          payload: { publicKey: networkKey, chainId: attestedChainId, pricingKeys: [], complianceKeys: [complianceKey] },
          attestation: null,
          isDebug: true,
        }),
      } as Response;
    }
    if (url.endsWith("/camouflage_escrow")) {
      camouflageBody = JSON.parse(String(init?.body));
      return {
        ok: true,
        json: async () => ({
          funding_mode: supportsReceiptFunding ? camouflageBody.funding_mode : undefined,
          camouflaged_bytecode: "0x6000",
          original_size: 2,
          camouflaged_size: 2,
          gas_analysis: { camouflaged_gas_estimate: 1_234_567 },
          selector_mapping: null,
        }),
      } as Response;
    }
    if (url.endsWith("/pricing/quote")) {
      pricingBody = JSON.parse(String(init?.body));
      const rewardAsset = pricingBody.signals[0].asset;
      // A request without a sender receives an unsigned preview, matching the
      // API contract.
      const preview = forceUnsignedQuote || pricingBody.sender === undefined;
      const deposits = Object.fromEntries(pricingBody.signals.map((signal: { asset: string; items: { amount: string }[] }) => [
        signal.asset, (signal.items.reduce((sum, item) => sum + BigInt(item.amount), signal.asset === rewardAsset ? 25n : 0n)).toString(),
      ]));
      return {
        ok: true,
        json: async () => ({
          chain_id: pricingBody.chain_id,
          service_fee: { asset: rewardAsset, amount: "25" },
          deployment: {
            escrow_type: quotedEscrowType ?? pricingBody.escrow_type,
            funding_mode: supportsReceiptFunding ? pricingBody.funding_mode : undefined,
            constructor_args: preview ? null : "0x1234",
            quote_commitment: preview ? null : COMMITMENT,
            reward_asset: rewardAsset,
            reward_amount: "25",
            deposit_by_asset: (!preview && signedFundingOverride) || deposits,
            msg_value: deposits[NATIVE_TOKEN_ADDRESS] ?? "0",
          },
          sealed_pricing_authorization: preview ? null : "0xabcd",
          expires_at: !preview && quoteTtl !== undefined ? Math.floor(Date.now() / 1000) + quoteTtl : undefined,
        }),
      } as Response;
    }
    throw new Error(`Unexpected URL ${url}`);
  }) as any;
});

const network = createNetworkConfig("ethereum", {
  chainId: 31337,
  apiServer: "https://api.test",
  attestation: { required: false },
});

describe("deployment checkpoints", () => {
  const blockHash = `0x${"55".repeat(32)}` as const;
  const replacementHash = `0x${"66".repeat(32)}` as const;
  async function fixture() {
    const escrowAddress = getContractAddress({ from: SENDER, nonce: 5n });
    const tx = { from: SENDER, to: null, nonce: 5, input: "0x60001234", value: 125n,
      hash: DEPLOY_HASH, blockHash, blockNumber: 20n, chainId: 31337 };
    const receipt = { from: SENDER, to: null, transactionHash: DEPLOY_HASH, contractAddress: escrowAddress,
      status: "success", blockHash, blockNumber: 20n, transactionIndex: 0, gasUsed: 55n, effectiveGasPrice: 3n };
    const rpc = {
      getChainId: vi.fn().mockResolvedValue(31337),
      getBlockNumber: vi.fn().mockResolvedValue(10n),
      getTransactionCount: vi.fn().mockResolvedValue(5),
      estimateGas: vi.fn().mockResolvedValue(1_234_567n),
      getTransaction: vi.fn().mockResolvedValue(tx),
      getTransactionReceipt: vi.fn().mockResolvedValue(receipt),

      waitForTransactionReceipt: vi.fn().mockResolvedValue(receipt),
      getBlock: vi.fn().mockResolvedValue({ number: 20n, hash: blockHash, transactions: [DEPLOY_HASH], timestamp: 1_700_000_001n }),
    };
    const prepared = await prepareTransfer({ tokenAddress: NATIVE_TOKEN_ADDRESS,
      recipientAddress: RECIPIENT_A, amount: 100n, senderAddress: SENDER, network, publicClient: rpc as any });
    const send = vi.fn().mockResolvedValue(DEPLOY_HASH);
    const wallet = { account: { address: SENDER }, sendTransaction: send } as any;
    let saved!: PendingDeployment;
    const onPrepared = vi.fn(async (checkpoint: PendingDeployment) => { saved = structuredClone(checkpoint); });
    const onBroadcast = vi.fn(async () => {});
    const deploy = () => prepared.deploy(wallet, undefined, { onPrepared, onBroadcast });
    const recover = () => recoverDeployment({ publicClient: rpc as any, pending: saved, hash: DEPLOY_HASH });
    const discover = () => recoverDeployment({ publicClient: rpc as any, pending: saved });
    return { deploy, recover, discover, wallet, send, rpc, tx, receipt, onPrepared, onBroadcast };
  }

  it("persists intent before send and hash before receipt, including concurrent callers", async () => {
    const f = await fixture();
    const [first, second] = await Promise.all([f.deploy(), f.deploy()]);
    expect(first).toEqual(second);
    expect(f.send).toHaveBeenCalledTimes(1);
    expect(f.onPrepared.mock.invocationCallOrder[0]).toBeLessThan(f.send.mock.invocationCallOrder[0]);
    expect(f.onBroadcast.mock.invocationCallOrder[0]).toBeLessThan(f.rpc.waitForTransactionReceipt.mock.invocationCallOrder[0]);
    expect(first.secrets).toMatchObject({ deployHash: DEPLOY_HASH, quoteCommitment: COMMITMENT,
      sealedPricingAuthorization: "0xabcd", fromBlock: 20n, deployedAt: 1_700_000_001_000 });
  });

  it("blocks submission if the checkpoint cannot be stored or the signed nonce is stale", async () => {
    const f = await fixture();
    f.onPrepared.mockRejectedValueOnce(new Error("storage full"));
    await expect(f.deploy()).rejects.toThrow("storage full");
    f.rpc.getTransactionCount.mockResolvedValue(6);
    await expect(f.deploy()).rejects.toThrow("nonce changed");
    expect(f.send).not.toHaveBeenCalled();
  });

  it("recovers after a lost wallet response using only the saved data and a matching hash", async () => {
    const f = await fixture();
    f.send.mockRejectedValueOnce(new Error("wallet timeout"));
    await expect(f.deploy()).rejects.toThrow("wallet timeout");
    await expect(f.deploy()).rejects.toMatchObject({ code: "DEPLOYMENT_NOT_MINED" });
    expect(f.onBroadcast).not.toHaveBeenCalled();
    await expect(f.recover()).resolves.toMatchObject({ hash: DEPLOY_HASH, secrets: { senderAddress: SENDER } });
    expect(f.send).toHaveBeenCalledTimes(1);
  });

  it("completes an admitted recovered deployment after quote expiry without another submission", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);
    try {
      const f = await fixture();
      f.send.mockRejectedValueOnce(new Error("wallet timeout"));
      await expect(f.deploy()).rejects.toThrow("wallet timeout");
      now.mockReturnValue(1_700_000_301_000);
      expect(Date.now()).toBeGreaterThan(f.onPrepared.mock.calls[0][0].createdAt + 300_000);
      const recovered = await f.recover();
      const receipt = signedAdmission({ escrowContract: recovered.escrowAddress });
      const originalFetch = globalThis.fetch;
      const resumedFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/attest")) return originalFetch(input, init);
        if (url.endsWith("/admission/lookup")) {
          return { ok: true, status: 200, json: async () => ({ status: "admitted", admissionReceipt: receipt }) } as Response;
        }
        throw new Error(`Unexpected reauthorization or submission: ${url}`);
      });
      globalThis.fetch = resumedFetch as typeof fetch;
      const resumed = await prepareTransfer({ tokenAddress: NATIVE_TOKEN_ADDRESS,
        recipientAddress: RECIPIENT_A, amount: 100n, network, publicClient: f.rpc as any,
        resume: recovered.secrets });
      await expect(resumed.deploy(f.wallet)).resolves.toEqual(recovered);
      f.rpc.getBlockNumber.mockResolvedValue(20n);
      f.rpc.getBlock.mockResolvedValue({ number: 20n, hash: blockHash, timestamp: 1_700_000_302n,
        transactions: [{ hash: replacementHash, from: RECIPIENT_B, to: RECIPIENT_A, value: 100n }] });

      const steps = [];
      for await (const step of resumed.complete(f.wallet)) steps.push(step);
      expect(steps.map(step => step.step)).toEqual(["signal", "transfer", "complete"]);
      expect(steps[0]).toEqual({ step: "signal", response: JSON.stringify({ status: "admitted", admissionReceipt: receipt }) });
      expect(resumedFetch.mock.calls.map(([url]) => String(url))).toEqual([
        "https://api.test/nomad/31337/attest", "https://api.test/nomad/31337/admission/lookup",
      ]);
      expect(JSON.parse(String(resumedFetch.mock.calls[1][1]?.body))).toEqual({
        escrowContract: recovered.escrowAddress, quoteCommitment: COMMITMENT,
      });
      expect(f.send).toHaveBeenCalledTimes(1);
    } finally {
      now.mockRestore();
    }
  });

  it("allows another wallet request only after explicit user rejection", async () => {
    const f = await fixture();
    f.send.mockRejectedValueOnce(Object.assign(new Error("user rejected"), { cause: { code: 4001 } }));
    await expect(f.deploy()).rejects.toThrow("user rejected");
    await expect(f.deploy()).resolves.toMatchObject({ hash: DEPLOY_HASH });
    expect(f.send).toHaveBeenCalledTimes(2);
  });

  it("finds a lost hash by the saved nonce and reads full transactions from just the matching block", async () => {
    const f = await fixture();
    f.send.mockRejectedValueOnce(new Error("lost response"));
    await expect(f.deploy()).rejects.toThrow("lost response");
    f.rpc.getBlockNumber.mockResolvedValue(1000n);
    f.rpc.getTransactionCount.mockImplementation(async ({ blockNumber }) => blockNumber < 20n ? 5 : 8);
    f.rpc.getBlock.mockResolvedValue({ number: 20n, hash: blockHash, timestamp: 1_700_000_001n, transactions: [
      f.tx, { ...f.tx, from: RECIPIENT_A }, { ...f.tx, nonce: 7 },
    ] });
    await expect(f.discover()).resolves.toMatchObject({ hash: DEPLOY_HASH, secrets: { fromBlock: 20n } });
    expect(f.rpc.getBlock).toHaveBeenCalledExactlyOnceWith({ blockNumber: 20n, includeTransactions: true });
    expect(f.rpc.waitForTransactionReceipt).not.toHaveBeenCalled();
    expect(f.rpc.getTransactionCount.mock.calls.length).toBeLessThan(16);
    expect(f.send).toHaveBeenCalledTimes(1);
    f.rpc.getBlock.mockResolvedValue({ number: 20n, hash: blockHash, transactions: [{ ...f.tx, input: "0x1234" }] });
    await expect(f.discover()).rejects.toMatchObject({ code: "DEPLOYMENT_NONCE_CONSUMED" });
  });

  it("reports unavailable historical state and still accepts a verified wallet hash", async () => {
    const f = await fixture();
    f.send.mockRejectedValueOnce(new Error("lost response"));
    await expect(f.deploy()).rejects.toThrow("lost response");
    f.rpc.getBlockNumber.mockResolvedValue(500n);
    f.rpc.getTransactionCount.mockResolvedValueOnce(7).mockRejectedValueOnce(new Error("historical state unavailable"));
    await expect(f.discover()).rejects.toMatchObject({ code: "DEPLOYMENT_LOOKUP_UNAVAILABLE" });
    await expect(f.recover()).resolves.toMatchObject({ hash: DEPLOY_HASH });
    expect(f.send).toHaveBeenCalledTimes(1);
  });

  it("retries receipt confirmation without replaying the wallet request", async () => {
    const f = await fixture();
    f.rpc.waitForTransactionReceipt.mockRejectedValueOnce(new Error("RPC timed out"));
    await expect(f.deploy()).rejects.toThrow("RPC timed out");
    f.rpc.waitForTransactionReceipt.mockResolvedValue({ ...f.receipt, transactionHash: replacementHash });
    f.rpc.getTransaction.mockResolvedValue({ ...f.tx, hash: replacementHash });
    f.rpc.getBlock.mockResolvedValue({ number: 20n, hash: blockHash, transactions: [replacementHash], timestamp: 1_700_000_001n });
    await expect(f.deploy()).resolves.toMatchObject({ hash: replacementHash, secrets: { deployHash: replacementHash } });
    expect(f.rpc.getTransaction).toHaveBeenCalledWith({ hash: replacementHash });
    expect(f.send).toHaveBeenCalledTimes(1);
  });

  it("rejects unrelated transactions and receipts even when the address or nonce matches", async () => {
    const f = await fixture();
    f.send.mockRejectedValueOnce(new Error("lost response"));
    await expect(f.deploy()).rejects.toThrow("lost response");
    for (const changed of [{ from: RECIPIENT_A }, { nonce: 6 }, { chainId: 1 }, { hash: replacementHash }]) {
      f.rpc.getTransaction.mockResolvedValueOnce({ ...f.tx, ...changed });
      await expect(f.recover()).rejects.toMatchObject({ code: "DEPLOYMENT_MISMATCH" });
    }
    for (const changed of [{ input: "0x6000" }, { value: 126n }]) {
      f.rpc.getTransaction.mockResolvedValueOnce({ ...f.tx, ...changed });
      await expect(f.recover()).rejects.toMatchObject({ code: "DEPLOYMENT_NONCE_CONSUMED" });
    }
    f.rpc.waitForTransactionReceipt.mockResolvedValueOnce({ ...f.receipt, status: "reverted" });
    await expect(f.recover()).rejects.toMatchObject({ code: "DEPLOYMENT_REVERTED" });
    for (const changed of [{ contractAddress: null }, { contractAddress: RECIPIENT_A },
      { to: RECIPIENT_A }, { from: RECIPIENT_A }]) {
      f.rpc.waitForTransactionReceipt.mockResolvedValueOnce({ ...f.receipt, ...changed });
      await expect(f.recover()).rejects.toThrow("does not confirm");
    }
    f.rpc.getChainId.mockResolvedValue(1);
    await expect(f.recover()).rejects.toThrow("original deployment network");
    expect(f.send).toHaveBeenCalledTimes(1);
  });

  it("treats a canonical cancellation as terminal but keeps orphaned or inconsistent receipts recoverable", async () => {
    const f = await fixture();
    f.send.mockRejectedValueOnce(new Error("lost response"));
    await expect(f.deploy()).rejects.toThrow("lost response");
    const cancellation = { ...f.tx, to: SENDER, value: 0n, input: "0x" };
    const receipt = { ...f.receipt, to: SENDER, contractAddress: null };
    f.rpc.getTransaction.mockResolvedValue(cancellation);
    f.rpc.waitForTransactionReceipt.mockResolvedValue(receipt);
    f.rpc.getBlock.mockResolvedValueOnce({ number: 20n, hash: replacementHash, transactions: [DEPLOY_HASH] });
    await expect(f.recover()).rejects.toMatchObject({ code: "DEPLOYMENT_LOOKUP_UNAVAILABLE" });
    f.rpc.getBlock.mockResolvedValueOnce({ number: 20n, hash: blockHash, transactions: [replacementHash] });
    await expect(f.recover()).rejects.toMatchObject({ code: "DEPLOYMENT_LOOKUP_UNAVAILABLE" });
    f.rpc.waitForTransactionReceipt.mockResolvedValueOnce({ ...receipt, from: RECIPIENT_A, status: "reverted" });
    await expect(f.recover()).rejects.toMatchObject({ code: "DEPLOYMENT_MISMATCH" });
    await expect(f.recover()).rejects.toMatchObject({ code: "DEPLOYMENT_NONCE_CONSUMED" });
    expect(f.rpc.getBlock).toHaveBeenCalledWith({ blockNumber: 20n });
    expect(f.send).toHaveBeenCalledTimes(1);
  });
});

describe("prepareTransfer pricing flow", () => {
  it("uses one signed quote for mixed assets and checks the nonce on review", async () => {
    const nonce = vi.fn().mockResolvedValue(3);
    const params = {
      transfers: [
        { tokenAddress: NATIVE_TOKEN_ADDRESS, recipientAddress: RECIPIENT_A, amount: 1n },
        { tokenAddress: USDC, recipientAddress: RECIPIENT_A, amount: 2n },
      ], senderAddress: SENDER, publicClient: { getTransactionCount: nonce, estimateContractGas: async () => 10n } as any, network,
    };
    const transfer = await prepareTransfer(params);
    const quotes = () => vi.mocked(fetch).mock.calls.filter(([url]) => String(url).endsWith("/pricing/quote"));
    expect(quotes()).toHaveLength(1);
    expect(nonce).toHaveBeenCalledTimes(1);
    expect(await transfer.canReuseForApproval!()).toBe(true);
    nonce.mockResolvedValue(4);
    expect(await transfer.canReuseForApproval!()).toBe(false);
    await transfer.refreshFees();
    expect(quotes()).toHaveLength(2);
    expect(await transfer.canReuseForApproval!()).toBe(true);
  });

  it.each([{ ttl: undefined }, { ttl: 0 }, { ttl: 10 }])("avoids reusing unknown or imminent expiry ($ttl)", async ({ ttl }) => {
    quoteTtl = ttl;
    const transfer = await prepareTransfer({ tokenAddress: USDC, recipientAddress: RECIPIENT_A, amount: 1n, senderAddress: SENDER,
      publicClient: { getTransactionCount: async () => 1, estimateContractGas: async () => 10n } as any, network });
    expect(await transfer.canReuseForApproval!()).toBe(false);
  });

  it("rejects a signed funding layout that contradicts the predicted approval assets", async () => {
    signedFundingOverride = { [NATIVE_TOKEN_ADDRESS]: "30" };
    await expect(prepareTransfer({ tokenAddress: USDC, recipientAddress: RECIPIENT_A, amount: 5n, senderAddress: SENDER,
      publicClient: { getTransactionCount: async () => 1 } as any, network })).rejects.toMatchObject({ code: "INVALID_PRICING_QUOTE" });
  });

  it("rechecks the spender before signing and reports wallet dispatch and hash before receipt", async () => {
    const rpc = {
      getTransactionCount: vi.fn().mockResolvedValue(3),
      estimateContractGas: vi.fn().mockResolvedValue(40_000n),
      waitForTransactionReceipt: vi.fn().mockResolvedValue({ status: "success", gasUsed: 35_000n }),
    };
    const transfer = await prepareTransfer({
      tokenAddress: USDC, recipientAddress: RECIPIENT_A, amount: 2n,
      senderAddress: SENDER, publicClient: rpc as any, network,
    });
    const wallet = { account: { address: SENDER }, writeContract: vi.fn().mockResolvedValue(DEPLOY_HASH) };
    const hooks = { onWalletRequest: vi.fn(), onBroadcast: vi.fn() };
    rpc.getTransactionCount.mockResolvedValueOnce(4);
    await expect(transfer.approve(wallet as any, hooks).next()).rejects.toMatchObject({ code: "STALE_PREPARATION" });
    expect(wallet.writeContract).not.toHaveBeenCalled();
    expect(hooks.onWalletRequest).not.toHaveBeenCalled();

    const sequence = transfer.approve(wallet as any, hooks);
    await sequence.next();
    expect(hooks.onBroadcast).toHaveBeenCalledWith(DEPLOY_HASH);
    const order = [hooks.onWalletRequest, wallet.writeContract, hooks.onBroadcast, rpc.waitForTransactionReceipt]
      .map(mock => mock.mock.invocationCallOrder[0]);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(await transfer.canReuseForApproval!()).toBe(false);
    await sequence.next();
  });

  it("quotes a one-row ERC-20 transfer with one blinded signer", async () => {
    const publicClient = {
      getTransactionCount: vi.fn().mockResolvedValue(5),
      estimateContractGas: vi.fn().mockResolvedValue(46_000n),
    } as any;
    const prepared = await prepareTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      senderAddress: SENDER,
      publicClient,
      network,
    });

    expect(pricingBody.escrow_type).toBe("erc20");
    expect(camouflageBody.escrow_type).toBe("erc20");
    expect(pricingBody.blinded_signers).toHaveLength(1);
    expect(pricingBody.signals).toEqual([
      {
        asset: USDC,
        execution_mode: "private",
        items: [{ client_row_id: "row-0", recipient: RECIPIENT_A, amount: "100" }],
      },
    ]);
    expect(prepared.fees.serviceFee).toEqual({ asset: USDC, amount: 25n });
    expect(prepared.fees.approvalGasEstimate).toBe(46_000n);
    expect(prepared.fees.deploymentGasEstimate).toBe(1_234_567n);
    expect(prepared.fees.totalWalletGasEstimate).toBe(1_280_567n);
  });

  it("quotes a one-row native transfer as a native escrow", async () => {
    const prepared = await prepareTransfer({
      tokenAddress: NATIVE_TOKEN_ADDRESS,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      senderAddress: SENDER,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
      network,
    });

    expect(pricingBody.escrow_type).toBe("native");
    expect(camouflageBody.escrow_type).toBe("native");
    expect(pricingBody.blinded_signers).toHaveLength(1);
    expect(prepared.fees.rewardAsset).toBe(NATIVE_TOKEN_ADDRESS);
  });

  it("rejects a quote for a different escrow artifact", async () => {
    quotedEscrowType = "batch";

    await expect(
      prepareTransfer({
        tokenAddress: USDC,
        recipientAddress: RECIPIENT_A,
        amount: 100n,
        senderAddress: SENDER,
        publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
        network,
      }),
    ).rejects.toMatchObject({ code: "INVALID_PRICING_QUOTE" });
  });

  it("keeps preparation available when approval gas simulation is unavailable", async () => {
    const prepared = await prepareTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      senderAddress: SENDER,
      publicClient: {
        getTransactionCount: vi.fn().mockResolvedValue(5),
        estimateContractGas: vi.fn().mockRejectedValue(new Error("RPC unavailable")),
      } as any,
      network,
    });

    expect(prepared.fees.approvalGasEstimate).toBeUndefined();
    expect(prepared.fees.deploymentGasEstimate).toBe(1_234_567n);
    expect(prepared.fees.totalWalletGasEstimate).toBeUndefined();
  });

  it("groups rows by asset while preserving the first asset as the reward asset", async () => {
    const prepared = await prepareTransfer({
      transfers: [
        { tokenAddress: NATIVE_TOKEN_ADDRESS, recipientAddress: RECIPIENT_A, amount: 100n },
        { tokenAddress: USDC, recipientAddress: RECIPIENT_B, amount: 200n },
        { tokenAddress: NATIVE_TOKEN_ADDRESS, recipientAddress: RECIPIENT_B, amount: 50n },
      ],
      senderAddress: SENDER,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
      network,
    });

    expect(pricingBody.blinded_signers).toHaveLength(3);
    expect(pricingBody.escrow_type).toBe("batch");
    expect(camouflageBody.escrow_type).toBe("batch");
    expect(pricingBody.signals.map((signal: any) => signal.asset)).toEqual([
      NATIVE_TOKEN_ADDRESS,
      USDC,
    ]);
    expect(pricingBody.signals[0].execution_mode).toBe("native");
    expect(pricingBody.signals[0].items).toHaveLength(2);
    expect(pricingBody.signals[1].execution_mode).toBe("private");
    expect(prepared.fees.rewardAsset).toBe(NATIVE_TOKEN_ADDRESS);
  });

  it("requires the sender before requesting a quote", async () => {
    await expect(
      prepareTransfer({
        tokenAddress: USDC,
        recipientAddress: RECIPIENT_A,
        amount: 100n,
        publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
        network,
      }),
    ).rejects.toMatchObject({ code: "SENDER_REQUIRED" });
  });

  it.each(["depositByAsset", "msgValue"] as const)(
    "rejects resume data missing %s with INVALID_RESUME",
    async (field) => {
      await expect(
        prepareTransfer({
          tokenAddress: USDC,
          recipientAddress: RECIPIENT_A,
          amount: 100n,
          publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
          network,
          resume: { ...VALID_RESUME, [field]: undefined } as any,
        }),
      ).rejects.toMatchObject({
        code: "INVALID_RESUME",
        message: "Resume data is missing or contains invalid pricing and funding values",
      });
    },
  );

  it("retains the deployed escrow type when resuming", async () => {
    const prepared = await prepareTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
      network,
      resume: { ...VALID_RESUME, escrowType: "erc20" },
    });

    await expect(prepared.deploy({} as any)).resolves.toMatchObject({
      escrowType: "erc20",
      secrets: { escrowType: "erc20" },
    });
  });

  it("rejects a batch resume with only one row", async () => {
    await expect(
      prepareTransfer({
        tokenAddress: USDC,
        recipientAddress: RECIPIENT_A,
        amount: 100n,
        publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
        network,
        resume: { ...VALID_RESUME, escrowType: "batch" },
      }),
    ).rejects.toMatchObject({ code: "INVALID_RESUME" });
  });

  it("accepts a batch resume with multiple rows", async () => {
    await expect(
      prepareTransfer({
        transfers: [
          { tokenAddress: USDC, recipientAddress: RECIPIENT_A, amount: 40n },
          { tokenAddress: USDC, recipientAddress: RECIPIENT_B, amount: 60n },
        ],
        publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
        network,
        resume: { ...VALID_RESUME, escrowType: "batch" },
      }),
    ).resolves.toBeDefined();
  });

  it("preserves execution approval rejection as an API error", async () => {
    const prepared = await prepareTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
      network,
      resume: VALID_RESUME,
    });
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      statusText: "Forbidden",
      text: async () =>
        JSON.stringify({
          error: "Predicate screening failed",
          details: "participant rejected",
        }),
    }) as any;

    const completion = prepared.complete({ account: { address: SENDER } } as any);
    await expect(completion.next()).rejects.toMatchObject({
      code: "API_ERROR",
      statusCode: 403,
    });
  });

  it("resumes an admitted request without recertifying or re-encrypting after quote expiry", async () => {
    const prepared = await prepareTransfer({ tokenAddress: USDC, recipientAddress: RECIPIENT_A,
      amount: 100n, publicClient: {} as any, network, resume: VALID_RESUME });
    const receipt = signedAdmission({ escrowContract: SENDER });
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200,
      json: async () => ({ status: "admitted", admissionReceipt: receipt }) }) as any;
    const completion = prepared.complete({ account: { address: SENDER } } as any);
    const next = await completion.next();
    expect(next.value).toEqual({ step: "signal", response: JSON.stringify({ status: "admitted", admissionReceipt: receipt }) });
    expect(globalThis.fetch).toHaveBeenCalledOnce();
    expect(String(vi.mocked(globalThis.fetch).mock.calls[0][0])).toMatch(/admission\/lookup$/);
    await completion.return(undefined);
  });
});

describe("nomad proxy routing", () => {
  const prepare = () =>
    prepareTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      senderAddress: SENDER,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
      network,
    });

  it("requests attestation through the per-chain proxy path", async () => {
    await prepare();
    expect(attestUrl).toBe("https://api.test/nomad/31337/attest");
  });

  it("rejects a key attested for a different chain than the one requested", async () => {
    // The proxy picks the node, so a wrong-chain answer must fail rather than
    // encrypt the signal to an enclave keyed to another chain.
    attestedChainId = 1;
    await expect(prepare()).rejects.toMatchObject({ code: "INVALID_NETWORK_KEY" });
  });

  it("accepts an attestation that reports no chain", async () => {
    attestedChainId = 0;
    await expect(prepare()).resolves.toBeDefined();
  });
});

describe("previewTransfer", () => {
  it("quotes fees with no sender, wallet, or attestation", async () => {
    const preview = await previewTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      network,
    });

    expect(pricingBody.sender).toBeUndefined();
    expect(pricingBody.blinded_signers).toBeUndefined();
    expect(pricingBody.escrow_type).toBe("erc20");
    expect(attestUrl).toBeUndefined();
    expect(preview.serviceFee).toEqual({ asset: USDC, amount: 25n });
    expect(preview.rewardAmount).toBe(25n);
    expect(preview.depositByAsset).toEqual({ [USDC]: 125n });
    expect(preview.assetRequirements).toEqual([
      { tokenAddress: USDC, transferAmount: 100n, escrowAmount: 125n },
    ]);
  });

  it("simulates wallet gas against a stand-in sender when given a public client", async () => {
    const estimateContractGas = vi.fn().mockResolvedValue(46_000n);
    const preview = await previewTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      network,
      publicClient: {
        getTransactionCount: vi.fn().mockResolvedValue(0),
        estimateContractGas,
      } as any,
    });

    // Approve gas does not depend on the caller's balance, so a stand-in
    // sender yields the same estimate the connected wallet will pay.
    expect(estimateContractGas).toHaveBeenCalledWith(
      expect.objectContaining({ account: "0x0000000000000000000000000000000000000001" }),
    );
    expect(preview.approvalGasEstimate).toBe(46_000n);
    expect(preview.deploymentGasEstimate).toBe(1_234_567n);
    expect(preview.totalWalletGasEstimate).toBe(1_280_567n);
  });

  it("omits wallet gas when no public client is supplied", async () => {
    const preview = await previewTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      network,
    });

    expect(preview.approvalGasEstimate).toBeUndefined();
    expect(preview.totalWalletGasEstimate).toBeUndefined();
  });

  it("keeps previewing when approval gas simulation fails", async () => {
    const preview = await previewTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      network,
      publicClient: {
        getTransactionCount: vi.fn().mockRejectedValue(new Error("RPC unavailable")),
      } as any,
    });

    expect(preview.approvalGasEstimate).toBeUndefined();
    expect(preview.totalWalletGasEstimate).toBeUndefined();
    expect(preview.serviceFee).toEqual({ asset: USDC, amount: 25n });
  });

  it("exposes no deployable field", async () => {
    const preview = await previewTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      network,
    });

    expect(preview).not.toHaveProperty("quoteCommitment");
    expect(preview).not.toHaveProperty("constructorArgs");
    expect(preview).not.toHaveProperty("sealedPricingAuthorization");
  });

  it("agrees with the sender-bound quote on fees for identical rows", async () => {
    const rows = [
      { tokenAddress: USDC, recipientAddress: RECIPIENT_A, amount: 100n },
      { tokenAddress: USDC, recipientAddress: RECIPIENT_B, amount: 200n },
    ];
    const publicClient = () =>
      ({
        getTransactionCount: vi.fn().mockResolvedValue(5),
        estimateContractGas: vi.fn().mockResolvedValue(46_000n),
      }) as any;
    const preview = await previewTransfer({
      transfers: rows,
      network,
      publicClient: publicClient(),
    });
    const prepared = await prepareTransfer({
      transfers: rows,
      senderAddress: SENDER,
      publicClient: publicClient(),
      network,
    });

    expect(preview.approvalGasEstimate).toBe(prepared.fees.approvalGasEstimate);
    expect(preview.deploymentGasEstimate).toBe(prepared.fees.deploymentGasEstimate);
    expect(preview.totalWalletGasEstimate).toBe(prepared.fees.totalWalletGasEstimate);
    expect(preview.serviceFee).toEqual(prepared.fees.serviceFee);
    expect(preview.rewardAsset).toBe(prepared.fees.rewardAsset);
    expect(preview.rewardAmount).toBe(prepared.fees.rewardAmount);
    expect(preview.depositByAsset).toEqual(prepared.fees.depositByAsset);
    expect(preview.msgValue).toBe(prepared.fees.msgValue);
    expect(preview.assetRequirements).toEqual(prepared.fees.assetRequirements);
  });

  it("still previews a native transfer", async () => {
    const preview = await previewTransfer({
      tokenAddress: NATIVE_TOKEN_ADDRESS,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      network,
    });

    expect(pricingBody.escrow_type).toBe("native");
    expect(preview.msgValue).toBe(125n);
  });

  it("rejects an unsigned quote returned for a committed sender", async () => {
    // Guards against a downgrade: a sender-bound request must never be
    // satisfied by a preview response.
    forceUnsignedQuote = true;
    await expect(
      prepareTransfer({
        tokenAddress: USDC,
        recipientAddress: RECIPIENT_A,
        amount: 100n,
        senderAddress: SENDER,
        publicClient: {
          getTransactionCount: vi.fn().mockResolvedValue(5),
          estimateContractGas: vi.fn().mockResolvedValue(46_000n),
        } as any,
        network,
      }),
    ).rejects.toMatchObject({ code: "INVALID_PRICING_QUOTE" });
  });
});

describe("zk intent", () => {
  it("sends an intent for an ERC-20 escrow", async () => {
    await prepareTransfer({
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      senderAddress: SENDER,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
      network,
    });

    expect(pricingBody.escrow_type).toBe("erc20");
    expect(pricingBody.intent.commitment).toMatch(/^0x[0-9a-f]{64}$/);
    expect(pricingBody.intent.instance_domain).toMatch(/^0x[0-9a-f]{64}$/);
    expect(pricingBody.intent.request_id).toMatch(/^0x[0-9a-f]{64}$/);
    // A zero commitment is openable by anyone who guesses the empty preimage.
    expect(pricingBody.intent.commitment).not.toBe(`0x${"00".repeat(32)}`);
  });

  it("commits native settlement and every batch row", async () => {
    await prepareTransfer({
      tokenAddress: NATIVE_TOKEN_ADDRESS,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      senderAddress: SENDER,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
      network,
    });
    expect(pricingBody.intent.commitment).toMatch(/^0x[0-9a-f]{64}$/);

    await prepareTransfer({
      transfers: [
        { tokenAddress: USDC, recipientAddress: RECIPIENT_A, amount: 100n },
        { tokenAddress: USDC, recipientAddress: RECIPIENT_B, amount: 200n },
      ],
      senderAddress: SENDER,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
      network,
    });
    expect(pricingBody.intent.commitments).toHaveLength(2);
    expect(pricingBody.intent.commitment).toBe(pricingBody.intent.commitments[0]);
    expect(new Set(pricingBody.intent.commitments).size).toBe(2);
  });

  it("binds mixed-asset commitments to grouped signed row indexes", async () => {
    const rows = [
      { tokenAddress: USDC, recipientAddress: RECIPIENT_A, amount: 100n },
      { tokenAddress: NATIVE_TOKEN_ADDRESS, recipientAddress: RECIPIENT_A, amount: 200n },
      { tokenAddress: USDC, recipientAddress: RECIPIENT_B, amount: 300n },
    ];
    const scalar = `0x${"01".repeat(32)}` as const;
    const signerSpy = vi.spyOn(bond, "deriveBlindedSigners").mockReturnValue({
      blindingScalar: scalar, blindedSigners: [SENDER, RECIPIENT_A, RECIPIENT_B],
    });
    await prepareTransfer({
      transfers: rows, senderAddress: SENDER,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
      network,
    });
    const { instance_domain: domain, request_id: requestId } = pricingBody.intent;
    const expected = [rows[0], rows[2], rows[1]].map((row, rowIndex) => intentCommitment({
      instanceDomain: domain, chainId: network.chainId,
      escrow: getContractAddress({ from: SENDER, nonce: 6n }), requestId, rowIndex,
      asset: row.tokenAddress, recipient: row.recipientAddress, amount: row.amount,
      salt: deriveSalt(scalar, domain, requestId, rowIndex),
    }));
    signerSpy.mockRestore();
    expect(pricingBody.intent.commitments).toEqual(expected);
  });

  it("rejects identical rows before requesting a quote", async () => {
    const row = { tokenAddress: USDC, recipientAddress: RECIPIENT_A, amount: 100n };
    await expect(prepareTransfer({
      transfers: [row, { ...row }], senderAddress: SENDER,
      publicClient: {} as any, network,
    })).rejects.toMatchObject({ code: "INVALID_PARAMS" });
    expect(pricingBody).toBeUndefined();
  });

  it("refreshes intent commitments when the pending deployment nonce changes", async () => {
    const scalar = `0x${"01".repeat(32)}` as const;
    const signerSpy = vi.spyOn(bond, "deriveBlindedSigners").mockReturnValue({
      blindingScalar: scalar, blindedSigners: [SENDER],
    });
    try {
      const getTransactionCount = vi.fn().mockResolvedValue(5);
      const prepared = await prepareTransfer({
        tokenAddress: USDC, recipientAddress: RECIPIENT_A, amount: 100n,
        senderAddress: SENDER, publicClient: { getTransactionCount } as any, network,
      });
      const initialIntent = pricingBody.intent;
      getTransactionCount.mockResolvedValue(8);
      await prepared.refreshFees();
      const { instance_domain: domain, request_id: requestId } = pricingBody.intent;
      expect(pricingBody.intent.commitment).toBe(intentCommitment({
        instanceDomain: domain, chainId: network.chainId,
        escrow: getContractAddress({ from: SENDER, nonce: 9n }), requestId, rowIndex: 0,
        asset: USDC, recipient: RECIPIENT_A, amount: 100n,
        salt: deriveSalt(scalar, domain, requestId, 0),
      }));
      expect(pricingBody.intent.commitment).not.toBe(initialIntent.commitment);
    } finally {
      signerSpy.mockRestore();
    }
  });

  it("binds a fresh domain and request id per preparation", async () => {
    const args = {
      tokenAddress: USDC,
      recipientAddress: RECIPIENT_A,
      amount: 100n,
      senderAddress: SENDER,
      network,
    };
    await prepareTransfer({
      ...args,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
    });
    const first = pricingBody.intent;
    await prepareTransfer({
      ...args,
      publicClient: { getTransactionCount: vi.fn().mockResolvedValue(5) } as any,
    });

    expect(pricingBody.intent.instance_domain).not.toBe(first.instance_domain);
    expect(pricingBody.intent.request_id).not.toBe(first.request_id);
    expect(pricingBody.intent.commitment).not.toBe(first.commitment);
  });
});
it("stops before a signed quote when independent address screening rejects", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = vi.fn(async (input, init) => {
    if (String(input).endsWith("/compliance/screen")) {
      return { ok:false, status:403, text:async()=>JSON.stringify({error:"Address screening rejected"}) } as Response;
    }
    return original(input, init);
  });
  await expect(prepareTransfer({tokenAddress:USDC,recipientAddress:RECIPIENT_A,amount:100n,
    senderAddress:SENDER,publicClient:{} as any,network})).rejects.toMatchObject({statusCode:403});
  expect(pricingBody).toBeUndefined();
});

it("screens changed recipients before replacing a prepared quote", async () => {
  const prepared = await prepareTransfer({tokenAddress:USDC,recipientAddress:RECIPIENT_A,amount:100n,
    senderAddress:SENDER,publicClient:{ getTransactionCount: vi.fn().mockResolvedValue(5) } as any,network});
  const initialCommitment = pricingBody.intent.commitment;
  vi.mocked(fetch).mockClear();
  await prepared.updateTransfers([{tokenAddress:USDC,recipientAddress:RECIPIENT_B,amount:100n}]);
  const calls=vi.mocked(fetch).mock.calls;
  const screenings=calls.filter(([url])=>String(url).endsWith("/compliance/screen"));
  expect(screenings.map(([,init])=>JSON.parse(String(init?.body)).address).sort()).toEqual([SENDER,RECIPIENT_B]);
  expect(pricingBody.signals[0].items[0].recipient).toBe(RECIPIENT_B);
  expect(pricingBody.intent.commitment).toMatch(/^0x[0-9a-f]{64}$/);
  expect(pricingBody.intent.commitment).not.toBe(initialCommitment);
});


it("uses the legacy escrow endpoint with the same seed when the new route is unavailable", async () => {
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(new Response(null, { status: 404 }))
    .mockResolvedValueOnce(Response.json({
      obfuscated_bytecode: "6000",
      obfuscated_size: 2,
      original_size: 2,
      gas_analysis: { obfuscated_gas_estimate: 53_000 },
    }));
  globalThis.fetch = fetchMock;

  const result = await fetchCamouflage("https://example.test", "native");

  expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
    "https://example.test/camouflage_escrow",
    "https://example.test/obfuscate_escrow",
  ]);
  expect(fetchMock.mock.calls[0][1].body).toBe(fetchMock.mock.calls[1][1].body);
  expect(result.camouflagedBytecode).toBe("0x6000");
  expect(result.camouflagedSize).toBe(2);
  expect(result.deploymentGasEstimate).toBe(53_000n);
});

describe("USDC receipt funding", () => {
  const usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7" as const;
  const sepoliaUsdc = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" as const;
  const mockUsdc = "0xd7b9DC75d34f895325E4dA3129C180e8822CcCfd" as const;
  const signer = privateKeyToAccount(`0x${"07".repeat(32)}`);

  function setup(tokens: readonly `0x${string}`[], chainId = 1) {
    attestedChainId = chainId;
    const asset = chainId === 1 ? USDC : sepoliaUsdc;
    const name = chainId === 1 ? "USD Coin" : "USDC";
    const domain = { chainId, verifyingContract: asset, name, version: "2" };
    let nonce = 5;
    const rpc = {
      getChainId: vi.fn(async () => chainId),
      getTransactionCount: vi.fn(async () => nonce),
      estimateContractGas: vi.fn(async () => 50_000n),
      readContract: vi.fn(async ({functionName}) => functionName === "name" ? name :
        hashDomain({domain, types:{EIP712Domain:getTypesForEIP712Domain({domain})}})),
      waitForTransactionReceipt: vi.fn(async () => ({status:"success",gasUsed:40_000n})),
    };
    const wallet = {
      account: signer, chain: {id:chainId},
      signTypedData: vi.fn(({account: _, ...typed}) => signer.signTypedData(typed)),
      writeContract: vi.fn(async () => { nonce += 1; return DEPLOY_HASH; }),
      sendTransaction: vi.fn(),
    };
    const params = {
      network:{...network, chainId}, publicClient:rpc as any, senderAddress:signer.address,
      transfers:tokens.map((tokenAddress, i) => ({
        tokenAddress,recipientAddress:i === 1 ? RECIPIENT_B : RECIPIENT_A,amount:100n,
      })), fundingMode:"erc3009" as const,
    };
    return {params, wallet, rpc, advance: () => { nonce += 1; }};
  }

  it.each([[1, USDC], [11155111, sepoliaUsdc]] as const)(
    "binds a hashless exact authorization to the deployment nonce on chain %i", async (chainId, asset) => {
      const {params, wallet, rpc} = setup([asset], chainId);
      const preview = await previewTransfer(params);
      expect(preview).toMatchObject({fundingMode:"erc3009", approvalGasEstimate:0n});
      const prepared = await prepareTransfer(params);
      expect(prepared.fees).toMatchObject({fundingMode:"erc3009", approvalGasEstimate:0n});
      const escrowAddress = getContractAddress({from:signer.address,nonce:5n});
      const onAuthorizationRequest = vi.fn();
      const approvals = prepared.approve(wallet as any, {onAuthorizationRequest});
      const signed = await approvals.next();
      expect(signed.value).toMatchObject({step:"authorize",tokenAddress:asset,amount:125n,escrowAddress});
      expect(onAuthorizationRequest).toHaveBeenCalledWith(expect.objectContaining({amount:125n,escrowAddress}));
      expect(wallet.signTypedData).toHaveBeenCalledWith(expect.objectContaining({
        primaryType:"ReceiveWithAuthorization", domain:expect.objectContaining({chainId,verifyingContract:asset}),
        message:expect.objectContaining({from:signer.address,to:escrowAddress,value:125n,validAfter:0n,
          validBefore:BigInt((signed.value as any).validBefore),nonce:expect.stringMatching(/^0x[0-9a-f]{64}$/)}),
      }));
      expect(await approvals.next()).toMatchObject({done:true,value:{approvals:[],approveGasUsed:0n}});
      await prepared.approve(wallet as any).next();
      expect(wallet.signTypedData).toHaveBeenCalledTimes(1);
      expect(wallet.writeContract).not.toHaveBeenCalled();
      expect(rpc.estimateContractGas).not.toHaveBeenCalled();
    },
  );

  it("signs before a mixed batch allowance and counts each remaining approval nonce", async () => {
    const {params, wallet} = setup([usdt, USDC, USDC]);
    const prepared = await prepareTransfer(params);
    expect(prepared.fees.approvalGasEstimate).toBe(50_000n);
    const approvals = prepared.approve(wallet as any);
    const escrowAddress = getContractAddress({from:signer.address,nonce:6n});
    expect(await approvals.next()).toMatchObject({value:{step:"authorize",tokenAddress:USDC,amount:200n,escrowAddress}});
    expect(wallet.writeContract).not.toHaveBeenCalled();
    expect(await approvals.next()).toMatchObject({value:{step:"approve",tokenAddress:usdt,total:1}});
    expect(wallet.writeContract).toHaveBeenCalledWith(expect.objectContaining({address:usdt,args:[escrowAddress,125n]}));
    expect(await approvals.next()).toMatchObject({value:{approveGasUsed:40_000n}});
  });

  it("recomputes the commitment and quote at the legacy nonce when the API predates authorization", async () => {
    supportsReceiptFunding = false;
    const {params, wallet} = setup([USDC]);
    expect((await previewTransfer(params)).fundingMode).toBe("allowance");
    const prepared = await prepareTransfer(params);
    expect(prepared.fees.fundingMode).toBe("allowance");
    const approvals = prepared.approve(wallet as any);
    expect(await approvals.next()).toMatchObject({value:{step:"approve"}});
    expect(wallet.writeContract).toHaveBeenCalledWith(expect.objectContaining({
      args:[getContractAddress({from:signer.address,nonce:6n}),125n],
    }));
    expect(wallet.signTypedData).not.toHaveBeenCalled();
    const requests = vi.mocked(fetch).mock.calls.filter(([url,init]) =>
      String(url).endsWith("/pricing/quote") && JSON.parse(init!.body as string).sender);
    expect(requests.map(([,init]) => JSON.parse(init!.body as string).funding_mode)).toEqual(["erc3009",undefined]);
    expect(JSON.parse(requests[0][1]!.body as string).intent.commitment)
      .not.toBe(JSON.parse(requests[1][1]!.body as string).intent.commitment);
  });

  it.each([
    ["unknown field `funding_mode`, expected escrow_type", true],
    ["unknown field `signals`, expected escrow_type", false],
  ] as const)("handles the old server's strict JSON decoder: %s", async (details, compatible) => {
    const original = globalThis.fetch;
    globalThis.fetch = vi.fn(async (url, init) => {
      if (String(url).endsWith("/pricing/quote") && JSON.parse(init!.body as string).funding_mode) {
        return new Response(details, { status:422 });
      }
      return original(url, init);
    });
    const {params, wallet} = setup([USDC]);
    if (compatible) {
      expect((await previewTransfer(params)).fundingMode).toBe("allowance");
      expect((await prepareTransfer(params)).fees.fundingMode).toBe("allowance");
    } else {
      await expect(prepareTransfer(params)).rejects.toMatchObject({statusCode:422});
    }
    expect(wallet.signTypedData).not.toHaveBeenCalled();
  });

  it("uses ordinary allowances for a mock token with the same symbol", async () => {
    const {params, wallet} = setup([mockUsdc],11155111);
    const prepared = await prepareTransfer(params);
    expect(prepared.fees.fundingMode).toBe("allowance");
    expect(await prepared.approve(wallet as any).next()).toMatchObject({value:{step:"approve"}});
    expect(wallet.signTypedData).not.toHaveBeenCalled();
  });

  it("keeps a rejected signature and stale nonce from triggering any fallback transaction", async () => {
    const {params, wallet, advance} = setup([usdt, USDC]);
    const prepared = await prepareTransfer(params);
    wallet.signTypedData.mockRejectedValueOnce(Object.assign(new Error("rejected"), {code:4001}));
    await expect(prepared.approve(wallet as any).next()).rejects.toMatchObject({code:4001});
    await expect(prepared.deploy(wallet as any)).rejects.toMatchObject({code:"INVALID_STAGE"});
    advance();
    await expect(prepared.approve(wallet as any).next()).rejects.toMatchObject({code:"STALE_PREPARATION"});
    expect(wallet.writeContract).not.toHaveBeenCalled();
    expect(wallet.sendTransaction).not.toHaveBeenCalled();
    expect(wallet.signTypedData).toHaveBeenCalledTimes(1);
  });

  it("refuses an incorrect domain, inflated funding amount, or missing quote expiry before signing", async () => {
    const {params, wallet, rpc} = setup([USDC]);
    rpc.readContract.mockImplementation(async ({functionName}) => functionName === "name" ? "USD Coin" : COMMITMENT);
    const prepared = await prepareTransfer(params);
    await expect(prepared.approve(wallet as any).next()).rejects.toMatchObject({code:"UNSUPPORTED_AUTHORIZATION"});
    signedFundingOverride = {[USDC]:"99999"};
    await expect(prepareTransfer(params)).rejects.toMatchObject({code:"INVALID_PRICING_QUOTE"});
    signedFundingOverride = undefined;
    quoteTtl = undefined;
    await expect(prepareTransfer(params)).rejects.toMatchObject({code:"INVALID_PRICING_QUOTE"});
    expect(wallet.signTypedData).not.toHaveBeenCalled();
  });
});
