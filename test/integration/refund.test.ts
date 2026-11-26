import fs from "node:fs";
import path from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  bytesToHex,
  createTestClient,
  hexToBytes,
  http,
  parseAbi,
  parseEther,
  toFunctionSelector,
  type Address,
  type Hex,
} from "viem";
import { cancelTransfer, getEscrowStatus, withdrawFromEscrow } from "../../src/internal/escrow.js";
import {
  ACCOUNTS,
  anvilChain,
  getPublicClient,
  getWalletClient,
  isTestnet,
  RPC_URL,
  startAnvil,
  stopAnvil,
} from "./setup.js";

const ARTIFACT_DIR = process.env.ESCROW_ARTIFACT_DIR
  ?? path.resolve(import.meta.dirname, "../../../escrow/artifacts");
const PRINCIPAL = parseEther("1");
const REWARD = parseEther("0.05");
const COMMITMENT = `0x${"11".repeat(32)}` as Hex;
const DOMAIN = `0x${"22".repeat(32)}` as Hex;
const REQUEST = `0x${"33".repeat(32)}` as Hex;
const nativeZkAbi = parseAbi([
  "constructor(uint256 payoutAmount, bytes32 intentCommitment, bytes32 instanceDomain, bytes32 requestHash, address blindedSigner, uint256 reward, uint256 maxGasAdvance) payable",
  "function collectionDeadline() view returns (uint256)",
  "function is_bonded() view returns (bool)",
  "function bond(uint256 gasAdvance, bytes bondSig)",
]);
const legacyNativeAbi = parseAbi([
  "constructor(address expectedRecipient, uint256 expectedAmount, address blindedSigner, uint256 reward, uint256 maxGasAdvance) payable",
]);
const deadlineSelector = toFunctionSelector("collectionDeadline()");
function remappedSelector(selector: Hex): Hex {
  const bytes = hexToBytes(selector);
  bytes[3] ^= 1;
  return bytesToHex(bytes);
}
const mappedSelectors = {
  [deadlineSelector]: remappedSelector(deadlineSelector),
  [toFunctionSelector("cancelAndWithdraw()")]: remappedSelector(toFunctionSelector("cancelAndWithdraw()")),
  [toFunctionSelector("is_bonded()")]: remappedSelector(toFunctionSelector("is_bonded()")),
} as Record<string, Hex>;

function deploymentArtifact(name: string): Hex {
  const bytecode = fs.readFileSync(path.join(ARTIFACT_DIR, name), "utf8").trim();
  return (bytecode.startsWith("0x") ? bytecode : `0x${bytecode}`) as Hex;
}

// Rename instruction-aligned PUSH4 selectors in a real deployed artifact.
// Constructor state, deadline checks and payout logic stay unchanged. This
// verifies mapped calls without requiring the API's camouflage service.
function renameSelectors(code: Hex, mapping: Record<string, Hex>): Hex {
  const bytes = hexToBytes(code);
  const existing = new Set<string>();
  for (let offset = 0; offset < bytes.length; offset++) {
    const opcode = bytes[offset];
    if (opcode < 0x60 || opcode > 0x7f) continue;
    const width = opcode - 0x5f;
    if (width === 4) existing.add(bytesToHex(bytes.subarray(offset + 1, offset + 5)));
    offset += width;
  }
  for (const replacement of Object.values(mapping)) expect(existing.has(replacement)).toBe(false);
  const replaced = new Set<string>();
  for (let offset = 0; offset < bytes.length; offset++) {
    const opcode = bytes[offset];
    if (opcode < 0x60 || opcode > 0x7f) continue;
    const width = opcode - 0x5f;
    if (width === 4) {
      const selector = bytesToHex(bytes.subarray(offset + 1, offset + 5));
      const replacement = mapping[selector];
      if (replacement !== undefined) {
        bytes.set(hexToBytes(replacement), offset + 1);
        replaced.add(selector);
      }
    }
    offset += width;
  }
  expect([...replaced].sort()).toEqual(Object.keys(mapping).sort());
  return bytesToHex(bytes);
}

describe.skipIf(isTestnet)("Escrow refund windows on Anvil", () => {
  const publicClient = getPublicClient();
  const testClient = createTestClient({ chain: anvilChain, mode: "anvil", transport: http(RPC_URL) });
  let snapshot: Hex | undefined;

  beforeAll(async () => { await startAnvil(); }, 120_000);
  afterAll(() => { stopAnvil(); });
  beforeEach(async () => { snapshot = await testClient.snapshot(); });
  afterEach(async () => {
    vi.restoreAllMocks();
    if (snapshot !== undefined) await testClient.revert({ id: snapshot });
  });

  async function deployFixedWindow(): Promise<{ address: Address; deadline: bigint }> {
    const walletClient = getWalletClient();
    const hash = await walletClient.deployContract({
      abi: nativeZkAbi,
      bytecode: deploymentArtifact("native_zk_deployment.hex"),
      args: [PRINCIPAL, COMMITMENT, DOMAIN, REQUEST, ACCOUNTS.deployer.address, REWARD, 0n],
      value: PRINCIPAL + REWARD,
      gas: 6_000_000n,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    expect(receipt.status).toBe("success");
    const address = receipt.contractAddress!;
    const deadline = await publicClient.readContract({ address, abi: nativeZkAbi, functionName: "collectionDeadline" });
    const fundingBlock = await publicClient.getBlock({ blockNumber: receipt.blockNumber });
    expect(deadline).toBe(fundingBlock.timestamp + 1800n);
    const code = await publicClient.getCode({ address });
    await testClient.setCode({ address, bytecode: renameSelectors(code!, mappedSelectors) });
    // The canonical getter is gone: a missing mapping cannot accidentally pass.
    await expect(publicClient.readContract({ address, abi: nativeZkAbi, functionName: "collectionDeadline" })).rejects.toThrow();
    return { address, deadline };
  }

  async function mineAt(timestamp: bigint): Promise<void> {
    await testClient.setNextBlockTimestamp({ timestamp });
    await testClient.mine({ blocks: 1 });
    expect((await publicClient.getBlock({ blockTag: "latest" })).timestamp).toBe(timestamp);
  }

  it("rejects early mapped cancellation without a wallet transaction, then refunds at the exact cutoff", async () => {
    const { address, deadline } = await deployFixedWindow();
    const walletClient = getWalletClient();
    const params = { escrowAddress: address, publicClient, walletClient, account: ACCOUNTS.sender.address, selectorMapping: mappedSelectors };
    await mineAt(deadline - 60n);
    expect(await getEscrowStatus(params)).toEqual({ bonded: false, cancellable: false });
    const nonce = await publicClient.getTransactionCount({ address: ACCOUNTS.sender.address, blockTag: "pending" });
    const send = vi.spyOn(walletClient, "sendTransaction");
    await expect(withdrawFromEscrow(params)).rejects.toThrow("refunds unlock 30 minutes after the escrow was funded");
    await expect(cancelTransfer(params)).rejects.toThrow("refunds unlock 30 minutes after the escrow was funded");
    expect(send).not.toHaveBeenCalled();
    expect(await publicClient.getTransactionCount({ address: ACCOUNTS.sender.address, blockTag: "pending" })).toBe(nonce);

    await mineAt(deadline - 1n);
    expect(await getEscrowStatus(params)).toEqual({ bonded: false, cancellable: false });
    await mineAt(deadline);
    expect(await getEscrowStatus(params)).toEqual({ bonded: false, cancellable: true });
    const hash = await cancelTransfer(params);
    expect((await publicClient.getTransactionReceipt({ hash })).status).toBe("success");
    expect(send).toHaveBeenCalledOnce();
    expect(await publicClient.getBalance({ address })).toBe(0n);
  }, 30_000);

  it("expires a mapped bonded escrow at the same fixed refund cutoff", async () => {
    const { address, deadline } = await deployFixedWindow();
    const collector = getWalletClient(ACCOUNTS.deployer);
    const signature = await collector.signTypedData({
      domain: { name: "MirageEscrow", version: "1", chainId: anvilChain.id, verifyingContract: address },
      types: { BondAuth: [{ name: "bondingExecutor", type: "address" }, { name: "gasAdvance", type: "uint256" }] },
      primaryType: "BondAuth",
      message: { bondingExecutor: ACCOUNTS.deployer.address, gasAdvance: 0n },
    });
    const hash = await collector.writeContract({ address, abi: nativeZkAbi, functionName: "bond", args: [0n, signature] });
    expect((await publicClient.waitForTransactionReceipt({ hash })).status).toBe("success");
    const params = { escrowAddress: address, publicClient, selectorMapping: mappedSelectors };
    expect(await getEscrowStatus(params)).toEqual({ bonded: true, cancellable: false });
    await mineAt(deadline);
    expect(await getEscrowStatus(params)).toEqual({ bonded: false, cancellable: true });
    await cancelTransfer({ ...params, walletClient: getWalletClient(), account: ACCOUNTS.sender.address });
    expect(await publicClient.getBalance({ address })).toBe(0n);
  }, 30_000);

  it("requires explicit legacy policy when an older plaintext escrow has no deadline getter", async () => {
    const walletClient = getWalletClient();
    const hash = await walletClient.deployContract({
      abi: legacyNativeAbi,
      bytecode: deploymentArtifact("native_deployment.hex"),
      args: [ACCOUNTS.recipient.address, PRINCIPAL, ACCOUNTS.deployer.address, REWARD, 0n],
      value: PRINCIPAL + REWARD,
      gas: 6_000_000n,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    expect(receipt.status).toBe("success");
    const address = receipt.contractAddress!;
    // Current plaintext artifacts may expose the common zero getter. Hide its
    // dispatch entry to model deployed legacy bytecode that has no such getter.
    const code = await publicClient.getCode({ address });
    await testClient.setCode({ address, bytecode: renameSelectors(code!, { [deadlineSelector]: remappedSelector(deadlineSelector) }) });
    const params = { escrowAddress: address, publicClient };
    await expect(getEscrowStatus(params)).rejects.toThrow();
    expect(await getEscrowStatus({ ...params, refundPolicy: "legacy" })).toEqual({ bonded: false, cancellable: true });
    await cancelTransfer({ ...params, walletClient, account: ACCOUNTS.sender.address });
    expect(await publicClient.getBalance({ address })).toBe(0n);
  }, 30_000);
});
