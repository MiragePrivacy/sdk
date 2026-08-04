import { describe, it, expect, vi } from "vitest";
import { getContractAddress } from "viem";
import { approveAndDeploy, predictContractAddress } from "../src/internal/escrow.js";

const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;
const USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7" as const;
const R1 = "0x0000000000000000000000000000000000000001" as const;
const ACCOUNT = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as const;

describe("predictContractAddress", () => {
  it("predicts CREATE address from deployer + nonce", () => {
    // Known test vector: deployer = 0xf39F...92266, nonce = 0
    // This matches viem's getContractAddress with CREATE opcode
    const deployer = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as `0x${string}`;
    const addr = predictContractAddress(deployer, 0);
    // Should be a valid checksummed address
    expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  it("matches viem's CREATE derivation", () => {
    for (const nonce of [0, 1, 2, 7, 64, 255, 256]) {
      expect(predictContractAddress(ACCOUNT, nonce)).toBe(
        getContractAddress({ from: ACCOUNT, nonce: BigInt(nonce), opcode: "CREATE" }),
      );
    }
  });

  it("different nonce produces different address", () => {
    const deployer = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as `0x${string}`;
    const addr0 = predictContractAddress(deployer, 0);
    const addr1 = predictContractAddress(deployer, 1);
    const addr2 = predictContractAddress(deployer, 2);
    expect(addr0).not.toBe(addr1);
    expect(addr1).not.toBe(addr2);
  });

  it("is deterministic", () => {
    const deployer = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as `0x${string}`;
    const a = predictContractAddress(deployer, 5);
    const b = predictContractAddress(deployer, 5);
    expect(a).toBe(b);
  });
});

describe("approveAndDeploy", () => {
  const NONCE = 4;

  function mocks(options: { deployedAddress?: `0x${string}` } = {}) {
    const sent: Array<{ kind: string; args?: unknown }> = [];

    const publicClient = {
      getTransactionCount: vi.fn().mockResolvedValue(NONCE),
      waitForTransactionReceipt: vi.fn().mockImplementation(({ hash }: { hash: string }) =>
        Promise.resolve({
          status: "success",
          gasUsed: 50_000n,
          effectiveGasPrice: 1n,
          contractAddress: hash === "0xdeploy" ? options.deployedAddress : undefined,
        }),
      ),
    } as any;

    const walletClient = {
      chain: undefined,
      writeContract: vi.fn().mockImplementation((args: any) => {
        sent.push({ kind: "approve", args });
        return Promise.resolve(`0xapprove${sent.length}`);
      }),
      sendTransaction: vi.fn().mockImplementation(() => {
        sent.push({ kind: "deploy" });
        return Promise.resolve("0xdeploy");
      }),
    } as any;

    return { publicClient, walletClient, sent };
  }

  const baseArgs = {
    bytecode: "0x60" as `0x${string}`,
    rewardAmount: 5n,
    blindedSigner: "0x00000000000000000000000000000000000000aa" as `0x${string}`,
    bondPot: 0n,
    account: ACCOUNT,
  };

  it("predicts the escrow at nonce + one approval per distinct token", async () => {
    const expected = predictContractAddress(ACCOUNT, NONCE + 2);
    const { publicClient, walletClient, sent } = mocks({ deployedAddress: expected });

    const result = await approveAndDeploy({
      ...baseArgs,
      escrowType: "batch",
      transfers: [
        { tokenAddress: USDC, recipientAddress: R1, amount: 100n },
        { tokenAddress: USDT, recipientAddress: R1, amount: 200n },
      ],
      walletClient,
      publicClient,
    });

    expect(result.deployResult.escrowAddress).toBe(expected);
    // Two approvals then the deploy: the deploy must land on the predicted nonce.
    expect(sent.map((s) => s.kind)).toEqual(["approve", "approve", "deploy"]);
    // Every approval targets the address the escrow will occupy.
    for (const call of sent.filter((s) => s.kind === "approve")) {
      expect((call.args as any).args[0]).toBe(expected);
    }
  });

  it("approves once per token, never resetting against a fresh escrow", async () => {
    const expected = predictContractAddress(ACCOUNT, NONCE + 1);
    const { publicClient, walletClient, sent } = mocks({ deployedAddress: expected });

    await approveAndDeploy({
      ...baseArgs,
      escrowType: "erc20",
      transfers: [{ tokenAddress: USDT, recipientAddress: R1, amount: 100n }],
      walletClient,
      publicClient,
    });

    const approvals = sent.filter((s) => s.kind === "approve");
    expect(approvals).toHaveLength(1);
    // A zero-reset would add a tx and shift the deploy off the predicted nonce.
    expect((approvals[0].args as any).args[1]).toBe(105n);
  });

  it("throws when the deployed address is not the predicted one", async () => {
    const { publicClient, walletClient } = mocks({
      deployedAddress: "0x000000000000000000000000000000000000dead",
    });

    await expect(
      approveAndDeploy({
        ...baseArgs,
        escrowType: "erc20",
        transfers: [{ tokenAddress: USDC, recipientAddress: R1, amount: 100n }],
        walletClient,
        publicClient,
      }),
    ).rejects.toThrow(/was predicted/);
  });

  it("checks for aborts between approvals", async () => {
    const expected = predictContractAddress(ACCOUNT, NONCE + 2);
    const { publicClient, walletClient } = mocks({ deployedAddress: expected });
    const onAbortCheck = vi.fn();

    await approveAndDeploy({
      ...baseArgs,
      escrowType: "batch",
      transfers: [
        { tokenAddress: USDC, recipientAddress: R1, amount: 100n },
        { tokenAddress: USDT, recipientAddress: R1, amount: 200n },
      ],
      walletClient,
      publicClient,
      onAbortCheck,
    });

    expect(onAbortCheck).toHaveBeenCalledTimes(2);
  });
});
