import { describe, expect, it, vi } from "vitest";
import { encodeAbiParameters, encodeErrorResult, parseAbi, toFunctionSelector } from "viem";
import { cancelTransfer, getEscrowStatus } from "../src/internal/escrow.js";
import { ContractError } from "../src/errors.js";

const ESCROW = "0x0000000000000000000000000000000000000001" as const;
const USER = "0x0000000000000000000000000000000000000002" as const;
const HASH = `0x${"11".repeat(32)}` as const;
const BONDED = toFunctionSelector("is_bonded()");
const DEADLINE = toFunctionSelector("collectionDeadline()");
const CANCEL = toFunctionSelector("cancelAndWithdraw()");
const CUTOFF = 2_800n;
const uint = (value: bigint) => encodeAbiParameters([{ type: "uint256" }], [value]);
const bool = (value: boolean) => encodeAbiParameters([{ type: "bool" }], [value]);
const refundRevert = () => ({
  cause: { cause: { data: encodeErrorResult({
    abi: parseAbi(["error RedemptionWindowActive()"]), errorName: "RedemptionWindowActive",
  }) } },
});

function clients(timestamp = CUTOFF - 1n, bonded = false) {
  const publicClient = {
    getBlock: vi.fn().mockResolvedValue({ number: 42n, timestamp }),
    call: vi.fn(async ({ data }: { data: string }) => {
      if (data === BONDED) return { data: bool(bonded) };
      if (data === DEADLINE) return { data: uint(CUTOFF) };
      throw new Error("unexpected calldata");
    }),
    getBytecode: vi.fn().mockResolvedValue("0x6000"),
    estimateGas: vi.fn().mockResolvedValue(100_001n),
    waitForTransactionReceipt: vi.fn().mockResolvedValue({ status: "success" }),
  };
  const walletClient = { chain: undefined, sendTransaction: vi.fn().mockResolvedValue(HASH) };
  return {
    publicClient,
    walletClient,
    status: { escrowAddress: ESCROW, publicClient: publicClient as any },
    withdraw: {
      escrowAddress: ESCROW, account: USER,
      publicClient: publicClient as any, walletClient: walletClient as any,
    },
  };
}

describe("escrow refund eligibility", () => {
  it.each([
    [CUTOFF - 1n, false, false],
    [CUTOFF, false, true],
    [CUTOFF + 1n, false, true],
    [CUTOFF - 1n, true, false],
    [CUTOFF, true, false],
  ])("uses chain time %s with bonded=%s", async (timestamp, bonded, cancellable) => {
    const { status, publicClient } = clients(timestamp, bonded);
    await expect(getEscrowStatus(status)).resolves.toEqual({ bonded, cancellable });
    expect(publicClient.getBlock).toHaveBeenCalledWith({ blockTag: "latest" });
    for (const [call] of publicClient.call.mock.calls) {
      expect(call).toMatchObject({ to: ESCROW, blockNumber: 42n });
    }
  });

  it("reads variable-width mapped selectors", async () => {
    const { status, publicClient } = clients(CUTOFF);
    publicClient.call.mockImplementation(async ({ data }) => {
      if (data === "0xab") return { data: bool(false) };
      if (data === "0xcdef01") return { data: uint(CUTOFF) };
      throw new Error("unmapped selector");
    });
    await expect(getEscrowStatus({ ...status, selectorMapping: {
      [BONDED]: "0xab", [DEADLINE]: "0xcdef01",
    } })).resolves.toEqual({ bonded: false, cancellable: true });
  });

  it("keeps a zero/uninitialized deadline ineligible by default", async () => {
    const { status, publicClient } = clients();
    publicClient.call.mockImplementation(async ({ data }) => ({
      data: data === BONDED ? bool(false) : uint(0n),
    }));
    await expect(getEscrowStatus(status)).resolves.toEqual({ bonded: false, cancellable: false });
  });

  it.each([false, true])("supports explicitly selected legacy policy with bonded=%s", async (bonded) => {
    const { status, publicClient } = clients(CUTOFF - 1n, bonded);
    publicClient.call.mockImplementation(async ({ data }) => {
      if (data !== BONDED) throw new Error("legacy contract has no deadline getter");
      return { data: bool(bonded) };
    });
    await expect(getEscrowStatus({ ...status, refundPolicy: "legacy" }))
      .resolves.toEqual({ bonded, cancellable: !bonded });
    expect(publicClient.call).toHaveBeenCalledTimes(1);
  });

  it.each(["0x", "0x01"])("rejects malformed getter data %s", async (data) => {
    const { status, publicClient } = clients();
    publicClient.call.mockResolvedValue({ data });
    await expect(getEscrowStatus(status)).rejects.toThrow();
  });

  it.each(["block", "bond", "deadline"])("does not infer legacy eligibility from a %s RPC failure", async (stage) => {
    const { status, publicClient } = clients();
    const failure = new Error("RPC unavailable");
    if (stage === "block") publicClient.getBlock.mockRejectedValue(failure);
    else publicClient.call.mockImplementation(async ({ data }) => {
      if (stage === "bond" || data === DEADLINE) throw failure;
      return { data: bool(false) };
    });
    await expect(getEscrowStatus(status)).rejects.toBe(failure);
  });

  it("rejects an incomplete mapping instead of treating it as legacy", async () => {
    const { status, publicClient } = clients();
    publicClient.call.mockResolvedValue({ data: bool(false) });
    await expect(getEscrowStatus({ ...status, selectorMapping: { [BONDED]: "0xab" } }))
      .rejects.toThrow("Missing or invalid escrow selector mapping");
  });
});

describe("escrow refund submission", () => {
  it("simulates the mapped call as the user and buffers its gas before sending", async () => {
    const { withdraw, publicClient, walletClient } = clients();
    await expect(cancelTransfer({ ...withdraw, selectorMapping: { [CANCEL]: "0xabcdef" } }))
      .resolves.toBe(HASH);
    const call = { account: USER, to: ESCROW, data: "0xabcdef" };
    expect(publicClient.estimateGas).toHaveBeenCalledWith(call);
    expect(walletClient.sendTransaction).toHaveBeenCalledWith({ ...call, chain: undefined, gas: 120_002n });
    expect(publicClient.estimateGas.mock.invocationCallOrder[0])
      .toBeLessThan(walletClient.sendTransaction.mock.invocationCallOrder[0]);
  });

  it("explains the refund lock without sending a transaction", async () => {
    const { withdraw, publicClient, walletClient } = clients();
    const failure = refundRevert();
    publicClient.estimateGas.mockRejectedValue(failure);
    await expect(cancelTransfer(withdraw)).rejects.toMatchObject({
      name: "ContractError", message: expect.stringContaining("30 minutes after the escrow was funded"),
      cause: failure, txHash: undefined,
    });
    expect(walletClient.sendTransaction).not.toHaveBeenCalled();
  });

  it.each(["getBytecode", "estimateGas"] as const)("never broadcasts after %s RPC fails", async (method) => {
    const { withdraw, publicClient, walletClient } = clients();
    const failure = new Error("RPC unavailable");
    publicClient[method].mockRejectedValue(failure);
    await expect(cancelTransfer(withdraw)).rejects.toBe(failure);
    expect(walletClient.sendTransaction).not.toHaveBeenCalled();
  });

  it.each([undefined, "0x"])("rejects an address with no contract code (%s)", async (code) => {
    const { withdraw, publicClient, walletClient } = clients();
    publicClient.getBytecode.mockResolvedValue(code);
    await expect(cancelTransfer(withdraw)).rejects.toThrow("No escrow contract");
    expect(walletClient.sendTransaction).not.toHaveBeenCalled();
  });

  it.each([{}, { [CANCEL]: "0x" }, { [CANCEL]: "0xabc" }, { [CANCEL]: "0xzz" }])(
    "rejects missing or malformed cancellation mapping %s", async (selectorMapping) => {
      const { withdraw, walletClient } = clients();
      await expect(cancelTransfer({ ...withdraw, selectorMapping }))
        .rejects.toThrow("Missing or invalid escrow selector mapping");
      expect(walletClient.sendTransaction).not.toHaveBeenCalled();
    },
  );

  it("retains the transaction hash if state changes after simulation and the refund reverts", async () => {
    const { withdraw, publicClient, walletClient } = clients();
    publicClient.waitForTransactionReceipt.mockResolvedValue({ status: "reverted" });
    publicClient.call.mockRejectedValue(refundRevert());
    await expect(cancelTransfer(withdraw)).rejects.toMatchObject({
      name: "ContractError", txHash: HASH,
      message: expect.stringContaining("30 minutes after the escrow was funded"),
    });
    expect(walletClient.sendTransaction).toHaveBeenCalledTimes(1);
  });

  it("retains the transaction hash if diagnosing a mined revert fails", async () => {
    const { withdraw, publicClient } = clients();
    publicClient.waitForTransactionReceipt.mockResolvedValue({ status: "reverted" });
    publicClient.call.mockRejectedValue(new Error("RPC unavailable"));
    await expect(cancelTransfer(withdraw)).rejects.toEqual(
      new ContractError("cancelAndWithdraw reverted: unknown reason", { txHash: HASH }),
    );
  });
});
