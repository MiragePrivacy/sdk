import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { executeTransfer } from "../../src/transfer.js";
import { getTokenBalance, NATIVE_TOKEN_ADDRESS } from "../../src/token.js";
import { TransferAbortedError } from "../../src/errors.js";
import type { TransferStep } from "../../src/types.js";
import {
  ACCOUNTS,
  getPublicClient,
  getWalletClient,
  getNetwork,
  startAll,
  stopAll,
  getTusdcAddress,
  isTestnet,
  TOKEN_ADDRESS,
} from "./setup.js";
import { parseUnits } from "viem";

function bigintReplacer(_key: string, value: unknown) {
  return typeof value === "bigint" ? value.toString() : value;
}

describe("Full transfer flow", () => {
  beforeAll(async () => {
    await startAll();
  }, 120_000);

  afterAll(async () => {
    await stopAll();
  });

  it("executes an ERC20 transfer end-to-end", { timeout: 300_000 }, async () => {
    const tokenAddress = isTestnet ? TOKEN_ADDRESS : getTusdcAddress();
    if (!tokenAddress || tokenAddress === NATIVE_TOKEN_ADDRESS) {
      console.log("Skipping ERC20 test — no TOKEN_ADDRESS set or is native");
      return;
    }

    const publicClient = getPublicClient();
    const walletClient = getWalletClient();
    const network = getNetwork();

    const amount = parseUnits("10", 6);
    const steps: TransferStep[] = [];

    for await (const step of executeTransfer({
      tokenAddress,
      recipientAddress: ACCOUNTS.recipient.address,
      amount,
      walletClient,
      publicClient,
      network,
      ...(!isTestnet && {
        gasPrice: {
          maxFeePerGas: 20_000_000_000n,
          maxPriorityFeePerGas: 1_000_000_000n,
        },
      }),
      pollTimeout: 240_000,
    })) {
      steps.push(step);
      console.log(`Step: ${step.step}`, JSON.stringify(step, bigintReplacer));
    }

    const stepNames = steps.map((s) => s.step);
    expect(stepNames).toContain("fees");
    if (network.enableBatch) {
      // Tempo: approve is batched into deploy
      expect(stepNames).not.toContain("approve");
    } else {
      expect(stepNames).toContain("approve");
    }
    expect(stepNames).toContain("deploy");
    if (network.enableCompliance) {
      expect(stepNames).toContain("compliance");
    }
    expect(stepNames).toContain("signal");
    expect(stepNames).toContain("complete");

    const completeStep = steps.find((s) => s.step === "complete");
    expect(completeStep).toBeDefined();
    if (completeStep?.step === "complete") {
      expect(completeStep.transfer.to).toBe(ACCOUNTS.recipient.address);
      expect(completeStep.transfer.amount).toBe(amount);
      expect(completeStep.transfer.transactionHash).toMatch(/^0x[0-9a-f]{64}$/);
    }
  });

  // Tempo batch mode doesn't support native ETH escrow (native token is a stablecoin)
  it.skipIf(isTestnet && getNetwork().enableBatch)("executes a native transfer end-to-end", { timeout: 300_000 }, async () => {
    const publicClient = getPublicClient();
    const walletClient = getWalletClient();
    const network = getNetwork();

    const amount = parseUnits("0.01", 18);

    const balanceBefore = await getTokenBalance(
      NATIVE_TOKEN_ADDRESS,
      ACCOUNTS.recipient.address,
      publicClient,
    );

    const steps: TransferStep[] = [];

    for await (const step of executeTransfer({
      tokenAddress: NATIVE_TOKEN_ADDRESS,
      recipientAddress: ACCOUNTS.recipient.address,
      amount,
      walletClient,
      publicClient,
      network,
      ...(!isTestnet && {
        gasPrice: {
          maxFeePerGas: 20_000_000_000n,
          maxPriorityFeePerGas: 1_000_000_000n,
        },
      }),
      pollTimeout: 240_000,
    })) {
      steps.push(step);
      console.log(`Step: ${step.step}`, JSON.stringify(step, bigintReplacer));
    }

    const stepNames = steps.map((s) => s.step);
    expect(stepNames).toContain("fees");
    expect(stepNames).not.toContain("approve");
    expect(stepNames).toContain("deploy");
    expect(stepNames).toContain("signal");
    expect(stepNames).toContain("complete");

    const balanceAfter = await getTokenBalance(
      NATIVE_TOKEN_ADDRESS,
      ACCOUNTS.recipient.address,
      publicClient,
    );
    expect(balanceAfter).toBeGreaterThan(balanceBefore);
  });

  it.skipIf(isTestnet)("abort signal cancels before deployment", { timeout: 30_000 }, async () => {
    const publicClient = getPublicClient();
    const walletClient = getWalletClient();
    const network = getNetwork();

    const controller = new AbortController();
    controller.abort();

    await expect(async () => {
      for await (const _step of executeTransfer({
        tokenAddress: getTusdcAddress(),
        recipientAddress: ACCOUNTS.recipient.address,
        amount: parseUnits("1", 6),
        walletClient,
        publicClient,
        network,
        abortSignal: controller.signal,
        gasPrice: {
          maxFeePerGas: 20_000_000_000n,
          maxPriorityFeePerGas: 1_000_000_000n,
        },
      })) {
        // Should not reach any step
      }
    }).rejects.toThrow(TransferAbortedError);
  });
});
