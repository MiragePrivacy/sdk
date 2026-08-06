import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { prepareTransfer } from "../../src/transfer.js";
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

const gasOverride = !isTestnet
  ? {
      gasPrice: {
        maxFeePerGas: 20_000_000_000n,
        maxPriorityFeePerGas: 1_000_000_000n,
      },
    }
  : {};

async function collectSteps(params: Parameters<typeof prepareTransfer>[0]) {
  const prepared = await prepareTransfer(params);
  const steps: TransferStep[] = [];
  for await (const step of prepared.execute()) {
    steps.push(step);
    console.log(`Step: ${step.step}`, JSON.stringify(step, bigintReplacer));
  }
  return { steps, fees: prepared.fees };
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

    const network = getNetwork();
    const amount = parseUnits("10", 6);

    const { steps } = await collectSteps({
      tokenAddress,
      recipientAddress: ACCOUNTS.recipient.address,
      amount,
      walletClient: getWalletClient(),
      publicClient: getPublicClient(),
      network,
      ...gasOverride,
      pollTimeout: 240_000,
    });

    const stepNames = steps.map((s) => s.step);
    expect(stepNames).toContain("fees");
    if (network.enableAtomicBatch) {
      // Tempo: approve is batched into deploy
      expect(stepNames).not.toContain("approve");
    } else {
      expect(stepNames).toContain("approve");
    }
    expect(stepNames).toContain("deploy");
    expect(stepNames).toContain("compliance");
    expect(stepNames).toContain("signal");
    expect(stepNames).toContain("transfer");
    expect(stepNames).toContain("complete");

    const deployStep = steps.find((s) => s.step === "deploy");
    if (deployStep?.step === "deploy") {
      expect(deployStep.escrowType).toBe("batch");
      expect(deployStep.secrets.quoteCommitment).toMatch(/^0x[0-9a-f]{64}$/);
      expect(deployStep.secrets.sealedPricingAuthorization).toMatch(/^0x[0-9a-f]+$/);
      expect(deployStep.secrets.blindingScalar).toMatch(/^0x[0-9a-f]{64}$/);
    }

    const transferStep = steps.find((s) => s.step === "transfer");
    expect(transferStep).toBeDefined();
    if (transferStep?.step === "transfer") {
      expect(transferStep.transfer.to).toBe(ACCOUNTS.recipient.address);
      expect(transferStep.transfer.amount).toBe(amount);
      expect(transferStep.total).toBe(1);
    }

    const completeStep = steps.find((s) => s.step === "complete");
    if (completeStep?.step === "complete") {
      expect(completeStep.transfers).toHaveLength(1);
      expect(completeStep.transfers[0].transactionHash).toMatch(/^0x[0-9a-f]{64}$/);
    }
  });

  it.skipIf(isTestnet)(
    "emits a transfer event per recipient in a batch",
    { timeout: 300_000 },
    async () => {
      const tokenAddress = getTusdcAddress();
      const amount = parseUnits("5", 6);

      const recipients = [
        ACCOUNTS.recipient.address,
        ACCOUNTS.sender.address,
      ] as `0x${string}`[];

      const { steps } = await collectSteps({
        transfers: recipients.map((recipientAddress) => ({
          tokenAddress,
          recipientAddress,
          amount,
        })),
        walletClient: getWalletClient(),
        publicClient: getPublicClient(),
        network: getNetwork(),
        ...gasOverride,
        pollTimeout: 240_000,
      });

      const deployStep = steps.find((s) => s.step === "deploy");
      if (deployStep?.step === "deploy") {
        expect(deployStep.escrowType).toBe("batch");
        expect(deployStep.secrets.blindingScalar).toMatch(/^0x[0-9a-f]{64}$/);
      }

      const transferSteps = steps.filter((s) => s.step === "transfer");
      expect(transferSteps).toHaveLength(recipients.length);

      // Each recipient is reported as its own event, before the final rollup.
      for (const step of transferSteps) {
        if (step.step !== "transfer") continue;
        expect(step.total).toBe(recipients.length);
        expect(recipients).toContain(step.row.recipientAddress);
      }

      const stepNames = steps.map((s) => s.step);
      const completeIndex = stepNames.indexOf("complete");
      expect(stepNames.lastIndexOf("transfer")).toBeLessThan(completeIndex);

      const completeStep = steps[completeIndex];
      if (completeStep?.step === "complete") {
        expect(completeStep.transfers).toHaveLength(recipients.length);
      }
    },
  );

  // Tempo batch mode doesn't support native ETH escrow (native token is a stablecoin)
  it.skipIf(isTestnet && getNetwork().enableAtomicBatch)(
    "executes a native transfer end-to-end",
    { timeout: 300_000 },
    async () => {
      const publicClient = getPublicClient();
      const amount = parseUnits("0.01", 18);

      const balanceBefore = await getTokenBalance(
        NATIVE_TOKEN_ADDRESS,
        ACCOUNTS.recipient.address,
        publicClient,
      );

      const { steps } = await collectSteps({
        tokenAddress: NATIVE_TOKEN_ADDRESS,
        recipientAddress: ACCOUNTS.recipient.address,
        amount,
        walletClient: getWalletClient(),
        publicClient,
        network: getNetwork(),
        ...gasOverride,
        pollTimeout: 240_000,
      });

      const stepNames = steps.map((s) => s.step);
      expect(stepNames).toContain("fees");
      expect(stepNames).not.toContain("approve");
      expect(stepNames).toContain("deploy");
      expect(stepNames).toContain("signal");
      expect(stepNames).toContain("complete");

      const deployStep = steps.find((s) => s.step === "deploy");
      if (deployStep?.step === "deploy") {
        expect(deployStep.escrowType).toBe("batch");
      }

      const balanceAfter = await getTokenBalance(
        NATIVE_TOKEN_ADDRESS,
        ACCOUNTS.recipient.address,
        publicClient,
      );
      expect(balanceAfter).toBeGreaterThan(balanceBefore);
    },
  );

  it.skipIf(isTestnet)("abort signal cancels before deployment", { timeout: 30_000 }, async () => {
    const controller = new AbortController();
    controller.abort();

    const prepared = await prepareTransfer({
      tokenAddress: getTusdcAddress(),
      recipientAddress: ACCOUNTS.recipient.address,
      amount: parseUnits("1", 6),
      walletClient: getWalletClient(),
      publicClient: getPublicClient(),
      network: getNetwork(),
      abortSignal: controller.signal,
      ...gasOverride,
    });

    await expect(async () => {
      for await (const _step of prepared.execute()) {
        // Should not reach the deploy step
      }
    }).rejects.toThrow(TransferAbortedError);
  });
});
