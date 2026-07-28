import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { prepareTransfer } from "../../src/transfer.js";
import { NATIVE_TOKEN_ADDRESS } from "../../src/token.js";
import {
  ACCOUNTS,
  getPublicClient,
  getWalletClient,
  getNetwork,
  startAnvil,
  stopAnvil,
  startMockApi,
  stopMockApi,
  getTusdcAddress,
  isTestnet,
  TOKEN_ADDRESS,
} from "./setup.js";
import { parseUnits } from "viem";

describe("Fee estimation", () => {
  beforeAll(async () => {
    await startAnvil();
    // Fee estimation reads limits and gas analysis from the API server.
    await startMockApi();
  }, 120_000);

  afterAll(async () => {
    await stopMockApi();
    stopAnvil();
  });

  it("estimates fees for native transfer", async () => {
    const publicClient = getPublicClient();
    const walletClient = getWalletClient();
    const network = getNetwork();

    const { fees } = await prepareTransfer({
      tokenAddress: NATIVE_TOKEN_ADDRESS,
      recipientAddress: ACCOUNTS.recipient.address,
      amount: parseUnits("0.01", 18),
      walletClient,
      publicClient,
      network,
      ...(!isTestnet && {
        gasPrice: {
          maxFeePerGas: 20_000_000_000n,
          maxPriorityFeePerGas: 1_000_000_000n,
        },
      }),
    });

    expect(fees.isNativeEth).toBe(true);
    expect(fees.transferAmount).toBe(parseUnits("0.01", 18));
    expect(fees.networkFee).toBeGreaterThan(0n);
    expect(fees.nodeFee).toBeGreaterThan(0n);
    expect(fees.platformFee).toBeGreaterThanOrEqual(0n);
    expect(fees.totalFee).toBe(fees.networkFee + fees.nodeFee + fees.platformFee);
    // Native escrows front the bond pot on top of the transfer and fees.
    expect(fees.bondPot).toBeGreaterThan(0n);
    expect(fees.totalAmount).toBe(fees.transferAmount + fees.totalFee + fees.bondPot);
    expect(fees.decimals).toBe(18);
  });

  it("estimates fees for ERC20 transfer", async () => {
    const tokenAddress = isTestnet ? TOKEN_ADDRESS : getTusdcAddress();
    if (!tokenAddress || tokenAddress === NATIVE_TOKEN_ADDRESS) {
      console.log("Skipping ERC20 fee test — no TOKEN_ADDRESS set or is native");
      return;
    }

    const publicClient = getPublicClient();
    const walletClient = getWalletClient();
    const network = getNetwork();

    const { fees } = await prepareTransfer({
      tokenAddress,
      recipientAddress: ACCOUNTS.recipient.address,
      amount: parseUnits("10", 6),
      walletClient,
      publicClient,
      network,
      ...(!isTestnet && {
        gasPrice: {
          maxFeePerGas: 20_000_000_000n,
          maxPriorityFeePerGas: 1_000_000_000n,
        },
      }),
    });

    expect(fees.isNativeEth).toBe(false);
    expect(fees.transferAmount).toBe(parseUnits("10", 6));
    expect(fees.networkFee).toBeGreaterThan(0n);
    expect(fees.nodeFee).toBeGreaterThan(0n);
    expect(fees.platformFee).toBeGreaterThanOrEqual(0n);
    expect(fees.decimals).toBe(6);
  });
});
