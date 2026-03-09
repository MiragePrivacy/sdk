import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  getTokenMetadata,
  getTokenBalance,
  NATIVE_TOKEN_ADDRESS,
  isNativeToken,
} from "../../src/token.js";
import {
  ACCOUNTS,
  getPublicClient,
  startAnvil,
  stopAnvil,
  getTusdcAddress,
  isTestnet,
  TOKEN_ADDRESS,
} from "./setup.js";

describe("Token utilities", () => {
  beforeAll(async () => {
    await startAnvil();
  }, 120_000);

  afterAll(() => { stopAnvil(); });

  it("reads ERC20 metadata", async () => {
    const tokenAddress = isTestnet ? TOKEN_ADDRESS : getTusdcAddress();
    if (!tokenAddress || tokenAddress === NATIVE_TOKEN_ADDRESS) {
      console.log("Skipping ERC20 metadata test — no TOKEN_ADDRESS set or is native");
      return;
    }

    const client = getPublicClient();
    const meta = await getTokenMetadata(tokenAddress, client);
    expect(meta.symbol).toBeTruthy();
    expect(meta.decimals).toBeGreaterThan(0);
    expect(meta.name).toBeTruthy();

    if (!isTestnet) {
      expect(meta.symbol).toBe("TUSDC");
      expect(meta.decimals).toBe(6);
      expect(meta.name).toBe("Test USD Coin");
    }
  });

  it("reads ERC20 balance for sender", async () => {
    const tokenAddress = isTestnet ? TOKEN_ADDRESS : getTusdcAddress();
    if (!tokenAddress || tokenAddress === NATIVE_TOKEN_ADDRESS) {
      console.log("Skipping ERC20 balance test — no TOKEN_ADDRESS set or is native");
      return;
    }

    const client = getPublicClient();
    const balance = await getTokenBalance(
      tokenAddress,
      ACCOUNTS.sender.address,
      client,
    );
    expect(balance).toBeGreaterThan(0n);
  });

  it("reads native balance", async () => {
    const client = getPublicClient();
    const balance = await getTokenBalance(
      NATIVE_TOKEN_ADDRESS,
      ACCOUNTS.sender.address,
      client,
    );
    expect(balance).toBeGreaterThan(0n);
  });

  it("native token detection works", () => {
    expect(isNativeToken(NATIVE_TOKEN_ADDRESS)).toBe(true);
    const tokenAddress = isTestnet ? TOKEN_ADDRESS : getTusdcAddress();
    if (tokenAddress && tokenAddress !== NATIVE_TOKEN_ADDRESS) {
      expect(isNativeToken(tokenAddress)).toBe(false);
    }
  });
});
