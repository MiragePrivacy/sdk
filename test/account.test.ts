import { describe, it, expect } from "vitest";
import { getAccount, assertAccountUnchanged } from "../src/internal/account.js";
import { MirageError } from "../src/errors.js";

function mockWalletClient(address?: string) {
  return {
    account: address ? { address } : undefined,
  } as any;
}

describe("getAccount", () => {
  it("returns account address", () => {
    const client = mockWalletClient("0xabc");
    expect(getAccount(client)).toBe("0xabc");
  });

  it("throws NO_ACCOUNT when no account", () => {
    const client = mockWalletClient();
    expect(() => getAccount(client)).toThrow(MirageError);
    try {
      getAccount(client);
    } catch (e) {
      expect((e as MirageError).code).toBe("NO_ACCOUNT");
    }
  });
});

describe("assertAccountUnchanged", () => {
  it("does nothing when account matches", () => {
    const addr = "0x1111111111111111111111111111111111111111";
    const client = mockWalletClient(addr);
    expect(() => assertAccountUnchanged(client, addr as `0x${string}`)).not.toThrow();
  });

  it("is case-insensitive", () => {
    const client = mockWalletClient("0xAbCdEf1111111111111111111111111111111111");
    expect(() =>
      assertAccountUnchanged(client, "0xabcdef1111111111111111111111111111111111" as `0x${string}`),
    ).not.toThrow();
  });

  it("throws ACCOUNT_CHANGED when account differs", () => {
    const client = mockWalletClient("0x2222222222222222222222222222222222222222");
    const expected = "0x1111111111111111111111111111111111111111" as `0x${string}`;
    try {
      assertAccountUnchanged(client, expected);
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(MirageError);
      expect((e as MirageError).code).toBe("ACCOUNT_CHANGED");
      expect((e as MirageError).meta?.expectedAccount).toBe(expected);
      expect((e as MirageError).meta?.actualAccount).toBe(
        "0x2222222222222222222222222222222222222222",
      );
    }
  });

  it("includes escrowAddress in meta when provided", () => {
    const client = mockWalletClient("0x2222222222222222222222222222222222222222");
    const escrow = "0xeeee222222222222222222222222222222222222" as `0x${string}`;
    try {
      assertAccountUnchanged(
        client,
        "0x1111111111111111111111111111111111111111" as `0x${string}`,
        escrow,
      );
      expect.fail("should have thrown");
    } catch (e) {
      expect((e as MirageError).meta?.escrowAddress).toBe(escrow);
    }
  });
});
