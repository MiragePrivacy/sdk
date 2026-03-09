import { describe, it, expect } from "vitest";
import { isNativeToken, NATIVE_TOKEN_ADDRESS } from "../src/token.js";

describe("isNativeToken", () => {
  it("returns true for zero address", () => {
    expect(isNativeToken("0x0000000000000000000000000000000000000000")).toBe(true);
  });

  it("returns true for NATIVE_TOKEN_ADDRESS", () => {
    expect(isNativeToken(NATIVE_TOKEN_ADDRESS)).toBe(true);
  });

  it("returns false for non-zero address", () => {
    expect(isNativeToken("0x1234567890abcdef1234567890abcdef12345678")).toBe(false);
  });
});
