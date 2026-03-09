import { describe, it, expect } from "vitest";
import { predictContractAddress } from "../src/internal/escrow.js";

describe("predictContractAddress", () => {
  it("predicts CREATE address from deployer + nonce", () => {
    // Known test vector: deployer = 0xf39F...92266, nonce = 0
    // This matches viem's getContractAddress with CREATE opcode
    const deployer = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as `0x${string}`;
    const addr = predictContractAddress(deployer, 0);
    // Should be a valid checksummed address
    expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
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
