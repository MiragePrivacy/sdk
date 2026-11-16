import { describe, it, expect } from "vitest";
import {
  MirageError,
  ApiError,
  ContractError,
  TransferAbortedError,
  TransferTimeoutError,
} from "../src/errors.js";

describe("MirageError", () => {
  it("sets code and message", () => {
    const err = new MirageError("TEST_CODE", "test message");
    expect(err.code).toBe("TEST_CODE");
    expect(err.message).toBe("test message");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("MirageError");
  });

  it("preserves cause via Error.cause", () => {
    const cause = new Error("root");
    const err = new MirageError("X", "msg", { cause });
    expect(err.cause).toBe(cause);
  });

  it("sets meta", () => {
    const err = new MirageError("X", "msg", { meta: { key: "value" } });
    expect(err.meta).toEqual({ key: "value" });
  });
});

describe("ApiError", () => {
  it("extends MirageError with statusCode", () => {
    const err = new ApiError(404, "not found", { detail: "x" });
    expect(err).toBeInstanceOf(MirageError);
    expect(err).toBeInstanceOf(Error);
    expect(err.statusCode).toBe(404);
    expect(err.body).toEqual({ detail: "x" });
    expect(err.code).toBe("API_ERROR");
    expect(err.name).toBe("ApiError");
  });
});

describe("ContractError", () => {
  it("includes txHash", () => {
    const err = new ContractError("deploy failed", { txHash: "0xabc" as `0x${string}` });
    expect(err.txHash).toBe("0xabc");
    expect(err.code).toBe("CONTRACT_ERROR");
    expect(err.name).toBe("ContractError");
  });

  it("includes cause", () => {
    const cause = new Error("revert");
    const err = new ContractError("failed", { cause });
    expect(err.cause).toBe(cause);
  });
});

describe("TransferAbortedError", () => {
  it("has TRANSFER_ABORTED code with no options", () => {
    const err = new TransferAbortedError();
    expect(err.code).toBe("TRANSFER_ABORTED");
    expect(err.escrowAddress).toBeUndefined();
    expect(err.withdrawHash).toBeUndefined();
    expect(err.withdrawError).toBeUndefined();
  });

  it("carries escrow and withdraw info", () => {
    const err = new TransferAbortedError({
      escrowAddress: "0x1111111111111111111111111111111111111111" as `0x${string}`,
      withdrawHash: "0xabc" as `0x${string}`,
    });
    expect(err.escrowAddress).toBe("0x1111111111111111111111111111111111111111");
    expect(err.withdrawHash).toBe("0xabc");
    expect(err.withdrawError).toBeUndefined();
  });

  it("carries withdrawError when withdrawal failed", () => {
    const withdrawErr = new Error("gas");
    const err = new TransferAbortedError({
      escrowAddress: "0x1111111111111111111111111111111111111111" as `0x${string}`,
      withdrawError: withdrawErr,
    });
    expect(err.withdrawError).toBe(withdrawErr);
    expect(err.withdrawHash).toBeUndefined();
  });
});

describe("TransferTimeoutError", () => {
  it("includes timeout in message", () => {
    const err = new TransferTimeoutError(60000);
    expect(err.code).toBe("TRANSFER_TIMEOUT");
    expect(err.message).toContain("60000");
    expect(err.name).toBe("TransferTimeoutError");
  });
});
