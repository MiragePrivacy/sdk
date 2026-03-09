import { describe, it, expect } from "vitest";
import { checkAbort } from "../src/internal/abort.js";
import { TransferAbortedError } from "../src/errors.js";

describe("checkAbort", () => {
  it("does nothing when signal is undefined", () => {
    expect(() => checkAbort(undefined)).not.toThrow();
  });

  it("does nothing when signal is not aborted", () => {
    const controller = new AbortController();
    expect(() => checkAbort(controller.signal)).not.toThrow();
  });

  it("throws TransferAbortedError when signal is aborted", () => {
    const controller = new AbortController();
    controller.abort();
    expect(() => checkAbort(controller.signal)).toThrow(TransferAbortedError);
  });

  it("includes escrowAddress in error when provided", () => {
    const controller = new AbortController();
    controller.abort();
    try {
      checkAbort(controller.signal, {
        escrowAddress: "0x1111111111111111111111111111111111111111" as `0x${string}`,
      });
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(TransferAbortedError);
      expect((e as TransferAbortedError).escrowAddress).toBe(
        "0x1111111111111111111111111111111111111111",
      );
    }
  });

  it("throws TransferAbortedError with no context when aborted pre-deploy", () => {
    const controller = new AbortController();
    controller.abort();
    try {
      checkAbort(controller.signal);
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(TransferAbortedError);
      expect((e as TransferAbortedError).escrowAddress).toBeUndefined();
    }
  });
});
