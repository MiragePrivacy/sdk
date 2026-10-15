import { afterEach, expect, it, vi } from "vitest";
import { submitSignal } from "../src/internal/nomad.js";

vi.mock("eciesjs", async (importOriginal) => ({
  encrypt: undefined,
  default: await importOriginal<typeof import("eciesjs")>(),
}));

afterEach(() => vi.unstubAllGlobals());

it("encrypts a decryptable signal with a default-only CommonJS namespace", async () => {
  const { PrivateKey, decrypt } = await vi.importActual<typeof import("eciesjs")>("eciesjs");
  const key = new PrivateKey();
  const fetch = vi.fn().mockResolvedValue({ ok: true, text: async () => "accepted" });
  vi.stubGlobal("fetch", fetch);
  const escrowAddress = "0x00000000000000000000000000000000000000ff" as const;
  const executionApproval = {
    version: 1,
    chainId: 11155111,
    escrowContract: escrowAddress,
    deploymentTxHash: `0x${"11".repeat(32)}` as `0x${string}`,
    runtimeCodeHash: `0x${"22".repeat(32)}` as `0x${string}`,
    quoteCommitment: `0x${"33".repeat(32)}` as `0x${string}`,
    approvedAt: 1700000000,
    signature: `0x${"44".repeat(64)}` as `0x${string}`,
  };
  const blindingScalar = `0x${"55".repeat(32)}` as `0x${string}`;
  const sealedPricingAuthorization = `0x${"66".repeat(32)}` as `0x${string}`;
  await expect(submitSignal({
    escrowType: "native",
    escrowAddress,
    blindingScalar,
    sealedPricingAuthorization,
    executionApproval,
    apiServer: "https://api.test",
    chainId: 11155111,
    networkKey: { publicKey: key.publicKey.toHex(), attested: true, debug: true, chainId: 11155111 },
  })).resolves.toBe("accepted");
  const [url, init] = fetch.mock.calls[0];
  expect(url).toBe("https://api.test/nomad/11155111/signal");
  const ciphertext = JSON.parse(init.body) as string;
  const plaintext = decrypt(key.toHex(), Buffer.from(ciphertext.slice(2), "hex"));
  expect(JSON.parse(plaintext.toString())).toEqual({
    escrowType: "native", escrowContract: escrowAddress,
    blindingScalar, sealedPricingAuthorization, executionApproval,
  });
});
