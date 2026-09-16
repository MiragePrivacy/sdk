import { afterEach, expect, it, vi } from "vitest";

// Match the default-only CommonJS namespace emitted by Vite in the browser.
vi.mock("eciesjs", async () => ({ encrypt: undefined, default: await vi.importActual("eciesjs") }));

import { submitSignal } from "../src/internal/nomad.js";

afterEach(() => vi.unstubAllGlobals());

it("encrypts a decryptable signal with default-only eciesjs exports", async () => {
  const { PrivateKey, decrypt } = await vi.importActual<typeof import("eciesjs")>("eciesjs");
  const key = new PrivateKey();
  const fetch = vi.fn().mockResolvedValue({ ok: true, text: async () => "accepted" });
  vi.stubGlobal("fetch", fetch);
  const scalar = `0x${"ab".repeat(32)}` as const;
  await expect(submitSignal({
    escrowType: "erc20",
    escrowAddress: "0x00000000000000000000000000000000000000ff",
    blindingScalar: scalar,
    sealedPricingAuthorization: "0x1234",
    executionApproval: {
      version: 1, chainId: 11155111,
      escrowContract: "0x00000000000000000000000000000000000000ff",
      deploymentTxHash: `0x${"11".repeat(32)}`,
      runtimeCodeHash: `0x${"22".repeat(32)}`,
      quoteCommitment: `0x${"33".repeat(32)}`,
      approvedAt: 1700000000,
      signature: `0x${"44".repeat(64)}`,
    },
    apiServer: "https://api.test", chainId: 11155111,
    networkKey: { publicKey: `0x${key.publicKey.toHex()}`, attested: false, debug: true, chainId: 11155111 },
  })).resolves.toBe("accepted");
  const [url, init] = fetch.mock.calls[0];
  expect(url).toBe("https://api.test/nomad/11155111/signal");
  const ciphertext = Buffer.from(JSON.parse(init.body).slice(2), "hex");
  const payload = JSON.parse(new TextDecoder().decode(decrypt(key.secret, ciphertext)));
  expect(payload.blindingScalar).toBe(scalar);
  expect(payload.sealedPricingAuthorization).toBe("0x1234");
});
