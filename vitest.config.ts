import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    // Integration tests share an anvil process — run them sequentially.
    fileParallelism: false,
  },
});
