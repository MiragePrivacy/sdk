import { describe, it, expect, vi } from "vitest";
import { estimateFees } from "../src/internal/fees.js";
import { networks } from "../src/networks.js";
import { NATIVE_TOKEN_ADDRESS } from "../src/token.js";
import type { TransferRow } from "../src/types.js";

const USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;
const USDT_ADDRESS = "0xdAC17F958D2ee523a2206206994597C13D831ec7" as const;
const RECIPIENT = "0x0000000000000000000000000000000000000001" as const;

function mockPublicClient(maxFeePerGas = 30_000_000_000n) {
  return {
    getFeeHistory: vi.fn().mockResolvedValue({
      reward: [[1_000_000_000n, 1_500_000_000n, 2_000_000_000n]],
    }),
    getBlock: vi.fn().mockResolvedValue({ baseFeePerGas: maxFeePerGas / 2n }),
    getGasPrice: vi.fn().mockResolvedValue(maxFeePerGas),
  } as any;
}

function row(tokenAddress: string, amount: bigint, recipient: string = RECIPIENT): TransferRow {
  return {
    tokenAddress: tokenAddress as `0x${string}`,
    recipientAddress: recipient as `0x${string}`,
    amount,
  };
}

describe("estimateFees", () => {
  describe("native ETH on ethereum", () => {
    const gasPrice = 50_000_000_000n;
    const nativeGas = networks.ethereum.nativeGas;

    it("uses deploy-only for user gas (no approve)", async () => {
      const fees = await estimateFees({
        transfers: [row(NATIVE_TOKEN_ADDRESS, 1_000_000_000_000_000_000n)],
        escrowType: "native",
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
      });

      expect(fees.networkFee).toBe(gasPrice * nativeGas.deploy);
      expect(fees.isNativeEth).toBe(true);
    });

    it("bills only fund gas to the node, since the bond pot covers bond and collect", async () => {
      const fees = await estimateFees({
        transfers: [row(NATIVE_TOKEN_ADDRESS, 1_000_000_000_000_000_000n)],
        escrowType: "native",
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
      });

      const nodeFeeBase = networks.ethereum.nodeFeeWei;
      expect(fees.nodeFee).toBe(nodeFeeBase + gasPrice * nativeGas.fund);
    });

    it("sizes the bond pot from bond + collect with margin", async () => {
      const fees = await estimateFees({
        transfers: [row(NATIVE_TOKEN_ADDRESS, 1_000_000_000_000_000_000n)],
        escrowType: "native",
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
      });

      const units = ((nativeGas.bond + nativeGas.collect) * 150n + 99n) / 100n;
      expect(fees.bondPot).toBe(units * gasPrice);
    });

    it("excludes the bond pot from totalFee but includes it in totalAmount", async () => {
      const fees = await estimateFees({
        transfers: [row(NATIVE_TOKEN_ADDRESS, 1_000_000_000_000_000_000n)],
        escrowType: "native",
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: 30_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n },
      });

      expect(fees.transferAmount).toBe(1_000_000_000_000_000_000n);
      expect(fees.totalFee).toBe(fees.networkFee + fees.nodeFee + fees.platformFee);
      expect(fees.bondPot).toBeGreaterThan(0n);
      expect(fees.totalAmount).toBe(fees.transferAmount + fees.totalFee + fees.bondPot);
      expect(fees.decimals).toBe(18);
    });

    it("keeps reward = totalFee - networkFee", async () => {
      const fees = await estimateFees({
        transfers: [row(NATIVE_TOKEN_ADDRESS, 1_000_000_000_000_000_000n)],
        escrowType: "native",
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: 30_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n },
      });

      expect(fees.rewardAmount).toBe(fees.totalFee - fees.networkFee);
      expect(fees.rewardAmount).toBe(fees.nodeFee + fees.platformFee);
    });
  });

  describe("ERC20 on ethereum", () => {
    const gasPrice = 30_000_000_000n;
    const gas = networks.ethereum.gas;
    const ethToTokenRate = 4500;

    it("calculates platform fee at 0.5%", async () => {
      const fees = await estimateFees({
        transfers: [row(USDC_ADDRESS, 10_000_000n)],
        escrowType: "erc20",
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate,
      });

      expect(fees.platformFee).toBe(50_000n);
    });

    it("user gas is approve+deploy, node gas is fund only", async () => {
      const fees = await estimateFees({
        transfers: [row(USDC_ADDRESS, 10_000_000n)],
        escrowType: "erc20",
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate,
      });

      const toToken = (wei: bigint) =>
        BigInt(Math.ceil((Number(wei) / 1e18) * ethToTokenRate * 1e6));

      expect(fees.networkFee).toBe(toToken(gasPrice * (gas.approve + gas.deploy)));
      expect(fees.nodeFee).toBe(2_000000n + toToken(gasPrice * gas.fund));
      expect(fees.isNativeEth).toBe(false);
    });

    it("denominates the bond pot in wei, not token units", async () => {
      const fees = await estimateFees({
        transfers: [row(USDC_ADDRESS, 10_000_000n)],
        escrowType: "erc20",
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate,
      });

      const units = ((gas.bond + gas.collect) * 150n + 99n) / 100n;
      expect(fees.bondPot).toBe(units * gasPrice);
      // The pot is ETH while the transfer is a token, so folding it into a
      // token total would be meaningless; callers reserve it separately.
      expect(fees.totalAmount).toBe(fees.transferAmount + fees.totalFee);
    });

    it("scales approve gas with the number of distinct ERC20s", async () => {
      const single = await estimateFees({
        transfers: [row(USDC_ADDRESS, 10_000_000n)],
        escrowType: "batch",
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate,
      });

      const mixed = await estimateFees({
        transfers: [row(USDC_ADDRESS, 10_000_000n), row(USDT_ADDRESS, 10_000_000n)],
        escrowType: "batch",
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate,
      });

      expect(mixed.networkFee).toBeGreaterThan(single.networkFee);
    });

    it("aggregates the reward asset case-insensitively", async () => {
      const fees = await estimateFees({
        transfers: [
          row(USDC_ADDRESS, 10_000_000n, "0x0000000000000000000000000000000000000001"),
          // Same token, different casing: must not be treated as another asset,
          // or the amount pulled would fall short of the approved allowance.
          row(USDC_ADDRESS.toLowerCase(), 20_000_000n, "0x0000000000000000000000000000000000000002"),
        ],
        escrowType: "batch",
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate,
      });

      expect(fees.transferAmount).toBe(30_000_000n);
      expect(fees.escrowAmount).toBe(30_000_000n + fees.rewardAmount);
    });

    it("charges no approve gas to an all-native batch", async () => {
      const fees = await estimateFees({
        transfers: [
          row(NATIVE_TOKEN_ADDRESS, 1_000n, "0x0000000000000000000000000000000000000001"),
          row(NATIVE_TOKEN_ADDRESS, 2_000n, "0x0000000000000000000000000000000000000002"),
        ],
        escrowType: "batch",
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
      });

      // Native rows need no allowances, so only deploy gas applies.
      expect(fees.networkFee).toBe(gasPrice * networks.ethereum.nativeGas.deploy);
    });

    it("charges the escrow the payment plus reward, excluding the network fee", async () => {
      const fees = await estimateFees({
        transfers: [row(USDC_ADDRESS, 10_000_000n)],
        escrowType: "erc20",
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate,
      });

      expect(fees.escrowAmount).toBe(fees.transferAmount + fees.rewardAmount);
      expect(fees.escrowAmount).toBe(fees.totalAmount - fees.networkFee);
    });
  });

  describe("batch", () => {
    it("bills bond + fund + collect to the node and takes no bond pot", async () => {
      const gasPrice = 30_000_000_000n;
      const gas = networks.ethereum.gas;

      const fees = await estimateFees({
        transfers: [
          row(USDC_ADDRESS, 10_000_000n, "0x0000000000000000000000000000000000000001"),
          row(USDC_ADDRESS, 20_000_000n, "0x0000000000000000000000000000000000000002"),
        ],
        escrowType: "batch",
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate: 4500,
      });

      const toToken = (wei: bigint) => BigInt(Math.ceil((Number(wei) / 1e18) * 4500 * 1e6));

      expect(fees.bondPot).toBe(0n);
      expect(fees.nodeFee).toBe(
        2_000000n + toToken(gasPrice * (gas.bond + gas.fund + gas.collect)),
      );
      // transferAmount aggregates the rows sharing the reward asset.
      expect(fees.transferAmount).toBe(30_000_000n);
    });

    it("charges the platform fee on the whole batch when a base is supplied", async () => {
      const fees = await estimateFees({
        transfers: [
          row(USDC_ADDRESS, 10_000_000n, "0x0000000000000000000000000000000000000001"),
          row(NATIVE_TOKEN_ADDRESS, 1_000_000_000_000_000_000n, "0x0000000000000000000000000000000000000002"),
        ],
        escrowType: "batch",
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: 30_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate: 4500,
        // $10 USDC + $4500 ETH
        platformFeeBase: 4_510_000_000n,
      });

      expect(fees.platformFee).toBe((4_510_000_000n * 50n) / 10_000n);
    });
  });

  describe("tempo", () => {
    it("uses fixed 10 gwei gas price", async () => {
      const client = mockPublicClient();
      const fees = await estimateFees({
        transfers: [row(USDC_ADDRESS, 10_000_000n)],
        escrowType: "erc20",
        tokenDecimals: 6,
        network: networks.tempo,
        publicClient: client,
        ethToTokenRate: 1,
      });

      expect(client.getFeeHistory).not.toHaveBeenCalled();
      expect(client.getBlock).not.toHaveBeenCalled();
      expect(client.getGasPrice).not.toHaveBeenCalled();

      expect(fees.networkFee).toBeGreaterThan(0n);
      expect(fees.nodeFee).toBeGreaterThan(0n);
    });

    it("uses deploy-only for user gas (approve is batched)", async () => {
      const gas = networks.tempo.gas;
      const tempoGasPrice = 10n * 1_000_000_000n;

      const fees = await estimateFees({
        transfers: [row(USDC_ADDRESS, 10_000_000n)],
        escrowType: "erc20",
        tokenDecimals: 6,
        network: networks.tempo,
        publicClient: mockPublicClient(),
      });

      expect(fees.networkFee).toBe((tempoGasPrice * gas.deploy) / 10n ** 12n);
    });

    it("bills only fund gas to the node for single escrows", async () => {
      const gas = networks.tempo.gas;
      const tempoGasPrice = 10n * 1_000_000_000n;

      const fees = await estimateFees({
        transfers: [row(USDC_ADDRESS, 10_000_000n)],
        escrowType: "erc20",
        tokenDecimals: 6,
        network: networks.tempo,
        publicClient: mockPublicClient(),
      });

      expect(fees.nodeFee).toBe(200000n + (tempoGasPrice * gas.fund) / 10n ** 12n);
    });

    it("funds a bond pot so bond and collect gas is not left unpaid", async () => {
      const gas = networks.tempo.gas;
      const tempoGasPrice = 10n * 1_000_000_000n;

      const fees = await estimateFees({
        transfers: [row(USDC_ADDRESS, 10_000_000n)],
        escrowType: "erc20",
        tokenDecimals: 6,
        network: networks.tempo,
        publicClient: mockPublicClient(),
      });

      // Node gas excludes bond + collect, so a pot must cover them.
      const units = ((gas.bond + gas.collect) * 150n + 99n) / 100n;
      expect(fees.bondPot).toBe((units * tempoGasPrice) / 10n ** 12n);
      // Tempo's gas token is the stablecoin, so the pot shares the transfer unit.
      expect(fees.totalAmount).toBe(fees.transferAmount + fees.totalFee + fees.bondPot);
    });

    it("takes no bond pot for batch escrows", async () => {
      const fees = await estimateFees({
        transfers: [
          row(USDC_ADDRESS, 10_000_000n, "0x0000000000000000000000000000000000000001"),
          row(USDC_ADDRESS, 20_000_000n, "0x0000000000000000000000000000000000000002"),
        ],
        escrowType: "batch",
        tokenDecimals: 6,
        network: networks.tempo,
        publicClient: mockPublicClient(),
      });

      expect(fees.bondPot).toBe(0n);
    });
  });

  describe("gas price resolution", () => {
    it("uses gasPrice override when provided", async () => {
      const client = mockPublicClient();
      await estimateFees({
        transfers: [row(NATIVE_TOKEN_ADDRESS, 1_000_000_000_000_000_000n)],
        escrowType: "native",
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: client,
        gasPrice: { maxFeePerGas: 50_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n },
      });

      expect(client.getFeeHistory).not.toHaveBeenCalled();
      expect(client.getBlock).not.toHaveBeenCalled();
      expect(client.getGasPrice).not.toHaveBeenCalled();
    });

    it("accepts gas overrides from API estimation", async () => {
      const gasPrice = 30_000_000_000n;
      const customDeploy = 500_000n;
      const fees = await estimateFees({
        transfers: [row(NATIVE_TOKEN_ADDRESS, 1_000_000_000_000_000_000n)],
        escrowType: "native",
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        gasOverrides: { deploy: customDeploy },
      });

      expect(fees.networkFee).toBe(gasPrice * customDeploy);
    });
  });
});
