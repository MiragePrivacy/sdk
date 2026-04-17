import { describe, it, expect, vi } from "vitest";
import { estimateFees } from "../src/internal/fees.js";
import { networks } from "../src/networks.js";
import { NATIVE_TOKEN_ADDRESS } from "../src/token.js";

const USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;

function mockPublicClient(maxFeePerGas = 30_000_000_000n) {
  return {
    getFeeHistory: vi.fn().mockResolvedValue({
      reward: [[1_000_000_000n, 1_500_000_000n, 2_000_000_000n]],
    }),
    getBlock: vi.fn().mockResolvedValue({ baseFeePerGas: maxFeePerGas / 2n }),
    getGasPrice: vi.fn().mockResolvedValue(maxFeePerGas),
  } as any;
}

describe("estimateFees", () => {
  describe("native ETH on ethereum", () => {
    it("uses deploy-only for user gas (no approve)", async () => {
      const gasPrice = 50_000_000_000n; // 50 gwei
      const fees = await estimateFees({
        amount: 1_000_000_000_000_000_000n, // 1 ETH
        tokenAddress: NATIVE_TOKEN_ADDRESS,
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
      });

      // networkFee = gasPrice * deploy (no approve for native)
      const expectedNetworkFee = gasPrice * networks.ethereum.gas.deploy;
      expect(fees.networkFee).toBe(expectedNetworkFee);
      expect(fees.isNativeEth).toBe(true);
    });

    it("uses bond+fund+collect for node gas (no approve)", async () => {
      const gasPrice = 50_000_000_000n;
      const gas = networks.ethereum.gas;
      const fees = await estimateFees({
        amount: 1_000_000_000_000_000_000n,
        tokenAddress: NATIVE_TOKEN_ADDRESS,
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
      });

      const expectedNodeGas = gasPrice * (gas.bond + gas.fund + gas.collect);
      const nodeFeeBase = 500_000_000_000_000n; // 0.0005 ETH
      expect(fees.nodeFee).toBe(nodeFeeBase + expectedNodeGas);
    });

    it("calculates correct totals", async () => {
      const fees = await estimateFees({
        amount: 1_000_000_000_000_000_000n,
        tokenAddress: NATIVE_TOKEN_ADDRESS,
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: 30_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n },
      });

      expect(fees.transferAmount).toBe(1_000_000_000_000_000_000n);
      expect(fees.totalFee).toBe(fees.networkFee + fees.nodeFee + fees.platformFee);
      expect(fees.totalAmount).toBe(fees.transferAmount + fees.totalFee);
      expect(fees.decimals).toBe(18);
    });
  });

  describe("ERC20 on ethereum", () => {
    it("calculates platform fee at 0.5%", async () => {
      const amount = 10_000_000n; // 10 USDC (6 decimals)
      const fees = await estimateFees({
        amount,
        tokenAddress: USDC_ADDRESS,
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: 30_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate: 4500,
      });

      // 0.5% of 10_000_000 = 50_000
      expect(fees.platformFee).toBe(50_000n);
    });

    it("user gas is approve+deploy, node gas is bond+fund+collect", async () => {
      const gasPrice = 30_000_000_000n;
      const gas = networks.ethereum.gas;
      const ethToTokenRate = 4500;

      const fees = await estimateFees({
        amount: 10_000_000n,
        tokenAddress: USDC_ADDRESS,
        tokenDecimals: 6,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        ethToTokenRate,
      });

      const userGasWei = gasPrice * (gas.approve + gas.deploy);
      const userGasEth = Number(userGasWei) / 1e18;
      const expectedNetworkFee = BigInt(Math.ceil(userGasEth * ethToTokenRate * 1e6));
      expect(fees.networkFee).toBe(expectedNetworkFee);

      const nodeGasWei = gasPrice * (gas.bond + gas.fund + gas.collect);
      const nodeGasEth = Number(nodeGasWei) / 1e18;
      const expectedNodeGasFee = BigInt(Math.ceil(nodeGasEth * ethToTokenRate * 1e6));
      const nodeFeeBase = 2_000000n; // $2 in 6-decimal token units
      expect(fees.nodeFee).toBe(nodeFeeBase + expectedNodeGasFee);
      expect(fees.isNativeEth).toBe(false);
    });
  });

  describe("tempo", () => {
    it("uses fixed 10 gwei gas price", async () => {
      const client = mockPublicClient();
      const fees = await estimateFees({
        amount: 10_000_000n, // 10 USDC
        tokenAddress: USDC_ADDRESS,
        tokenDecimals: 6,
        network: networks.tempo,
        publicClient: client,
        ethToTokenRate: 1, // doesn't matter for tempo
      });

      // Should not call any RPC for gas price
      expect(client.getFeeHistory).not.toHaveBeenCalled();
      expect(client.getBlock).not.toHaveBeenCalled();
      expect(client.getGasPrice).not.toHaveBeenCalled();

      expect(fees.networkFee).toBeGreaterThan(0n);
      expect(fees.nodeFee).toBeGreaterThan(0n);
    });

    it("uses deploy-only for user gas (approve is batched)", async () => {
      const gas = networks.tempo.gas;
      const tempoGasPrice = 10n * 1_000_000_000n; // 10 gwei in wei

      const fees = await estimateFees({
        amount: 10_000_000n,
        tokenAddress: USDC_ADDRESS,
        tokenDecimals: 6,
        network: networks.tempo,
        publicClient: mockPublicClient(),
      });

      // User gas: deploy only (18-decimal wei → 6-decimal token)
      const userGasWei = tempoGasPrice * gas.deploy;
      const expectedNetworkFee = userGasWei / (10n ** 12n);
      expect(fees.networkFee).toBe(expectedNetworkFee);
    });

    it("uses bond+fund+collect for node gas", async () => {
      const gas = networks.tempo.gas;
      const tempoGasPrice = 10n * 1_000_000_000n;

      const fees = await estimateFees({
        amount: 10_000_000n,
        tokenAddress: USDC_ADDRESS,
        tokenDecimals: 6,
        network: networks.tempo,
        publicClient: mockPublicClient(),
      });

      const nodeGasWei = tempoGasPrice * (gas.bond + gas.fund + gas.collect);
      const expectedNodeGasFee = nodeGasWei / (10n ** 12n);
      const nodeFeeBase = (networks.tempo.nodeFeeUsd * 10n ** 6n) / 10n ** 6n; // 200000n
      expect(fees.nodeFee).toBe(nodeFeeBase + expectedNodeGasFee);
    });
  });

  describe("gas price resolution", () => {
    it("uses gasPrice override when provided", async () => {
      const client = mockPublicClient();
      await estimateFees({
        amount: 1_000_000_000_000_000_000n,
        tokenAddress: NATIVE_TOKEN_ADDRESS,
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
        amount: 1_000_000_000_000_000_000n,
        tokenAddress: NATIVE_TOKEN_ADDRESS,
        tokenDecimals: 18,
        network: networks.ethereum,
        publicClient: mockPublicClient(),
        gasPrice: { maxFeePerGas: gasPrice, maxPriorityFeePerGas: 2_000_000_000n },
        gasOverrides: { deploy: customDeploy },
      });

      // Network fee for native: gasPrice * deploy (overridden)
      const expectedNetworkFee = gasPrice * customDeploy;
      expect(fees.networkFee).toBe(expectedNetworkFee);
    });
  });
});
