import type { Address, PublicClient } from "viem";
import { formatUnits } from "viem";
import type { FeeEstimate, GasConstants, GasPrice, NetworkConfig } from "../types.js";
import { MirageError } from "../errors.js";
import { isNativeToken } from "../token.js";

const UNISWAP_ROUTER_ABI = [
  {
    type: "function",
    name: "getAmountsOut",
    stateMutability: "view",
    inputs: [
      { name: "amountIn", type: "uint256" },
      { name: "path", type: "address[]" },
    ],
    outputs: [{ name: "amounts", type: "uint256[]" }],
  },
  {
    type: "function",
    name: "WETH",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
] as const;

async function resolveGasPrice(
  publicClient: PublicClient,
  gasPrice?: GasPrice,
): Promise<bigint> {
  if (gasPrice) return gasPrice.maxFeePerGas;

  try {
    const [feeHistory, latestBlock] = await Promise.all([
      publicClient.getFeeHistory({
        blockCount: 4,
        blockTag: "latest",
        rewardPercentiles: [25, 50, 75],
      }),
      publicClient.getBlock({ blockTag: "latest" }),
    ]);

    const baseFeePerGas = latestBlock.baseFeePerGas ?? 0n;
    const recentRewards = feeHistory.reward ?? [];
    const medianPriorityFees = recentRewards
      .map((r) => r[1])
      .filter((fee): fee is bigint => fee !== undefined && fee !== null);

    const maxPriorityFeePerGas =
      medianPriorityFees.length > 0
        ? medianPriorityFees.reduce((sum, fee) => sum + fee, 0n) / BigInt(medianPriorityFees.length)
        : 1_500_000_000n;

    return baseFeePerGas * 2n + maxPriorityFeePerGas;
  } catch {
    return publicClient.getGasPrice();
  }
}

// Fetch ETH -> token exchange rate from Uniswap V2 router.
// Returns how many token units (raw) you get for 1 ETH.
async function getEthToTokenRate(
  tokenAddress: Address,
  routerAddress: Address,
  publicClient: PublicClient,
  tokenDecimals: number,
): Promise<number> {
  const wethAddress = await publicClient.readContract({
    address: routerAddress,
    abi: UNISWAP_ROUTER_ABI,
    functionName: "WETH",
  }) as Address;

  const amountIn = 10n ** 18n; // 1 ETH
  const path = [wethAddress, tokenAddress];

  const amounts = await publicClient.readContract({
    address: routerAddress,
    abi: UNISWAP_ROUTER_ABI,
    functionName: "getAmountsOut",
    args: [amountIn, path],
  }) as bigint[];

  return parseFloat(formatUnits(amounts[1], tokenDecimals));
}

/**
 * Resolve the ETH→USD price for limit checks and fee conversion.
 * For EVM networks, uses Uniswap V2 router. Throws if no router is configured.
 * Since supported tokens are USD stablecoins, ETH→token ≈ ETH→USD.
 */
export async function resolveEthPrice(
  network: NetworkConfig,
  publicClient: PublicClient,
  tokenAddress: Address,
  tokenDecimals: number,
  ethToTokenRate?: number,
): Promise<number> {
  if (ethToTokenRate !== undefined) return ethToTokenRate;

  if (network.kind === "tempo") return 1;

  const routerAddress = network.priceUniswapRouter ?? network.uniswapRouter;
  if (!routerAddress) {
    throw new MirageError(
      "MISSING_PRICE_ORACLE",
      "No Uniswap router configured for ETH price resolution. Set network.uniswapRouter or pass ethToTokenRate.",
    );
  }

  const priceClient = network.priceRpcUrl ? publicClient : publicClient;
  return getEthToTokenRate(
    network.priceTokenContract ?? tokenAddress,
    routerAddress,
    priceClient,
    tokenDecimals,
  );
}

export async function estimateFees(
  params: {
    amount: bigint;
    tokenAddress: Address;
    tokenDecimals: number;
    network: NetworkConfig;
    publicClient: PublicClient;
    gasPrice?: GasPrice;
    gasOverrides?: Partial<GasConstants>;
    ethToTokenRate?: number;
  },
): Promise<FeeEstimate> {
  const { amount, tokenAddress, tokenDecimals, network, publicClient, gasPrice, gasOverrides } = params;
  const nativeEth = isNativeToken(tokenAddress);

  const gas: GasConstants = { ...network.gas, ...gasOverrides };

  let networkFee: bigint;
  let nodeFee: bigint;

  if (network.kind === "tempo") {
    // Tempo: fixed 10 gwei base fee, stablecoin native token
    const tempoBaseFeeGwei = 10n;
    const gweiToWei = 1_000_000_000n;
    const tempoGasPrice = tempoBaseFeeGwei * gweiToWei;

    // User pays: deploy only (approve + fund are batched with it)
    const userGasWei = tempoGasPrice * gas.deploy;
    // Node pays: bond + fund + collect
    const nodeGasWei = tempoGasPrice * (gas.bond + gas.fund + gas.collect);

    // Tempo native token is stablecoin with 18 decimals, token is 6 decimals
    // Convert from 18-decimal gas cost to token-decimal cost
    networkFee = userGasWei / (10n ** (18n - BigInt(tokenDecimals)));
    const nodeGasFee = nodeGasWei / (10n ** (18n - BigInt(tokenDecimals)));

    const nodeFeeBase = (network.nodeFeeUsd * 10n ** BigInt(tokenDecimals)) / 10n ** 6n;
    nodeFee = nodeFeeBase + nodeGasFee;
  } else if (nativeEth) {
    // Native ETH on EVM: gas costs are in wei, same unit as transfer
    const maxFee = await resolveGasPrice(publicClient, gasPrice);

    // User pays: deploy only (no approval for native ETH)
    const userGasWei = maxFee * gas.deploy;
    // Node pays: bond + fund + collect
    const nodeGasWei = maxFee * (gas.bond + gas.fund + gas.collect);

    networkFee = userGasWei;

    // nodeFeeBase for native ETH: use a fixed ETH amount
    // NODE_FEE_ETH = 0.0005 ETH = 500_000_000_000_000 wei
    const nodeFeeBase = 500_000_000_000_000n;
    nodeFee = nodeFeeBase + nodeGasWei;
  } else {
    // ERC20 on EVM: convert gas costs from ETH to token units
    const maxFee = await resolveGasPrice(publicClient, gasPrice);

    // User pays: approve + deploy
    const userGasWei = maxFee * (gas.approve + gas.deploy);
    // Node pays: bond + fund + collect
    const nodeGasWei = maxFee * (gas.bond + gas.fund + gas.collect);

    // Get ETH->token exchange rate
    const ethToTokenRate = await resolveEthPrice(
      network, publicClient, tokenAddress, tokenDecimals, params.ethToTokenRate,
    );

    // Convert gas costs in ETH (float) to token units
    const userGasEth = Number(userGasWei) / 1e18;
    const nodeGasEth = Number(nodeGasWei) / 1e18;

    const networkFeeFloat = userGasEth * ethToTokenRate;
    const nodeGasFeeFloat = nodeGasEth * ethToTokenRate;

    networkFee = BigInt(Math.ceil(networkFeeFloat * 10 ** tokenDecimals));
    const nodeGasFee = BigInt(Math.ceil(nodeGasFeeFloat * 10 ** tokenDecimals));

    const nodeFeeBase = (network.nodeFeeUsd * 10n ** BigInt(tokenDecimals)) / 10n ** 6n;
    nodeFee = nodeFeeBase + nodeGasFee;
  }

  // Platform fee: percentage of transfer amount
  const platformFee = (amount * network.platformFeeRate) / 10_000n;

  const totalFee = networkFee + nodeFee + platformFee;
  const totalAmount = amount + totalFee;

  return {
    transferAmount: amount,
    networkFee,
    nodeFee,
    platformFee,
    totalFee,
    totalAmount,
    decimals: tokenDecimals,
    isNativeEth: nativeEth,
  };
}
