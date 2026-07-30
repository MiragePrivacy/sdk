import type { Address, PublicClient } from "viem";
import { formatUnits } from "viem";
import type {
  EscrowKind,
  FeeEstimate,
  GasConstants,
  GasPrice,
  NativeGasConstants,
  NetworkConfig,
  TransferRow,
} from "../types.js";
import { MirageError } from "../errors.js";
import { isNativeToken } from "../token.js";
import { computeBondPot } from "./bond.js";
import { pickRewardToken } from "./escrow.js";

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

export async function resolveGasPrice(
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
  const wethAddress = (await publicClient.readContract({
    address: routerAddress,
    abi: UNISWAP_ROUTER_ABI,
    functionName: "WETH",
  })) as Address;

  const amounts = (await publicClient.readContract({
    address: routerAddress,
    abi: UNISWAP_ROUTER_ABI,
    functionName: "getAmountsOut",
    args: [10n ** 18n, [wethAddress, tokenAddress]],
  })) as bigint[];

  return parseFloat(formatUnits(amounts[1], tokenDecimals));
}

/**
 * Resolve the ETH->USD price for limit checks and fee conversion.
 * For EVM networks, uses Uniswap V2 router. Throws if no router is configured.
 * Since supported tokens are USD stablecoins, ETH->token is ETH->USD.
 */
export async function resolveEthPrice(
  network: NetworkConfig,
  publicClient: PublicClient,
  tokenAddress: Address,
  tokenDecimals: number,
  ethToTokenRate?: number,
): Promise<number> {
  if (ethToTokenRate !== undefined) return ethToTokenRate;
  if (network.ethToTokenRate !== undefined) return network.ethToTokenRate;

  if (network.kind === "tempo") return 1;

  const routerAddress = network.priceUniswapRouter ?? network.uniswapRouter;
  if (!routerAddress) {
    throw new MirageError(
      "MISSING_PRICE_ORACLE",
      "No Uniswap router configured for ETH price resolution. Set network.uniswapRouter or pass ethToTokenRate.",
    );
  }

  return getEthToTokenRate(
    network.priceTokenContract ?? tokenAddress,
    routerAddress,
    publicClient,
    tokenDecimals,
  );
}

/**
 * Gas the node is reimbursed for through the reward. Single escrows exclude
 * bond and collect because the on-chain bond pot funds those directly;
 * including them would bill the user twice.
 */
function nodeGasUnits(
  escrowType: EscrowKind,
  gas: GasConstants | NativeGasConstants,
): bigint {
  return escrowType === "batch" ? gas.bond + gas.fund + gas.collect : gas.fund;
}

export interface EstimateFeesParams {
  transfers: TransferRow[];
  escrowType: EscrowKind;
  /** Decimals of the reward asset, which all fee amounts are denominated in. */
  tokenDecimals: number;
  network: NetworkConfig;
  publicClient: PublicClient;
  gasPrice?: GasPrice;
  gasOverrides?: Partial<GasConstants>;
  ethToTokenRate?: number;
  /**
   * Total batch value in USD-equivalent reward-token units, used for the
   * platform fee. Defaults to the sum of rows sharing the reward asset.
   */
  platformFeeBase?: bigint;
}

export async function estimateFees(params: EstimateFeesParams): Promise<FeeEstimate> {
  const {
    transfers,
    escrowType,
    tokenDecimals,
    network,
    publicClient,
    gasPrice,
    gasOverrides,
    platformFeeBase,
  } = params;

  const rewardToken = pickRewardToken(transfers);
  const nativeEth = isNativeToken(rewardToken);

  const gas: GasConstants = { ...network.gas, ...gasOverrides };
  const nativeGas: NativeGasConstants = {
    deploy: gasOverrides?.deploy ?? network.nativeGas.deploy,
    bond: gasOverrides?.bond ?? network.nativeGas.bond,
    fund: gasOverrides?.fund ?? network.nativeGas.fund,
    collect: gasOverrides?.collect ?? network.nativeGas.collect,
  };

  // Amount denominated in the reward asset, which the escrow pulls. Compared
  // case-insensitively so a mixed-case duplicate is not treated as a separate
  // asset, which would under-count against the approved allowance.
  const rewardTokenKey = rewardToken.toLowerCase();
  const rewardAssetAmount = transfers.reduce(
    (sum, t) => (t.tokenAddress.toLowerCase() === rewardTokenKey ? sum + t.amount : sum),
    0n,
  );

  // One approval per distinct ERC20; the reward folds into an existing bucket.
  const approvalCount = new Set(
    transfers.filter((t) => !isNativeToken(t.tokenAddress)).map((t) => t.tokenAddress.toLowerCase()),
  ).size;

  let networkFee: bigint;
  let nodeFee: bigint;
  let bondPot = 0n;
  let networkGasToken = 0n;

  if (network.kind === "tempo") {
    // Tempo: fixed base fee, stablecoin native token, no price conversion.
    const tempoGasPrice = 10n * 1_000_000_000n;
    const tempoGas = nativeEth ? nativeGas : gas;

    // User pays deploy only; approve and fund are batched with it.
    const userGasWei = tempoGasPrice * tempoGas.deploy;
    const nodeGasWei = tempoGasPrice * nodeGasUnits(escrowType, tempoGas);

    const scale = 10n ** (18n - BigInt(tokenDecimals));
    networkFee = userGasWei / scale;
    networkGasToken = networkFee;
    const nodeFeeBase = (network.nodeFeeUsd * 10n ** BigInt(tokenDecimals)) / 10n ** 6n;
    nodeFee = nodeFeeBase + nodeGasWei / scale;
    // Single escrows still fund bond and collect through the pot; without it
    // that gas would be reimbursed by nobody. Tempo's native token is the
    // stablecoin, so the pot is already in token units.
    bondPot =
      computeBondPot({
        escrowType,
        gas,
        nativeGas,
        maxFeePerGas: tempoGasPrice,
        marginBps: network.bondPotMarginBps,
      }) / scale;
  } else if (nativeEth) {
    // Native ETH: gas costs are already in the transfer's unit.
    const maxFee = await resolveGasPrice(publicClient, gasPrice);

    networkFee = maxFee * nativeGas.deploy;
    networkGasToken = networkFee;
    nodeFee = network.nodeFeeWei + maxFee * nodeGasUnits(escrowType, nativeGas);
    bondPot = computeBondPot({
      escrowType,
      gas,
      nativeGas,
      maxFeePerGas: maxFee,
      marginBps: network.bondPotMarginBps,
    });
  } else {
    // ERC20 on EVM: convert gas costs from ETH to token units.
    const maxFee = await resolveGasPrice(publicClient, gasPrice);

    // Approve gas scales with the distinct ERC20 count; an all-native batch
    // needs no allowances at all.
    const userGasWei = maxFee * (gas.approve * BigInt(approvalCount) + gas.deploy);
    networkGasToken = userGasWei;
    const nodeGasWei = maxFee * nodeGasUnits(escrowType, gas);
    const bondPotWei = computeBondPot({
      escrowType,
      gas,
      nativeGas,
      maxFeePerGas: maxFee,
      marginBps: network.bondPotMarginBps,
    });

    const ethToTokenRate = await resolveEthPrice(
      network,
      publicClient,
      rewardToken,
      tokenDecimals,
      params.ethToTokenRate,
    );

    const toTokenUnits = (wei: bigint) =>
      BigInt(Math.ceil((Number(wei) / 1e18) * ethToTokenRate * 10 ** tokenDecimals));

    networkFee = toTokenUnits(userGasWei);
    const nodeFeeBase = (network.nodeFeeUsd * 10n ** BigInt(tokenDecimals)) / 10n ** 6n;
    nodeFee = nodeFeeBase + toTokenUnits(nodeGasWei);
    // The pot is paid in ETH, so it stays in wei rather than token units.
    bondPot = bondPotWei;
  }

  const platformFee = ((platformFeeBase ?? rewardAssetAmount) * network.platformFeeRate) / 10_000n;

  const rewardAmount = nodeFee + platformFee;
  const totalFee = networkFee + rewardAmount;
  // The escrow pulls the payment plus the reward; the network fee is paid as
  // gas on the wallet's own transactions, so it is not approved or funded.
  const escrowAmount = rewardAssetAmount + rewardAmount;

  // The pot shares the transfer's unit only when the escrow's own asset is the
  // chain's gas token. For an ERC20 escrow on an EVM chain the pot is ETH and
  // the transfer is a token, so folding it into a token total would be
  // meaningless; callers reserve it separately via bondPot.
  const potInTransferUnits = nativeEth || network.kind === "tempo";
  const byAsset = new Map<string, { tokenAddress: Address; transferAmount: bigint }>();
  for (const row of transfers) {
    const key = row.tokenAddress.toLowerCase();
    const current = byAsset.get(key);
    if (current) current.transferAmount += row.amount;
    else byAsset.set(key, { tokenAddress: row.tokenAddress, transferAmount: row.amount });
  }
  const rewardEntry = byAsset.get(rewardTokenKey) ?? {
    tokenAddress: rewardToken,
    transferAmount: 0n,
  };
  byAsset.set(rewardTokenKey, rewardEntry);
  const assetRequirements = Array.from(byAsset.values()).map((entry) => ({
    tokenAddress: entry.tokenAddress,
    transferAmount: entry.transferAmount,
    escrowAmount:
      entry.transferAmount +
      (entry.tokenAddress.toLowerCase() === rewardTokenKey ? rewardAmount : 0n),
  }));

  return {
    transferAmount: rewardAssetAmount,
    networkFee,
    nodeFee,
    platformFee,
    totalFee,
    bondPot,
    escrowAmount,
    rewardAmount,
    totalAmount: rewardAssetAmount + totalFee + (potInTransferUnits ? bondPot : 0n),
    decimals: tokenDecimals,
    isNativeEth: nativeEth,
    assetRequirements,
    gasTokenRequirement: networkGasToken + bondPot,
  };
}
