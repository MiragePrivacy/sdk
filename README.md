# @mirageprivacy/sdk

TypeScript SDK for private transfers on the Mirage protocol. It requests API-authored pricing, deploys the exact quoted EscrowBatch, obtains a quote-bound execution approval, submits the encrypted Nomad Signal, and polls recipient transfers.

## Install

```sh
npm install @mirageprivacy/sdk viem
```

`viem` is a peer dependency.

## Quick start

```ts
import { networks, prepareTransfer, getTokenMetadata, getTokenBalance } from "@mirageprivacy/sdk";
import { createPublicClient, createWalletClient, http, custom, parseUnits, formatUnits } from "viem";
import { mainnet } from "viem/chains";

const publicClient = createPublicClient({ chain: mainnet, transport: http() });
const walletClient = createWalletClient({ chain: mainnet, transport: custom(window.ethereum) });

const TOKEN = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC
const RECIPIENT = "0x...";

const token = await getTokenMetadata(TOKEN, publicClient);
const balance = await getTokenBalance(TOKEN, walletClient.account.address, publicClient);
const amount = parseUnits("100", token.decimals);

// 1. Preview fees
const prepared = await prepareTransfer({
  tokenAddress: TOKEN,
  recipientAddress: RECIPIENT,
  amount,
  walletClient,
  publicClient,
  network: networks.ethereum,
});

console.log(
  `Service fee: ${formatUnits(prepared.fees.serviceFee.amount, token.decimals)} ${token.symbol}`,
);

// 2. Execute transfer
for await (const event of prepared.execute()) {
  switch (event.step) {
    case "fees":    console.log("Fees calculated");                          break;
    case "approve": console.log(`Approved: ${event.hash}`);                  break;
    case "deploy":  console.log(`Escrow: ${event.escrowAddress}`);           break;
    case "signal":  console.log(`Signal sent: ${event.response}`);           break;
    case "complete": console.log(`Delivered ${event.transfers.length} row(s)`); break;
  }
}
```

## Staged execution

Consumers that expose separate approval and deployment controls can use the
same prepared transfer without reimplementing protocol logic:

```ts
const prepared = await prepareTransfer({
  transfers,
  senderAddress: walletClient.account.address,
  publicClient,
  network: networks.ethereum,
});

// Approve button. The generator yields immediately after each token approval.
const approvals = prepared.approve(walletClient);
let checkpoint;
while (true) {
  const next = await approvals.next();
  if (next.done) {
    checkpoint = next.value;
    break;
  }
  console.log(next.value.hash);
}

// Deploy button. Persist `deployed.secrets` immediately.
const deployed = await prepared.deploy(walletClient, checkpoint);

// Automatically submit and monitor after deployment.
for await (const event of prepared.complete(walletClient, deployed.secrets)) {
  console.log(event.step);
}
```

`ApprovalCheckpoint` and `TransferSecrets` are serializable stage boundaries.
The latter includes the batch scalar, quote commitment, and opaque sealed
pricing authorization. Persist it immediately: a reload must submit the same
authorization that produced the deployed constructor.

## Networks

Built-in configs for `ethereum`, `sepolia`, and `tempo`:

```ts
import { networks, createNetworkConfig } from "@mirageprivacy/sdk";

// Use a built-in config directly
const network = networks.ethereum;

// Or customize transport and attestation policy.
const custom = createNetworkConfig("ethereum", {
  rpcUrl: "https://my-rpc.example.com",
  attestation: { maxAgeSecs: 180 },
});
```

Attestation and Signal submission are routed through the API server's nomad
proxy at `{apiServer}/nomad/{chainId}`, so `NetworkConfig` has no `nomadUrl`
field and nodes are never contacted directly. Pointing at a local nomad node
now requires an API server with the proxy configured.

## Transfer lifecycle

`prepareTransfer` returns a `PreparedTransfer` with the API quote in `.fees` and an async `.execute()` pipeline:

1. **fees** - Public API service fee and exact funding requirements
2. **approve** - One exact approval per ERC-20 funding asset
3. **deploy** - Exact API-quoted EscrowBatch deployment
4. **compliance** - Execution approval bound to the deployment and quote
5. **signal** - Minimal encrypted Signal envelope submission to Nomad
6. **complete** - Transfer event observed on-chain

### Cancellation

Pass an `AbortSignal` to cancel mid-transfer:

```ts
const controller = new AbortController();

const prepared = await prepareTransfer({
  // ...params,
  abortSignal: controller.signal,
});

// Cancel from UI, network change, etc.
controller.abort();
```

If aborted before any transactions are sent, `TransferAbortedError` is thrown with no `escrowAddress`. If aborted after escrow deployment, the error includes `escrowAddress` for manual recovery.

### Resuming a transfer

If a transfer fails after the escrow is deployed (e.g. account change, abort, timeout), you can resume from where it left off:

```ts
const prepared = await prepareTransfer({
  // ...same params,
  resume: savedTransferSecrets,
});

for await (const event of prepared.execute()) {
  // picks up from compliance/signal step
}
```

## Pricing

All amounts are `bigint` in raw token units. Use viem's `parseUnits`/`formatUnits` at the boundary.

```ts
const prepared = await prepareTransfer({ /* ... */ });
const { fees } = prepared;

fees.serviceFee;      // one public { asset, amount } quote
fees.rewardAsset;     // escrow reward denomination
fees.rewardAmount;    // complete reward pot; internal split remains private
fees.depositByAsset;  // exact principal + reward funding by asset
fees.msgValue;        // exact native amount supplied during deployment
```

The SDK does not calculate or publish a platform/node split. Pricing formulas,
gas profiles, floors, ceilings, and execution limits are owned and signed by
the API.

## Token utilities

```ts
import {
  getTokenMetadata,
  getTokenBalance,
  getTokenAllowance,
  isNativeToken,
  NATIVE_TOKEN_ADDRESS,
} from "@mirageprivacy/sdk";

const meta = await getTokenMetadata(tokenAddress, publicClient);
// { address, name, symbol, decimals }

const balance = await getTokenBalance(tokenAddress, owner, publicClient);
const allowance = await getTokenAllowance(tokenAddress, owner, spender, publicClient);

// Native ETH is represented by the zero address
isNativeToken(NATIVE_TOKEN_ADDRESS); // true
```

## Service utilities

```ts
import { fetchNetworkKey, fetchApiHealth, fetchTransferLimit } from "@mirageprivacy/sdk";

// SGX attestation status, fetched through the API's nomad proxy at
// {apiServer}/nomad/{chainId}. Nodes are not addressed directly.
const key = await fetchNetworkKey("https://api.mirageprivacy.com", 1);
// { publicKey, attested, debug, chainId, mrenclave?, mrsigner?, verification? }

// Tune the verification policy for a known hardened enclave release.
const hardenedKey = await fetchNetworkKey("https://api.mirageprivacy.com", 1, {
  verify: {
    allowedTcbStatus: [
      "UpToDate",
      "SWHardeningNeeded",
      "ConfigurationAndSWHardeningNeeded",
    ],
    allowedAdvisoryIds: ["INTEL-SA-00289", "INTEL-SA-00615"],
    minimumIsvSvn: 2,
  },
});

// Service health and transfer limits
const health = await fetchApiHealth("https://api.mirageprivacy.com");
// { status, version?, maxTransferUsd? }

// Per-network transfer limit (USD)
const limit = await fetchTransferLimit("https://api.mirageprivacy.com", 1);
// "10000" | null | undefined
```

## Error handling

All SDK errors extend `MirageError`, which has a machine-readable `code` property:

```ts
import {
  MirageError,
  ApiError,
  ContractError,
  TransferAbortedError,
  TransferTimeoutError,
  WhitelistRequiredError,
} from "@mirageprivacy/sdk";

try {
  for await (const event of prepared.execute()) { /* ... */ }
} catch (e) {
  if (e instanceof TransferAbortedError) {
    // e.escrowAddress - set if deploy completed before abort
  } else if (e instanceof TransferTimeoutError) {
    // Transfer event not observed within pollTimeout (default 2 min)
  } else if (e instanceof WhitelistRequiredError) {
    // e.amountUsd and e.thresholdUsd are present when supplied by the API
  } else if (e instanceof MirageError && e.code === "ACCOUNT_CHANGED") {
    // Wallet account switched mid-transfer
    // e.meta.expectedAccount, e.meta.actualAccount, e.meta.escrowAddress
  } else if (e instanceof ApiError) {
    // e.statusCode, e.body
  } else if (e instanceof ContractError) {
    // e.txHash
  }
}
```

## What this SDK does not do

- Wallet connection (use AppKit, MetaMask, etc.)
- ENS resolution
- Gas/price subscriptions (fetches on-demand; caller manages polling)
- Framework-specific state (React hooks, Svelte stores, etc.)
- Display formatting (use viem's `formatUnits`)

## License

UNLICENSED
