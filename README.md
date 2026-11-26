# @mirageprivacy/sdk

TypeScript SDK for private transfers on the Mirage protocol. It requests API-authored pricing, deploys the exact quoted escrow, obtains a quote-bound execution approval, durably admits the encrypted Nomad Signal, and polls recipient transfers.

The API returns a signed admission receipt before its durable outbox delivers the request. Submission retries reuse the exact ciphertext; receipts bind its hash and the original funding deadlines. `prepared.complete()` first looks up the original receipt using the saved escrow and quote commitment, so an already admitted resume needs no refreshed screening, quote, or approval. The SDK verifies receipt signatures against compliance keys in the verified network attestation. A node HTTP acknowledgement is not proof of execution.

This client requires the matching durable-admission API, Nomad receipt verification/backlog, and fixed-window escrow artifact release. Publish those services before releasing this SDK and updating the frontend dependency. Previously funded contracts with the old renewable lease are not migrated by a client upgrade.

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

// The generator yields each completed signature or mined allowance approval.
const approvals = prepared.approve(walletClient);
let checkpoint;
while (true) {
  const next = await approvals.next();
  if (next.done) {
    checkpoint = next.value;
    break;
  }
  if (next.value.step === "approve") console.log(next.value.hash);
}

// Deploy button. Persist `deployed.secrets` immediately.
const deployed = await prepared.deploy(walletClient, checkpoint);

// Automatically submit and monitor after deployment.
for await (const event of prepared.complete(walletClient, deployed.secrets)) {
  console.log(event.step);
}
```

`ApprovalCheckpoint` and `TransferSecrets` are serializable stage boundaries.
The latter includes the blinding scalar, quote commitment, and opaque sealed
pricing authorization. Persist it immediately: a reload must submit the same
authorization that produced the deployed constructor.

For native Circle USDC on Ethereum or Sepolia, pass `fundingMode: "erc3009"` to `previewTransfer` and `prepareTransfer`. Display the selected `.fundingMode` from the preview or prepared fees. The SDK requests a new allowance quote if the server does not support signed receipt funding. Other ERC-20s continue to use ordinary allowances.

In receipt mode, `approve()` first asks the wallet to sign Circle's `ReceiveWithAuthorization` for the exact USDC deposit and predicted escrow. It yields an `authorize` event, which has no transaction hash. Each remaining ERC-20 requires one allowance. The deployment consumes the USDC signature and funds the escrow atomically. The signature stays inside the prepared transfer until submission, so the application must retain that instance through deployment. After a rejected or unsupported signature, the application can offer a fresh review using `fundingMode: "allowance"`. The SDK does not submit an allowance in response to a signing failure.

To recover a deployment across a reload or a lost wallet response, pass a third
argument to `prepared.deploy` with `onPrepared(pending)` and `onBroadcast(hash)`.
The SDK awaits the first callback before asking the wallet to send. Save
`pending` in device-local storage with a serializer that preserves bigint
values, then attach the hash to the same record in the second callback.
Treat the checkpoint as private transfer material.

After reopening, call `recoverDeployment({ publicClient, pending, hash })` on
the original chain. The hash is optional. Without it, the SDK looks for the
original sender and nonce. On RPCs without historical state, supply the
creation hash from the wallet. Recovery verifies the mined creation against
the checkpoint and returns the deployment step for `prepared.complete`.
Recovery only reads from the chain.

## Networks

Built-in configs for `ethereum` and `sepolia`:

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
2. **authorize / approve** - An optional USDC typed signature, followed by one on-chain approval per remaining ERC-20 funding asset
3. **deploy** - Exact API-quoted escrow deployment
4. **compliance** - Execution approval bound to the deployment and quote
5. **signal** - Minimal encrypted Signal envelope submission to Nomad
6. **complete** - Transfer event observed on-chain

One ERC-20 row uses `EscrowERC20`, one native row uses `EscrowNativeZK`, and two or more rows use the ZK batch variant of `EscrowBatch`. The SDK commits to each delivery when preparing the transfer. Nomad later proves that each payment matches its commitment. The proof can settle the escrow without publishing which Ethereum transaction paid the recipient. The SDK’s `complete` event means the delivery was observed. Escrow reimbursement may happen later.

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

Aborting the SDK does not unlock funds on-chain. Fixed-window escrows allow refunds of remaining funds 30 minutes after the escrow was funded. `getEscrowStatus({ escrowAddress, publicClient, selectorMapping })` checks the contract's refund deadline against the latest chain timestamp, including when no node has reserved the escrow. Preserve the complete selector mapping returned for that deployment.

For a known older or plaintext escrow without a fixed refund window, explicitly pass `refundPolicy: "legacy"` to `getEscrowStatus`. Do not select legacy mode to work around an RPC or mapping error. The default rejects failed deadline reads and reports an uninitialized deadline as ineligible.

`cancelTransfer({ escrowAddress, publicClient, walletClient, account, selectorMapping })` simulates the user's exact withdrawal before asking the wallet to submit it, and uses the gas estimate plus 20% headroom. Status describes reservation and deadline eligibility; the simulation also checks the caller and remaining funds. A state change between simulation and inclusion can still cause a revert.

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
fees.approvalGasEstimate; // optional sum of exact ERC-20 approval gas units
fees.deploymentGasEstimate; // optional API-simulated escrow deployment gas units
fees.totalWalletGasEstimate; // optional approvals + deployment gas units
fees.rewardAsset;     // escrow reward denomination
fees.rewardAmount;    // complete reward pot; internal split remains private
fees.depositByAsset;  // exact principal + reward funding by asset
fees.msgValue;        // exact native amount supplied during deployment
```

Multiply `totalWalletGasEstimate` by the current chain gas price to estimate the wallet's
native-token cost before private execution. It includes the exact quoted ERC-20 approvals and
escrow deployment; node execution is already funded by the service fee.

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
} from "@mirageprivacy/sdk";

try {
  for await (const event of prepared.execute()) { /* ... */ }
} catch (e) {
  if (e instanceof TransferAbortedError) {
    // e.escrowAddress - set if deploy completed before abort
  } else if (e instanceof TransferTimeoutError) {
    // Transfer event not observed within pollTimeout (default 2 min)
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

### Independent screening and transfer admission

Transfer preparation screens each distinct address in its own
`POST /compliance/screen` request, in shuffled order, with no sender/recipient
roles, transfer IDs, or amounts. The SDK retains five-minute signed receipts in
memory and sends them to `/execution/approve` after deployment. Resume or expired
receipts trigger fresh individual screening. A rejected address stops initial
preparation before wallet funding.

`fetchTransferPreflight(apiServer, { chainId, escrowType, signals })` accepts
signals of `{ asset, execution_mode, amounts }`, without participant addresses.
It reports amount policy and capacity as a snapshot.
Signed quotes repeat admission internally; a standalone preflight is not an
execution authorization or a liquidity reservation.
Fee previews strip recipient fields before sending the request.

This SDK requires the API screening/admission split and migration 24. Deploy the
API first, allow older quotes to drain before rollout, then release/pin this SDK
in clients. The compatibility `/compliance` route remains available to older
clients. Coordinate frontend #358 so fee display uses previews instead of signed
transfer preparation. API #103 / SDK #15 change escrow constructors and need a
separate rebase; retain the quote-bound screening coverage through that change.

These requests reduce explicit role disclosure to screening. The existing signed
pricing API still receives the full plan, and timing/IP metadata can correlate
independent requests.


### Early-access whitelist removal

The early-access whitelist is removed. Clients must stop importing
`checkWhitelist`, `checkWhitelistToken`, or `WhitelistRequiredError`, passing
`TransferParams.accessToken`, or reading `ApiHealth.whitelistRequiredUsd` and
`TransferAdmission.requires_whitelist`. These are breaking public API removals.
Deploy the companion API whitelist removal before releasing this SDK to clients;
older servers can still reject requests through their legacy gate. Policy and
screening rejections continue to surface as `ApiError`. Amount limits, capacity
checks, address screening, attestation and execution approval remain enforced by
their existing paths.
