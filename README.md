# @mirageprivacy/mirage-sdk

TypeScript SDK for private transfers on the Mirage protocol. Encapsulates the full transfer lifecycle (fee estimation, token approvals, escrow deployment, compliance, encrypted signal submission, and transfer polling) into a single async generator flow.

## Install

```sh
npm install @mirageprivacy/mirage-sdk viem
```

`viem` is a peer dependency.

## Quick start

```ts
import { networks, prepareTransfer, getTokenMetadata, getTokenBalance } from "@mirageprivacy/mirage-sdk";
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

console.log(`Total cost: ${formatUnits(prepared.fees.totalAmount, token.decimals)} ${token.symbol}`);

// 2. Execute transfer
for await (const event of prepared.execute()) {
  switch (event.step) {
    case "fees":    console.log("Fees calculated");                          break;
    case "approve": console.log(`Approved: ${event.hash}`);                  break;
    case "deploy":  console.log(`Escrow: ${event.escrowAddress}`);           break;
    case "signal":  console.log(`Signal sent: ${event.hash}`);               break;
    case "complete": console.log(`Done: ${event.transfer.transactionHash}`); break;
  }
}
```

## Staged execution

Consumers that expose separate approval and deployment controls can use the
same prepared transfer without reimplementing protocol logic:

```ts
const prepared = await prepareTransfer({
  transfers,
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
The latter includes the deployment polling cursor and committed reward so a
reload can resume without changing the escrow's signal.

## Networks

Built-in configs for `ethereum`, `sepolia`, and `tempo`:

```ts
import { networks, createNetworkConfig } from "@mirageprivacy/mirage-sdk";

// Use a built-in config directly
const network = networks.ethereum;

// Or customize (nested objects like `gas` are merged, not replaced)
const custom = createNetworkConfig("ethereum", {
  rpcUrl: "https://my-rpc.example.com",
  gas: { approve: 60_000n }, // only overrides approve, keeps other gas values
});
```

## Transfer lifecycle

`prepareTransfer` returns a `PreparedTransfer` with `.fees` (the fee estimate) and `.execute()` (an async generator that runs the full pipeline):

1. **fees** - Gas and protocol fee estimation
2. **approve** - ERC-20 token approval (skipped for native ETH and batched flows)
3. **deploy** - Escrow contract deployment
4. **compliance** - Compliance check (when `network.enableCompliance` is true)
5. **signal** - Encrypted signal submission to the Mirage node
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

## Fee estimation

All amounts are `bigint` in raw token units. Use viem's `parseUnits`/`formatUnits` at the boundary.

```ts
const prepared = await prepareTransfer({ /* ... */ });
const { fees } = prepared;

fees.transferAmount; // what the recipient receives
fees.networkFee;     // gas cost for user transactions
fees.nodeFee;        // node fee (base + gas for node operations)
fees.platformFee;    // percentage-based protocol fee (0.50%)
fees.totalFee;       // networkFee + nodeFee + platformFee
fees.totalAmount;    // transferAmount + totalFee (what leaves the wallet)
```

## Token utilities

```ts
import {
  getTokenMetadata,
  getTokenBalance,
  getTokenAllowance,
  isNativeToken,
  NATIVE_TOKEN_ADDRESS,
} from "@mirageprivacy/mirage-sdk";

const meta = await getTokenMetadata(tokenAddress, publicClient);
// { address, name, symbol, decimals }

const balance = await getTokenBalance(tokenAddress, owner, publicClient);
const allowance = await getTokenAllowance(tokenAddress, owner, spender, publicClient);

// Native ETH is represented by the zero address
isNativeToken(NATIVE_TOKEN_ADDRESS); // true
```

## Service utilities

```ts
import { fetchNetworkKey, fetchApiHealth, fetchTransferLimit } from "@mirageprivacy/mirage-sdk";

// SGX attestation status
const key = await fetchNetworkKey("https://sgx1.mirageprivacy.com");
// { publicKey, attested, debug, chainId, mrenclave?, mrsigner? }

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
  TransferLimitError,
} from "@mirageprivacy/mirage-sdk";

try {
  for await (const event of prepared.execute()) { /* ... */ }
} catch (e) {
  if (e instanceof TransferAbortedError) {
    // e.escrowAddress - set if deploy completed before abort
  } else if (e instanceof TransferTimeoutError) {
    // Transfer event not observed within pollTimeout (default 2 min)
  } else if (e instanceof TransferLimitError) {
    // e.amountUsd, e.limitUsd
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
