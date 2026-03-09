# SDK Proposal

Private transfers on Mirage require a multi-step protocol: 
- fee estimation
- token approvals
- escrow deployment
- compliance checks
- encrypted signal submission
- transfer polling. 

This SDK encapsulates that protocol into a single async flow, leveraging javascript event sources and abort signals for consistent usage with other libraries.

All token amounts are `bigint` (raw wei/unit values). The SDK never uses floating-point for amounts, callers use viem's `parseUnits`/`formatUnits` at the boundary.

## Public API

### Configuration

```ts
type NetworkId = "sepolia" | "tempo" | "ethereum";
type NetworkKind = "ethereum" | "tempo";

interface NetworkConfig {
  id: NetworkId;
  kind: NetworkKind;
  chainId: number;
  rpcUrl: string;
  nomadUrl: string;
  apiServer: string;
  enableCompliance: boolean;

  // When true, approve + deploy + fund are submitted as a single batched tx.
  // Defaults to true for tempo (native multicall), false for ethereum.
  // Future: ethereum batch support via smart accounts or Buildernet.
  enableBatch: boolean;

  // Fee parameters
  nodeFeeUsd: bigint;           // e.g. 2_000000n for $2.00 (6 decimals)
  platformFeeRate: bigint;      // basis points, e.g. 50n = 0.50%

  // Gas constants for fee estimation.
  // API gas estimations override these, when not available it wil fall back
  gas: GasConstants;
}

interface GasConstants {
  approve: bigint;
  deploy: bigint;
  bond: bigint;
  transfer: bigint;
  collect: bigint;
}

// Built-in configs for known networks.
const networks: Record<NetworkId, NetworkConfig>;

// Derive a config from a built-in or custom base, overriding specific fields.
// Nested objects (e.g. gas) are merged field-by-field, not replaced wholesale.
// i.e. { gas: { approve: 60_000n } } overrides only approve, keeping other gas fields.
function createNetworkConfig(
  base: NetworkId | NetworkConfig,
  overrides?: DeepPartial<NetworkConfig>,
): NetworkConfig;
```

### Errors

```ts
class MirageError extends Error {
  code: string;               // machine-readable, e.g. "INSUFFICIENT_BALANCE"
  cause?: unknown;
}

class ApiError extends MirageError {
  statusCode: number;
  body?: unknown;
}

class ContractError extends MirageError {
  txHash?: Hash;
}

// Thrown by executeTransfer when the AbortSignal is triggered after
// transactions have already been submitted.
// If aborted after deploy, the SDK attempts a withdrawal before throwing.
// If the withdrawal itself fails, withdrawError is set and escrowAddress
// is included so the caller can attempt recovery.
class TransferAbortedError extends MirageError {
  code: "TRANSFER_ABORTED";
  escrowAddress?: Address;    // set if deploy completed before abort
  withdrawHash?: Hash;        // set if withdrawal tx was submitted successfully
  withdrawError?: unknown;    // set if withdrawal tx failed
}

// Thrown (as MirageError with code "ACCOUNT_CHANGED") when walletClient.account
// differs from the account locked at executeTransfer entry, checked before every
// tx submission. The transfer is not recoverable, the caller should prompt the
// user to switch back to the original account and start a new transfer.
// Same withdrawal semantics as TransferAbortedError apply if deploy completed.
//
// error.meta: {
//   expectedAccount: Address,  // account locked at start
//   actualAccount: Address,    // account seen at detection
//   escrowAddress?: Address,
//   withdrawHash?: Hash,
//   withdrawError?: unknown,
// }
```

### Types

```ts
// All fee fields are in token units (bigint), same decimals as the transfer token.
// For native ETH transfers, amounts are in wei.
interface FeeEstimate {
  transferAmount: bigint;       // what the recipient receives
  networkFee: bigint;           // gas cost for user txs (approve + deploy)
  nodeFee: bigint;              // base node fee + gas cost for node txs
  platformFee: bigint;          // percentage-based protocol fee
  totalFee: bigint;             // networkFee + nodeFee + platformFee
  totalAmount: bigint;          // transferAmount + totalFee (what leaves the wallet)
  decimals: number;             // token decimals, for display formatting
  isNativeEth: boolean;
}

interface TransferEvent {
  transactionHash: Hash;
  blockNumber: bigint;
  amount: bigint;
  from: Address;
  to: Address;
}

interface NetworkKeyStatus {
  publicKey: string;
  attested: boolean;
  debug: boolean;
  chainId: number;
  mrenclave?: string;
  mrsigner?: string;
}
```

### Transfer

```ts
interface TransferParams {
  tokenAddress: Address;
  recipientAddress: Address;
  amount: bigint;               // raw token units (use parseUnits at call site)
  walletClient: WalletClient;
  publicClient: PublicClient;
  // account is derived from walletClient.account at call time and locked for
  // the duration of the transfer. No explicit account field.
  network: NetworkConfig;
  // Resume a transfer whose escrow is already deployed (e.g. after an
  // ACCOUNT_CHANGED or TRANSFER_ABORTED recovery). Skips approve and deploy
  // steps; the generator starts from compliance (or signal if compliance is
  // not required). Fee estimation is also skipped, amount must match what
  // was originally funded.
  escrowAddress?: Address;
  // Required when network.enableCompliance is true. Validated before any
  // transactions are submitted, missing or invalid token throws immediately.
  accessToken?: string;
  gasPrice?: GasPrice;          // override live gas; required for fee calc on EVM
  abortSignal?: AbortSignal;    // cancellation; see TransferAbortedError
  // Max time (ms) to wait for the Transfer event after signal submission.
  // Throws TransferTimeoutError if exceeded. Default: 120_000 (2 minutes).
  pollTimeout?: number;
}

// Optional gas price override. If omitted, the SDK fetches current gas from the publicClient.
interface GasPrice {
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

type TransferStep =
  | { step: "fees"; fees: FeeEstimate }
  // hash is the approval tx hash. The SDK waits for confirmation before proceeding.
  | { step: "approve"; hash: Hash }
  // hash is the deploy tx hash; escrowAddress is available once confirmed.
  | { step: "deploy"; hash: Hash; escrowAddress: Address }
  | { step: "compliance"; approval: { signature: string; timestamp: number } }
  // hash is the signal submission tx hash.
  | { step: "signal"; hash: Hash }
  | { step: "complete"; transfer: TransferEvent };

// Estimate fees without sending transactions.
// Fetches gas price from the publicClient (or uses gasPrice override).
async function prepareTransfer(
  params: TransferParams,
): Promise<FeeEstimate>;

// Execute full transfer. Yields progress steps as each stage completes.
// Internally handles: fee calc → approve → deploy → compliance → signal → poll.
// Network kind (ethereum vs tempo) determines the escrow strategy automatically.
//
// Cancellation: pass an AbortSignal via params.abortSignal. The generator checks the
// signal between steps. If aborted before any transactions are sent, it throws
// TransferAbortedError with no escrowAddress. If aborted after deploy, the SDK
// submits a withdrawal tx before throwing. on success, withdrawHash is set; on
// failure, withdrawError and escrowAddress are set for caller-side recovery.
//
// Timeout: if the Transfer event is not observed within params.pollTimeout ms
// after signal submission, throws TransferTimeoutError.
async function* executeTransfer(
  params: TransferParams,
): AsyncGenerator<TransferStep>;
```

### Token Utilities

```ts
interface TokenMetadata {
  address: Address;
  name: string;
  symbol: string;
  decimals: number;
}

// Read on-chain token metadata.
async function getTokenMetadata(
  tokenAddress: Address,
  publicClient: PublicClient,
): Promise<TokenMetadata>;

// Read raw balance (bigint).
async function getTokenBalance(
  tokenAddress: Address,
  owner: Address,
  publicClient: PublicClient,
): Promise<bigint>;

// Read raw allowance (bigint).
async function getTokenAllowance(
  tokenAddress: Address,
  owner: Address,
  spender: Address,
  publicClient: PublicClient,
): Promise<bigint>;

// Check if address is the native token (zero address).
function isNativeToken(address: Address): boolean;

// The zero address constant used for native ETH.
const NATIVE_TOKEN_ADDRESS: Address;
```

### Service Utilities

```ts
// SGX attestation status.
async function fetchNetworkKey(
  nomadUrl: string,
): Promise<NetworkKeyStatus>;

// Transfer limits and service health.
// maxTransferUsd values are strings (not bigint) to survive JSON serialization.
async function fetchApiHealth(
  apiServer: string,
): Promise<{
  status: string;
  version?: string;
  maxTransferUsd?: Record<string, string | null>;
}>;
```

## Example Usage

```ts
import {
  networks,
  prepareTransfer,
  executeTransfer,
  getTokenMetadata,
  getTokenBalance,
  MirageError,
  TransferAbortedError,
  TransferTimeoutError,
} from "@mirageprivacy/mirage-sdk";
import { createWalletClient, createPublicClient, http, parseUnits, formatUnits } from "viem";

// walletClient and publicClient are provided by the app (e.g. via AppKit/MetaMask).
// The SDK does not manage wallet connections.
const publicClient = createPublicClient({ chain: mainnet, transport: http() });
const walletClient = createWalletClient({ chain: mainnet, transport: custom(window.ethereum) });

const TOKEN_ADDRESS = "0x..."; // USDC
const RECIPIENT    = "0x...";
const NETWORK      = networks.ethereum;

// 1. Resolve token metadata and current balance.
const token   = await getTokenMetadata(TOKEN_ADDRESS, publicClient);
const account = walletClient.account.address;
const balance = await getTokenBalance(TOKEN_ADDRESS, account, publicClient);

const amount = parseUnits("100", token.decimals);

if (balance < amount) {
  throw new Error(`Insufficient balance: ${formatUnits(balance, token.decimals)} ${token.symbol}`);
}

// 2. Preview fees before asking the user to confirm.
const fees = await prepareTransfer({
  tokenAddress: TOKEN_ADDRESS,
  recipientAddress: RECIPIENT,
  amount,
  walletClient,
  publicClient,
  network: NETWORK,
});

console.log(`Sending:    ${formatUnits(fees.transferAmount, token.decimals)} ${token.symbol}`);
console.log(`Total cost: ${formatUnits(fees.totalAmount, token.decimals)} ${token.symbol}`);
console.log(`  network fee:  ${formatUnits(fees.networkFee, token.decimals)}`);
console.log(`  node fee:     ${formatUnits(fees.nodeFee, token.decimals)}`);
console.log(`  platform fee: ${formatUnits(fees.platformFee, token.decimals)}`);

// 3. Execute. The controller lets the UI cancel (e.g. user clicks "Cancel").
const controller = new AbortController();

// Wire up a cancel button, network change, or account change event:
//   controller.abort();

try {
  for await (const event of executeTransfer({
    tokenAddress: TOKEN_ADDRESS,
    recipientAddress: RECIPIENT,
    amount,
    walletClient,
    publicClient,
    network: NETWORK,
    abortSignal: controller.signal,
    pollTimeout: 120_000,
  })) {
    switch (event.step) {
      case "fees":
        // Re-emitted at execution time; fees may differ slightly from prepareTransfer
        // if gas moved between preview and execution.
        break;
      case "approve":
        console.log(`Token approval confirmed: ${step.hash}`);
        break;
      case "deploy":
        console.log(`Escrow deployed: ${step.escrowAddress} (tx: ${step.hash})`);
        break;
      case "compliance":
        console.log(`Compliance approved at ${step.approval.timestamp}`);
        break;
      case "signal":
        console.log(`Signal submitted: ${step.hash}`);
        break;
      case "complete":
        console.log(`Transfer complete: ${step.transfer.transactionHash}`);
        break;
    }
  }
} catch (e) {
  if (e instanceof TransferAbortedError) {
    if (e.withdrawHash) {
      console.warn("Cancelled: withdrawal submitted, funds returning", e.withdrawHash);
    } else if (e.withdrawError) {
      // Escrow is still funded. Surface escrowAddress for manual recovery.
      console.error("Cancelled: withdrawal failed, manual recovery needed", {
        escrow: e.escrowAddress,
        error: e.withdrawError,
      });
    } else {
      console.warn("Cancelled before any transactions were sent");
    }
  } else if (e instanceof TransferTimeoutError) {
    console.error("Timed out waiting for node to complete transfer");
  } else if (e instanceof MirageError && e.code === "ACCOUNT_CHANGED") {
    // walletClient.account changed mid-flight. If deploy had completed,
    // prompt the user to switch back to expectedAccount and resume.
    console.error("Wallet account changed during transfer", {
      expected: e.meta.expectedAccount,
      actual:   e.meta.actualAccount,
    });
    if (e.meta.escrowAddress) {
      // Once the user switches back, resume from compliance/signal:
      // executeTransfer({ ...params, escrowAddress: e.meta.escrowAddress })
      console.warn("Resume with escrowAddress:", e.meta.escrowAddress);
    }
  } else if (e instanceof MirageError) {
    console.error(`Transfer failed [${e.code}]`, e.cause);
  } else {
    throw e;
  }
}
```

## Internal Modules (not public API)

The following are implementation details composed by the pipeline:

- **fees**: fee calculation using obfuscation estimations, fallback gas constants, and the protocol's rates, all in bigint
- **token**: ERC20 approve, balance, allowance
- **escrow**: contract deployment (standard for ethereum kind, batched for tempo kind), withdrawal
- **api**: bytecode obfuscation, compliance requests
- **nomad**: ECIES signal encryption and submission
- **transfer**: polling for Transfer events / native ETH transfers

### Fee Calculation (internal)

All fee math is in bigint. For EVM networks, gas costs are converted to token units
using an on-chain price oracle (Uniswap `getAmountsOut`). For Tempo, gas costs are
fixed (stablecoin native token at known gwei).

```
networkFee   = maxFeePerGas * (approveGas + deployGas)
nodeGasFee   = maxFeePerGas * (approveGas + bondGas + transferGas + collectGas)
nodeFee      = nodeFeeBase + nodeGasFee                    [converted to token units]
platformFee  = transferAmount * platformFeeRate / 10_000n
totalFee     = networkFee + nodeFee + platformFee
totalAmount  = transferAmount + totalFee
```

For native ETH: gas costs are already in wei, no price conversion needed.
For ERC20 on EVM: gas costs (wei) are multiplied by ETH/token exchange rate.
For Tempo: gas price is fixed, native token is a stablecoin, no conversion needed.

## What is out of scope for the library?

- Wallet connection (AppKit, MetaMask, passkeys, Tempo WebAuthn)
- ENS resolution
- Gas/price subscriptions (SDK fetches gas on-demand; caller manages polling)
- Faucet interaction (we can consider adding a utility though for our API on eth, and tempo faucet?)
- Framework-specific state (Svelte stores, React hooks, localStorage)
- Display formatting (callers should just use viem's `formatUnits`)

## Dependencies

- `viem`: peer dependency
- `eciesjs`: direct dependency (encryption format must match node-side Rust `ecies` crate)

