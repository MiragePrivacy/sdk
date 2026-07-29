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

// Escrow variant. Determines deployed bytecode, constructor shape, and fee
// profile. The node cross-validates this against the signal's reward token.
type EscrowKind = "erc20" | "native" | "batch";

interface NetworkConfig {
  id: NetworkId;
  kind: NetworkKind;
  chainId: number;
  rpcUrl: string;
  nomadUrl: string;
  apiServer: string;
  enableCompliance: boolean;

  // When true, approve + deploy + fund are submitted as a single native
  // multicall tx (tempo). Unrelated to batch escrows, which are the
  // multi-recipient escrow variant.
  enableAtomicBatch: boolean;

  // Fee parameters
  nodeFeeUsd: bigint;           // e.g. 2_000000n for $2.00 (6 decimals)
  nodeFeeWei: bigint;           // base node fee for native ETH transfers
  platformFeeRate: bigint;      // basis points, e.g. 50n = 0.50%

  // Gas constants for fee estimation.
  // API gas estimations override these, when not available it will fall back
  gas: GasConstants;
  nativeGas: NativeGasConstants;

  // Multiplier applied to bond + collect gas when sizing the bond pot (x100).
  bondPotMarginBps: bigint;

  // Verify the enclave's SGX quote before encrypting a signal to its key.
  // Strongly recommended in production. Pin the measurements to a known build,
  // otherwise any Intel-signed enclave would be accepted.
  attestation?: {
    required: boolean;
    expectedMrEnclave?: string[];
    expectedMrSigner?: string[];
    allowedTcbStatus?: TcbStatus[];
    allowDebug?: boolean;
    maxAgeSecs?: number;
  };

  // Fixed ETH->token rate, bypassing the on-chain oracle. For local chains.
  ethToTokenRate?: number;
}

interface GasConstants {
  approve: bigint;
  deploy: bigint;
  bond: bigint;
  fund: bigint;
  collect: bigint;
}

interface NativeGasConstants {
  deploy: bigint;
  bond: bigint;
  fund: bigint;
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

// Thrown by executeTransfer when the AbortSignal is triggered.
// The SDK does not attempt a withdrawal: if deploy completed, escrowAddress is
// included so the caller can decide whether to withdraw.
class TransferAbortedError extends MirageError {
  code: "TRANSFER_ABORTED";
  escrowAddress?: Address;    // set if deploy completed before abort
  withdrawHash?: Hash;        // set only if the caller-side withdrawal ran
  withdrawError?: unknown;
}

// Thrown when a single row exceeds the network's per-transaction limit.
// Limits apply per transfer, not to a batch total.
class TransferLimitError extends MirageError {
  code: "TRANSFER_LIMIT_EXCEEDED";
  amountUsd: number;
  limitUsd: number;
  rowIndex: number;           // index of the offending row
}

// Thrown when a transfer exceeds the network's whitelist threshold and no
// access token was supplied. Run the whitelist flow, then retry with the
// resulting token as params.accessToken.
class WhitelistRequiredError extends MirageError {
  code: "WHITELIST_REQUIRED";
  amountUsd: number;
  thresholdUsd: number;
}

// Thrown when resuming a non-batch escrow without its blinding scalar. The
// node cannot be authorized to bond without it, so the transfer can only be
// completed from the device that deployed the escrow.
class MissingBlindingScalarError extends MirageError {
  code: "MISSING_BLINDING_SCALAR";
  escrowAddress?: Address;
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
  // ETH the wallet fronts as msg.value at deploy to pay for the node's bond
  // and collect txs. Always wei, even for ERC20 escrows. Zero for batch.
  // Refundable surplus, so excluded from totalFee but part of totalAmount.
  bondPot: bigint;
  // Pulled by the escrow: transferAmount + rewardAmount. Excludes networkFee,
  // which the wallet pays as gas on its own txs.
  escrowAmount: bigint;
  rewardAmount: bigint;         // paid to the node: nodeFee + platformFee
  totalAmount: bigint;          // total leaving the wallet, including bondPot
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
// A single recipient row. A plain transfer is internally a one-row batch.
interface TransferRow {
  tokenAddress: Address;
  recipientAddress: Address;
  amount: bigint;
}

// Secret material required to complete a deployed escrow. The blinding scalar
// never leaves the device in shareable form: without it the node cannot be
// authorized to bond, so a resumed transfer must supply the original value.
interface TransferSecrets {
  escrowAddress: Address;
  escrowType: EscrowKind;
  blindingScalar?: `0x${string}`;  // absent for batch escrows
  seed: string;
  selectorMapping?: Record<string, string>;
  deployHash: Hash;
  deployedAt: number;
}

interface TransferParams {
  // Single-recipient form. Mutually exclusive with `transfers`.
  tokenAddress?: Address;
  recipientAddress?: Address;
  amount?: bigint;              // raw token units (use parseUnits at call site)
  // Multi-recipient form. Deploys one batch escrow for all rows; mixed
  // ERC20 + native ETH is supported.
  transfers?: TransferRow[];
  walletClient: WalletClient;
  publicClient: PublicClient;
  // account is derived from walletClient.account at call time and locked for
  // the duration of the transfer. No explicit account field.
  network: NetworkConfig;
  // Resume a transfer whose escrow is already deployed. Skips approve and
  // deploy; the generator starts from compliance (or signal if compliance is
  // not required). Must carry the blinding scalar for non-batch escrows,
  // which only the deploying device holds.
  resume?: TransferSecrets;
  // Required when the transfer exceeds the network's whitelist threshold.
  // See WhitelistRequiredError.
  accessToken?: string;
  gasPrice?: GasPrice;          // override live gas; required for fee calc on EVM
  abortSignal?: AbortSignal;    // cancellation; see TransferAbortedError
  // Max time (ms) to wait for all deliveries after signal submission.
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
  // Emitted once per distinct ERC20 requiring an allowance. The SDK waits for
  // confirmation before proceeding.
  | { step: "approve"; hash: Hash; tokenAddress: Address; index: number; total: number }
  // secrets must be retained to resume this transfer; never log or share them.
  | {
      step: "deploy";
      hash: Hash;
      escrowAddress: Address;
      escrowType: EscrowKind;
      secrets: TransferSecrets;
    }
  | { step: "compliance"; approval: { signature: string; timestamp: number } }
  | { step: "signal"; response: string }
  // Emitted incrementally as each recipient's delivery lands on chain. The
  // node sends one tx per recipient, so a batch completes progressively.
  | { step: "transfer"; transfer: TransferEvent; row: TransferRow; index: number; total: number }
  // All recipients delivered.
  | { step: "complete"; transfers: TransferEvent[] };

interface PreparedTransfer {
  fees: FeeEstimate;
  execute(): AsyncGenerator<TransferStep>;
}

// Estimate fees without sending transactions, and return an executor that
// reuses the fetched obfuscation and gas analysis.
// Checks per-row transfer limits and whitelist thresholds up front.
async function prepareTransfer(
  params: TransferParams,
): Promise<PreparedTransfer>;

// Execute full transfer. Yields progress steps as each stage completes.
// Internally: fee calc -> approve(s) -> deploy -> compliance -> signal -> poll.
// Escrow variant is derived from the rows: more than one row is always batch,
// otherwise native or erc20 based on the reward token.
//
// Cancellation: pass an AbortSignal via params.abortSignal. The generator
// checks the signal between steps and throws TransferAbortedError. No
// withdrawal is attempted; escrowAddress is included for caller-side recovery.
//
// Timeout: if all deliveries are not observed within params.pollTimeout ms
// after signal submission, throws TransferTimeoutError. Deliveries observed
// before the timeout are still yielded.
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
// SGX attestation status. Reads publicKey and chainId from the node's
// hash-committed `payload` object, falling back to the legacy flat fields.
//
// Pass `{ verify: true }` (or VerifyAttestationOptions) to verify the quote
// against Intel's root CA and bind it to the served payload. Without this the
// public key is only asserted by whatever host answered the request. When
// verifying, the returned key and chainId come from the attested payload
// rather than the response's top-level fields.
async function fetchNetworkKey(
  nomadUrl: string,
  options?: { verify?: boolean | VerifyAttestationOptions },
): Promise<NetworkKeyStatus>;

// Verify a quote and its payload commitment directly.
// Checks, in order: Intel signature chain, TCB status, enclave measurements,
// the payload hash committed in the report data, debug mode, global-key flag,
// and report age.
async function verifyAttestation(
  attestation: { quote: string; collateral: unknown },
  payload: AttestationPayload,
  options?: VerifyAttestationOptions,
): Promise<AttestationVerification>;

interface VerifyAttestationOptions {
  expectedMrEnclave?: string[];   // pin the enclave measurement
  expectedMrSigner?: string[];    // pin the signing identity
  allowedTcbStatus?: TcbStatus[]; // default: UpToDate, SWHardeningNeeded
  allowDebug?: boolean;           // never enable against production nodes
  requireGlobal?: boolean;        // default true
  maxAgeSecs?: number;            // default 86_400; 0 disables
  nowSecs?: number;               // for reproducible tests
}

// Transfer limits, whitelist thresholds, and service health.
// USD values are strings (not bigint) to survive JSON serialization, keyed by
// chain id.
async function fetchApiHealth(
  apiServer: string,
): Promise<{
  status: string;
  version?: string;
  maxTransferUsd?: Record<string, string | null>;
  whitelistRequiredUsd?: Record<string, string | null>;
}>;

// Historical gas averages, for surfacing an "elevated gas" indicator.
// Not used for execution pricing, which reads live gas from the chain.
// Returns null when the endpoint is unavailable or has no samples.
async function fetchGasHistoryAverages(
  apiServer: string,
  chainId: number,
): Promise<{ maxFeePerGas: bigint; sampledDays: number; windowDays: number } | null>;

// Check whether an identifier is whitelisted. The value is normalized
// (trimmed, lowercased) and hashed client-side; the hash itself becomes the
// access token passed as accessToken on subsequent transfers.
async function checkWhitelist(
  apiServer: string,
  email: string,
): Promise<{ whitelisted: boolean; accessToken?: string }>;
```

## Example Usage

```ts
import {
  networks,
  prepareTransfer,
  getTokenMetadata,
  getTokenBalance,
  MirageError,
  TransferAbortedError,
  TransferTimeoutError,
  TransferLimitError,
  WhitelistRequiredError,
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

// 2. Preview fees before asking the user to confirm. Limits and whitelist
//    thresholds are checked here, before any transaction is sent.
const controller = new AbortController();

const prepared = await prepareTransfer({
  tokenAddress: TOKEN_ADDRESS,
  recipientAddress: RECIPIENT,
  amount,
  walletClient,
  publicClient,
  network: NETWORK,
  abortSignal: controller.signal,
  pollTimeout: 120_000,
});

const { fees } = prepared;
console.log(`Sending:    ${formatUnits(fees.transferAmount, token.decimals)} ${token.symbol}`);
console.log(`Total cost: ${formatUnits(fees.totalAmount, token.decimals)} ${token.symbol}`);
console.log(`  network fee:  ${formatUnits(fees.networkFee, token.decimals)}`);
console.log(`  node fee:     ${formatUnits(fees.nodeFee, token.decimals)}`);
console.log(`  platform fee: ${formatUnits(fees.platformFee, token.decimals)}`);
// Refundable ETH outlay, always wei.
console.log(`  bond pot:     ${formatUnits(fees.bondPot, 18)} ETH`);

// For a batch, pass rows instead of a single recipient:
//   prepareTransfer({ transfers: [{ tokenAddress, recipientAddress, amount }, ...], ... })

// 3. Execute. The controller lets the UI cancel (e.g. user clicks "Cancel").
//    Wire up a cancel button, network change, or account change event:
//      controller.abort();

try {
  for await (const step of prepared.execute()) {
    switch (step.step) {
      case "fees":
        // Re-emitted at execution time; fees may differ slightly from the
        // preview if gas moved in between.
        break;
      case "approve":
        console.log(`Approved ${step.tokenAddress} (${step.index + 1}/${step.total}): ${step.hash}`);
        break;
      case "deploy":
        console.log(`Escrow deployed: ${step.escrowAddress} (tx: ${step.hash})`);
        // Persist step.secrets to resume later. Contains the blinding scalar,
        // so keep it local: never put it in a URL, log, or error report.
        localStorage.setItem(step.escrowAddress, JSON.stringify(step.secrets));
        break;
      case "compliance":
        console.log(`Compliance approved at ${step.approval.timestamp}`);
        break;
      case "signal":
        console.log(`Signal submitted: ${step.response}`);
        break;
      case "transfer":
        // Emitted per recipient as each delivery lands.
        console.log(
          `Delivered ${step.index + 1}/${step.total} to ${step.row.recipientAddress}: ` +
            step.transfer.transactionHash,
        );
        break;
      case "complete":
        console.log(`All ${step.transfers.length} transfer(s) complete`);
        break;
    }
  }
} catch (e) {
  if (e instanceof TransferAbortedError) {
    // The escrow keeps the funds until withdrawn; surface it for recovery.
    console.warn("Cancelled", { escrow: e.escrowAddress });
  } else if (e instanceof TransferLimitError) {
    console.error(`Row ${e.rowIndex} exceeds the $${e.limitUsd} limit`);
  } else if (e instanceof WhitelistRequiredError) {
    // Run the whitelist flow, then retry with the resulting accessToken.
    console.error(`Transfers above $${e.thresholdUsd} require verification`);
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
      // Once the user switches back, resume from compliance/signal using the
      // secrets persisted at the deploy step:
      //   prepareTransfer({ ...params, resume: savedSecrets })
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
- **bond**: blinded signer derivation (secp256k1) and bond pot sizing
- **token**: ERC20 approve, balance, allowance
- **escrow**: contract deployment (per-variant constructors, batch, tempo atomic multicall), withdrawal
- **api**: bytecode obfuscation, compliance, limits, whitelist, gas history
- **attestation**: SGX quote verification and payload commitment checking
- **nomad**: attestation and ECIES signal encryption/submission
- **poll**: incremental per-recipient delivery watching

### Attestation (internal)

The node serves a quote, its collateral, and an `AttestationPayload`. The quote
commits to that payload only by hash, in the report data:

```
report_data[0..32]  = sha256(publicKey . chainId_be . maxBalanceUsd_be . complianceKeys)
report_data[32..40] = timestamp (unix seconds, big endian)
report_data[61]     = isMetrics
report_data[62]     = isDebug
report_data[63]     = isGlobal
```

Verification recomputes that hash and compares it to the report data, which is
what binds the signal-encryption key to the enclave. The compliance keys are
hashed in the order served: the enclave sorts and deduplicates them when
building the payload, so re-sorting client-side would break the commitment.

Quote verification uses `@phala/dcap-qvl`, loaded through a dynamic import so
callers that never verify do not pay for it. Collateral is served alongside the
quote, so verification needs no network access.

### Escrow Variants (internal)

```
EscrowNative: (address recipient, uint256 amount, address blindedSigner,
               uint256 rewardAmount, uint256 bondAmount) payable
EscrowERC20:  (address token, address recipient, uint256 amount,
               address blindedSigner, uint256 rewardAmount) payable
EscrowBatch:  (address rewardAsset,
               (address asset, address recipient, uint256 amount)[] transfers,
               uint256 rewardAmount)
```

msg.value at deploy:
- native single: `amount + reward + bondPot`
- erc20 single: `bondPot`
- batch: `sum(native rows) + (rewardAsset is native ? reward : 0)`

The reward asset is the first ERC20 row, else row 0. This choice must agree
across fee calculation, approval bucketing, constructor encoding, and the
signal's `tokenContract`, or the deploy reverts.

### Blinded Signer (internal)

Each single escrow stores `blindedSigner = address(G + s*B)` on secp256k1,
where `G` is the enclave's attested public key and `s` is a fresh random
scalar. The enclave signs the escrow's BondAuth with `g + s`, which recovers
to that address. The scalar is sent in the signal and must never be reused
across escrows, since reuse links them to the network key.

### Bond Pot (internal)

Single escrows hold an ETH pot that funds the node's `bond()` and `collect()`
transactions, replacing the previous reimbursement through the node reward.

```
bondPot = ceil((bondGas + collectGas) * margin) * maxFeePerGas
```

Batch escrows take no pot and keep bond + collect in the reward instead.

### Fee Calculation (internal)

All fee math is in bigint. For EVM networks, gas costs are converted to token units
using an on-chain price oracle (Uniswap `getAmountsOut`). For Tempo, gas costs are
fixed (stablecoin native token at known gwei).

```
networkFee   = maxFeePerGas * (approveGas * approvalCount + deployGas)
nodeGasUnits = single ? fundGas : bondGas + fundGas + collectGas
nodeFee      = nodeFeeBase + maxFeePerGas * nodeGasUnits   [converted to token units]
platformFee  = platformFeeBase * platformFeeRate / 10_000n
rewardAmount = nodeFee + platformFee
totalFee     = networkFee + rewardAmount
escrowAmount = transferAmount + rewardAmount               [what the escrow pulls]
totalAmount  = transferAmount + totalFee + bondPot         [native: pot included]
```

Single escrows bill only `fund` gas to the node because the bond pot covers
bond and collect; including them would charge the user twice.

The escrow pulls `escrowAmount`, not `totalAmount`: the network fee is paid as
gas on the wallet's own transactions, so approving it would strand allowance.

For native ETH: gas costs are already in wei, no price conversion needed.
For ERC20 on EVM: gas costs (wei) are multiplied by ETH/token exchange rate.
The bond pot stays in wei even for ERC20 escrows, since it is paid in ETH.
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
- `@noble/curves`: direct dependency (secp256k1 point arithmetic for blinded signer derivation)
- `@noble/hashes`: direct dependency (sha256 for the attestation payload commitment)
- `@phala/dcap-qvl`: direct dependency (SGX quote verification; dynamically imported so it is only loaded when verifying)

