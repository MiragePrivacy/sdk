# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`@mirageprivacy/sdk` is the TypeScript SDK for private transfers through Mirage. It coordinates wallet approvals, API-authored pricing, EscrowBatch deployment, compliance approval, encrypted Signal submission to Nomad, and recipient-transfer polling.

The API owns pricing and funding calculations. Nomad verifies the signed pricing and compliance authorizations and performs private execution. The SDK must not recreate the private platform/node fee split or accept executable economics from the application.

All token amounts use raw-unit `bigint` values. Use viem's `parseUnits` and `formatUnits` at application boundaries.

## Development Commands

```bash
# Install dependencies
npm install

# Type checking
npm run check

# Build the package
npm run build

# Run unit tests
npm test

# Run tests in watch mode
npm run test:watch

# Run local Anvil integration tests
npm run test:integration

# Run every test
npm run test:all
```

Local integration tests start `anvil` directly. Set `ANVIL_BINARY` if it is installed under a non-standard executable name or path.

## Development Workflow

### Branching Strategy

- **Never edit directly on the primary branch (`main`)**
- Always create a feature branch before making changes
- If not already on a feature branch, create one: `git checkout -b <branch-name>`

### Commit Conventions

Use conventional commit format for all commits and PRs:

- `feat:` - New features
- `fix:` - Bug fixes
- `refactor:` - Code refactoring without feature changes
- `chore:` - Maintenance tasks and dependencies
- `docs:` - Documentation changes
- `style:` - Code style changes
- `test:` - Adding or updating tests
- `perf:` - Performance improvements

Examples:

```text
feat(pricing): consume signed API quotes
fix(transfer): reject incomplete resume funding
refactor(escrow): remove legacy constructor encoding
test(attestation): cover pricing signer commitments
```

### Issue Tracking

When you notice a needed change, improvement, or technical debt:

- Do not silently ignore it
- Keep unrelated changes out of the current task
- Record follow-up work with a clear description, context, and relevant file references

## Architecture

### Core Transfer Flow

The SDK implements the following private transfer flow:

1. **Prepare**: Preserve row order, group rows into Signals by asset, fetch Nomad's attested network key, and derive one blinded signer per row.
2. **Quote**: Send the chain, sender, ordered Signals, execution modes, and blinded signers to `/pricing/quote`.
3. **Approve**: Approve each non-native asset using the exact amount returned in `depositByAsset`.
4. **Deploy**: Deploy the API-provided EscrowBatch constructor with the exact quoted native `msgValue`.
5. **Compliance**: Submit the deployment transaction and quote commitment to `/compliance` and receive a quote-bound execution approval.
6. **Signal**: Encrypt a minimal Signal envelope with Nomad's attested network key and submit it to `/signal`.
7. **Complete**: Poll and emit each recipient delivery, followed by the final completion event.

Every transfer uses `EscrowBatch`, including a one-row transfer. The SDK does not fall back to the legacy ERC-20 or native escrow formats.

### Pricing and Signal Construction

Input rows are grouped into one Signal per asset while preserving the order in which assets first appear. The first Signal asset is the reward denomination selected by the API.

- ERC-20 Signals use `private` execution mode
- Native Signals use `native` execution mode
- Linked execution mode is not supported
- One base blinding scalar derives one ordered, one-time signer per row

The pricing response provides:

- The public service fee
- Reward asset and reward amount
- Exact deposits required per asset
- Exact native `msgValue`
- Exact EscrowBatch constructor arguments
- Quote commitment
- Pricing authorization sealed directly for Nomad

The encrypted Nomad envelope contains the escrow address, base blinding scalar, sealed pricing authorization, execution approval, selector mapping, and deployment metrics. It does not contain application-authored rows, rewards, fee allocations, or execution economics.

### Key Internal Modules

**Transfer orchestration** (`src/transfer.ts`)

- Resolves single and multi-row input
- Builds ordered pricing Signals
- Requests pricing and obfuscation
- Coordinates approval, deployment, compliance, Signal submission, and polling
- Validates persisted recovery data before resuming

**API services** (`src/internal/api.ts`)

- Fetches escrow obfuscation
- Requests pricing quotes and execution approvals
- Retrieves and verifies Nomad attestation payloads through the nomad proxy
- Builds nomad proxy URLs (`nomadProxyUrl`)
- Provides health, whitelist, transfer-limit, and gas-history utilities
- Extracts real whitelist amount/threshold information from compliance errors

**Escrow services** (`src/internal/escrow.ts`)

- Predicts the deployment address
- Builds exact ERC-20 approval buckets from the API funding map
- Deploys the exact API-quoted constructor and `msgValue`
- Reads escrow status and handles cancellation

**Nomad services** (`src/internal/nomad.ts`)

- Builds the minimal Signal envelope
- Encrypts it with ECIES
- Submits it through the API's nomad proxy, which forwards to an indexed node. The proxy is not trusted for the network key: the quote is re-verified client-side and the key comes from the attested payload

**Attestation** (`src/internal/attestation.ts`)

- Verifies Intel DCAP evidence
- Enforces Mirage's signer and TCB policy
- Binds the network key to both compliance and pricing signer sets

**Blinded signers** (`src/internal/bond.ts`)

- Generates the local batch scalar
- Derives one ordered blinded signer for every row

**Polling** (`src/internal/poll.ts`)

- Observes recipient deliveries incrementally
- Prevents one batch row from being reported as another

### Public Configuration

Built-in network configuration lives in `src/networks.ts`. Each network defines:

- Chain ID and network kind
- RPC and API URLs. Nomad is reached through the API's proxy at `{apiServer}/nomad/{chainId}`, so there is no per-node URL
- Whether native atomic deployment is supported
- SGX attestation policy

Pricing rates, node fees, gas profiles, price oracles, and bond margins do not belong in SDK configuration. They are owned by the API pricing schedule.

### Public Types

Public interfaces live in `src/types.ts` and are exported through `src/index.ts`.

`FeeEstimate` exposes only API-authored values:

- `serviceFee`
- `rewardAsset`
- `rewardAmount`
- `depositByAsset`
- `msgValue`
- `assetRequirements`

`TransferSecrets` contains everything required to resume the exact quoted transfer, including the blinding scalar, quote commitment, sealed pricing authorization, funding map, sender, and deployment details.

## Important Implementation Details

- **API-owned pricing**: Never calculate the platform fee, node fee, reward pot, floor, ceiling, gas buffer, or capital component in the SDK.
- **Exact deployment**: Approval amounts, constructor arguments, and `msgValue` must come directly from the quote used for that deployment.
- **One-row batches**: A single transfer is the `n = 1` EscrowBatch case, not a separate protocol path.
- **Row ordering**: Reordering rows changes signer derivation, Signal grouping, and potentially the reward denomination. Preserve the caller's order.
- **No linked mode**: Do not add linked execution to API requests or Nomad Signals.
- **Attestation hash**: The payload commitment is `sha256(publicKey . chainId_be . maxBalanceUsd_be . complianceKeys . pricingKeys)`. Preserve both signer arrays in served order.
- **Signer separation**: Pricing and compliance use separate Ed25519 authorities so either role can rotate independently and compromising one does not authorize the other.
- **Resume validation**: Missing or malformed signed pricing and funding fields must fail with `INVALID_RESUME`, not an incidental JavaScript `TypeError`.
- **Secret persistence**: Persist `TransferSecrets` with a serializer that preserves `bigint`. Never log or expose the blinding scalar.
- **Whitelist errors**: `WhitelistRequiredError.amountUsd` and `thresholdUsd` are optional. Populate them only from real API values; never substitute zero.
- **Server limits**: Transfer limits are enforced by the API. `fetchTransferLimit()` is informational and there is no client-side `TransferLimitError`.
- **Account locking**: The active wallet must remain equal to the sender committed into the quote throughout approval, deployment, and completion.
- **Abort handling**: Check the abort signal between state-changing stages and retain the deployed escrow address for recovery when applicable.
- **No unused protocol fields**: Do not retain response parsing or public exports after their consumer has been removed.
