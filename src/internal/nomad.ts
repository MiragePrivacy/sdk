import type { Address } from "viem";
import { ApiError, MirageError, MissingBlindingScalarError } from "../errors.js";
import type { EscrowKind, NetworkKeyStatus, TransferRow } from "../types.js";

async function encryptSignal(payload: Uint8Array, publicKeyHex: string): Promise<Uint8Array> {
  const { encrypt } = await import("eciesjs");
  // Strip 0x prefix if present
  const keyHex = publicKeyHex.replace(/^0x/, "");
  return encrypt(keyHex, payload) as unknown as Uint8Array;
}

function toHexString(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface SignalParams {
  escrowAddress: Address;
  escrowType: EscrowKind;
  /** Reward asset: the token the node is paid in. */
  tokenAddress: Address;
  transfers: TransferRow[];
  rewardAmount: bigint;
  blindingScalar?: `0x${string}`;
  selectorMapping?: Record<string, string>;
  complianceSignature?: string;
  complianceTimestamp?: number;
  deployedAt?: number;
  userApproveGas?: bigint;
  userDeployGas?: bigint;
  userGasPrice?: bigint;
  nomadUrl: string;
  networkKey: NetworkKeyStatus;
}

export async function submitSignal(params: SignalParams): Promise<string> {
  const {
    escrowAddress,
    escrowType,
    tokenAddress,
    transfers,
    rewardAmount,
    blindingScalar,
    selectorMapping,
    complianceSignature,
    complianceTimestamp,
    deployedAt,
    userApproveGas,
    userDeployGas,
    userGasPrice,
    nomadUrl,
    networkKey,
  } = params;

  if (transfers.length === 0) {
    throw new MirageError("EMPTY_TRANSFERS", "At least one transfer is required");
  }

  // Single escrows are gated by a BondAuth the enclave signs with g + s, so
  // the scalar is mandatory. Fail here rather than letting the node reject an
  // incomplete signal.
  if (escrowType !== "batch" && !blindingScalar) {
    throw new MissingBlindingScalarError(escrowAddress);
  }

  const first = transfers[0];
  // The node sums only rows sharing the first row's asset; mixed-asset batches
  // deliberately under-report here. Compared case-insensitively so a
  // mixed-case duplicate of the same token still counts.
  const firstAssetKey = first.tokenAddress.toLowerCase();
  const totalTransferAmount = transfers.reduce(
    (sum, t) => (t.tokenAddress.toLowerCase() === firstAssetKey ? sum + t.amount : sum),
    0n,
  );

  const signal: Record<string, unknown> = {
    escrowType,
    escrowContract: escrowAddress,
    tokenContract: tokenAddress,
    recipient: first.recipientAddress,
    transferAmount: first.amount.toString(),
    transfers: transfers.map((t) => ({
      asset: t.tokenAddress,
      recipient: t.recipientAddress,
      amount: t.amount.toString(),
    })),
    totalTransferAmount: totalTransferAmount.toString(),
    rewardAmount: rewardAmount.toString(),
    ...(blindingScalar ? { blindingScalar } : {}),
    deployedAt: deployedAt ?? null,
    selectorMapping: selectorMapping ?? null,
    approval: complianceSignature
      ? { signature: complianceSignature, timestamp: complianceTimestamp }
      : null,
    userApproveGas: userApproveGas !== undefined ? Number(userApproveGas) : null,
    userDeployGas: userDeployGas !== undefined ? Number(userDeployGas) : null,
    userGasPrice: userGasPrice !== undefined ? Number(userGasPrice) : null,
  };

  const signalBytes = new TextEncoder().encode(JSON.stringify(signal));
  const encrypted = await encryptSignal(signalBytes, networkKey.publicKey);

  // Submit as JSON-encoded hex string (matches nomad API expectation)
  const res = await fetch(`${nomadUrl}/signal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(`0x${toHexString(encrypted)}`),
  });

  if (!res.ok) {
    const errorText = await res.text().catch(() => "unknown error");
    throw new ApiError(res.status, `Signal submission failed: ${errorText}`);
  }

  return res.text();
}
