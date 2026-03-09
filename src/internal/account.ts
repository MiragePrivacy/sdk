import type { Address, WalletClient } from "viem";
import { MirageError } from "../errors.js";

export function getAccount(walletClient: WalletClient): Address {
  const account = walletClient.account;
  if (!account) {
    throw new MirageError("NO_ACCOUNT", "walletClient has no account");
  }
  return account.address;
}

export function assertAccountUnchanged(
  walletClient: WalletClient,
  expectedAccount: Address,
  escrowAddress?: Address,
): void {
  const actual = getAccount(walletClient);
  if (actual.toLowerCase() !== expectedAccount.toLowerCase()) {
    throw new MirageError("ACCOUNT_CHANGED", "Wallet account changed during transfer", {
      meta: {
        expectedAccount,
        actualAccount: actual,
        escrowAddress,
      },
    });
  }
}
