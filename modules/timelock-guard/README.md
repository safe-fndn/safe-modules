# TimelockGuard

A Safe transaction guard that enforces a configurable delay between when a multisig transaction is approved and when it can be executed.

Addresses [safe-fndn/safe-smart-account#1065](https://github.com/safe-fndn/safe-smart-account/issues/1065). See [DESIGN.md](../../docs/DESIGN.md) (in the project deliverables repo) for the full design rationale.

## How it works

1. **Schedule**: Owners sign a transaction (standard EIP-712 Safe flow). Anyone calls `scheduleTransaction(safe, ...params, signatures)` — the guard verifies the threshold of signatures on-chain and records `readyAt = block.timestamp + delay`.
2. **Wait**: The configured delay elapses. All pending transactions are publicly visible via `TransactionScheduled` events, giving observers time to detect and cancel malicious proposals.
3. **Execute**: `safe.execTransaction(...)` proceeds normally. `checkTransaction` verifies the tx was scheduled and is ready; `checkAfterExecution` clears the record.
4. **Cancel** (optional): The Safe itself or any designated canceller calls `cancel(safe, txHash)` before execution.

## Setup

```solidity
// 1. Configure (before installing guard — no timelock yet)
timelockGuard.setUp(delay);

// 2. Install
safe.execTransaction(address(safe), 0, abi.encodeCall(safe.setGuard, (address(timelockGuard))), ...);

// From this point, all execTransactions are timelocked.
```

## Canceller management

By default only the Safe itself can cancel a scheduled transaction (which is itself timelocked once the guard is installed). To allow faster cancellation without requiring a full Safe vote, the Safe can grant trusted EOAs or contracts the right to cancel individual transactions:

```solidity
// Grant cancellation rights to an operations key
timelockGuard.setCanceller(opsKey, true);

// Revoke
timelockGuard.setCanceller(opsKey, false);
```

Cancellers can cancel **any** scheduled transaction for their Safe. Grant this right only to addresses whose compromise would not be worse than the attack the delay is designed to prevent.

## Security considerations

**Bootstrapping order matters.** Call `setUp` via `execTransaction` *before* calling `setGuard`. If the guard is installed first, the `setUp` call itself becomes subject to the delay — creating a deadlock where no transactions can execute until the delay elapses, but the delay cannot be configured until a transaction executes.

**Reconfiguration is self-timelocked.** Once the guard is installed, calls to `updateDelay`, `setCanceller`, and even `setGuard(address(0))` (removal) are timelocked. This is intentional: it prevents an attacker who gains transient control of the threshold from instantly disabling the guard.

**Nonce invalidation.** If two transactions are scheduled for the same Safe nonce, executing one invalidates the other's signatures at the Safe level. This is standard Safe behavior, not a guard limitation.

**Singleton deployment.** A single `TimelockGuard` deployment serves any number of Safes. All state is keyed by the Safe address, so one Safe's configuration cannot affect another's.

## Contract addresses

| Network | Address |
|---|---|
| Sepolia | _TBD — Week 3_ |
| Mainnet | _Not yet deployed_ |

## Development

```bash
pnpm install        # from repo root
cd modules/timelock-guard
pnpm build          # compile
pnpm test           # run tests
pnpm coverage       # coverage report
pnpm lint           # solhint + eslint
```

## License

LGPL-3.0-only
