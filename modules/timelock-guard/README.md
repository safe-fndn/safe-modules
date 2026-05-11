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
