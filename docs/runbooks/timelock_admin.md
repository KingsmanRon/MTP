# Timelock-gated admin for `AnchorRegistry`

Phase 3.3 hardens contract administration by placing a
`TimelockController` between the admin multi-sig and the registry. A
single key compromise is no longer sufficient to change the allowed
submitter set or unpause the contract — the attacker would also need to
survive the timelock delay without being spotted and cancelled.

## Topology

```
Gnosis Safe (multi-sig)          TimelockController           AnchorRegistry
────────────────────────         ──────────────────           ──────────────
  PROPOSER_ROLE    ── schedule ──>  (pending ops)
  CANCELLER_ROLE   ── cancel   ──>
  (open)           ── execute  ──>  after MIN_DELAY ──>  DEFAULT_ADMIN_ROLE

Hot wallet (separate key) ──────────────────────── PAUSER_ROLE (fast path)
```

* **Safe** is the only holder of `PROPOSER_ROLE` / `CANCELLER_ROLE`.
* **Executor** role is open (`address(0)`), so any account can push a
  queued op once the delay elapses — we do not want the Safe's liveness
  to block execution.
* **Pauser** is a separate, low-privilege hot wallet. It can pause the
  registry instantly in an incident, but cannot unpause — unpause goes
  through the timelock like any other admin action.

## Parameters

| Parameter | Default | Why |
|-----------|---------|-----|
| `MIN_DELAY` | 48 h (172 800 s) | Covers a full business day plus a weekend for on-chain observers to notice and cancel a hostile queue. |
| Safe threshold | ≥ 3-of-5 | One compromised signer cannot queue ops alone. |
| Pauser | 1-of-N hot wallet | Pause is an emergency brake; we accept a lower bar in exchange for fast response. |

Override the delay at deploy time via `MIN_DELAY_SECONDS`.

## Deploying

```bash
# Required environment
export SAFE_ADDRESS=0x...            # Gnosis Safe multi-sig
export INITIAL_SUBMITTER=0x...       # anchor worker signing key
export PAUSER_ADDRESS=0x...          # hot wallet for emergency pause
export MIN_DELAY_SECONDS=172800      # optional override

forge script script/DeployTimelock.s.sol:DeployTimelock \
    --rpc-url "$RPC_URL" \
    --broadcast \
    --verify
```

The script prints the deployed `TimelockController` and `AnchorRegistry`
addresses, plus the calldata for the next operator action (granting
`PAUSER_ROLE` to the hot wallet via a queued op).

## Post-deploy checklist

1. **Confirm admin holder.** Call `hasRole(DEFAULT_ADMIN_ROLE, timelock)`
   returns `true` and `hasRole(DEFAULT_ADMIN_ROLE, deployer)` returns
   `false`. The deploy script is written so the deployer is never
   granted admin, but confirm on the block explorer anyway.
2. **Submit the pauser grant from the Safe.** Use the calldata printed
   by the deploy script with
   `timelock.schedule(registry, 0, <calldata>, 0, <salt>, MIN_DELAY)`.
   Record the salt and scheduled execution time.
3. **Wait out the delay**, then execute from any account.
4. **Revoke deployer admin on legacy deployments.** If the registry was
   deployed previously with the deployer as admin, schedule
   `registry.revokeRole(DEFAULT_ADMIN_ROLE, deployer)` from the Safe.

## Running a routine admin change

Example: add a new anchor submitter.

```solidity
// 1. Encode the call
bytes memory data = abi.encodeWithSelector(
    AnchorRegistry.addSubmitter.selector,
    newSubmitter
);

// 2. From the Safe UI (or forge cast), schedule
timelock.schedule(
    registryAddress,
    0,                // value
    data,
    bytes32(0),       // predecessor
    keccak256("add-submitter-2026-04-18"),  // salt
    172800            // delay
);
```

Wait the delay, then any account calls `timelock.execute(...)` with the
same arguments.

## Incident: suspicious queued op

Any account can observe pending ops via
`TimelockController.isOperationPending(bytes32 id)`. If a queued op
looks hostile:

1. Compute the op id with
   `timelock.hashOperation(target, value, data, predecessor, salt)`.
2. From the Safe, call `timelock.cancel(id)` — cancellation is
   immediate, no delay.

The Safe signers collectively hold `CANCELLER_ROLE` (OZ grants
`PROPOSER_ROLE` and `CANCELLER_ROLE` to the same address at
construction).

## What is explicitly NOT protected

* Pause itself is a hot-wallet action. A compromised pauser can stop the
  contract, but cannot extract, mutate, or authorize anything.
* Submitter key compromise lets the attacker anchor garbage Merkle roots
  until the Safe queues a `removeSubmitter` call and the delay passes.
  The fast lane is to **pause** first (hot wallet), then do the
  removal + unpause via timelock.
* On-chain observers have 48h to cancel. If the Safe itself is fully
  compromised *and* the incident goes unnoticed for the entire delay,
  the attacker wins. The multi-sig threshold and monitoring exist
  precisely to keep both conditions from being true simultaneously.

## Verifying in CI

`test/contracts/AnchorRegistryTimelock.t.sol` exercises the guarantees:

* deployer has no admin role after construction,
* the Safe cannot call `addSubmitter` directly,
* non-Safe EOAs cannot schedule ops,
* queued ops revert before the delay,
* queued ops execute correctly after the delay,
* the Safe can cancel a pending op.

Any regression in the handoff wiring fails CI before it ships.
