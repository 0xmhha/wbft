# Bounded current-view round-change retries

`node.Config.RoundChangeRetry` is an optional local policy. Nil preserves the
existing timer and cache behavior. Enable it explicitly with
`consensus.RoundChangeRetryOptions{MaxIntervalMs: maximum}`. The maximum must
be positive, representable as a duration, and at least every effective base
request timeout in the chain configuration. It is independent of the round
reservation timeout and has no implicit operating-network default.

For one full height/round and unsigned round-change signing identity, retry
spacing is `min(maximum, base * 2^k)`, beginning with `k=0`. The exponent and
interval saturate; a new view or message identity resets the sequence. Only a
live current-view retry timer while accepting requests can select the dedicated
route. After a successful same-payload signature and synchronous own-message
WAL append, that route can attempt the identical signed bytes to attached
validators even when their recent cache already contains the message. Self,
non-validators and unattached peers remain excluded. Generic gossip or an
observational retry cause does not authorize the exception.

Both legacy and completed-write caches retain their normal pending ownership,
capacity, stream lifetime, queue results and completion rules. An attempt or
queue acceptance does not establish a successful local write, remote receipt
or consensus progress. The independent stale-retry cancellation option remains
separate. A previously queued callback does not acquire a current-view exception
by surviving a view or phase change.

The runner requires WAL replay and an open WAL. External runner integrations
can use `wal.OpenOS` with the existing operating-system synchronization and
recovery semantics. Format-4 boundaries wrap the exact prior boundary profile
and record this retry policy. Reopening requires matching options and a
compatible binary. An older binary may ignore an opaque boundary and is not a
supported downgrade path. Normal replay reconstructs the current identity and
exponent and rearms the full last interval from the new monotonic origin.
Unrepresentable new-policy deadlines halt rather than silently clamp. Normal
close/open coverage does not establish power-loss durability.

The journal declares a separate versioned retry profile and records optional
owner sources without changing disabled-profile encodings. Diagnostic metadata
cannot enable the functional policy. The source checker joins independently
recomputed core steps, original timer operations, public signer state, later
own-message WAL frames and cache decisions. Missing source remains unavailable;
conditional consistency is not physical delivery or a full accepted-cache
runtime replay. See [source command usage](../cmd/wbft-journal/README.md#round-change-retry-source-checks).

This local policy changes no wire/header encoding, validator selection, fee or
economic rule. Configuration and WAL compatibility must be retained across
restarts; enabling a production network remains an explicit operating choice.
