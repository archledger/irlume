# Non-granting IR verification-request evaluation

`ir_request_evaluation` measures the production engine's IR-only verification
request. It returns `would_grant`, a categorical refusal, or an incomplete
measurement. Every report contains `authentication_granted: false`.

This developer example is compiled only with `ir-only-evaluation`. It does not
call PAM, release credentials, enroll a face, or change the experimental policy.
It is not a qualification result. Follow the
[qualification protocol](IR_ONLY_QUALIFICATION.md) before planning a campaign.

## Scope

The first version requires the existing `ir-only-experimental` policy, a
configured ordinary RGB/IR pair, and a recognized greeter or screen-unlock
service. It supports primary enrollment and an authorized secondary group.
Automatic selection, split pairs, privileged services and credential-release
requests are refused.

The evaluator enters normal engine verification and reuses its preparation,
enrollment compatibility, PAD, identity predicates, presence retries, deadlines
and final binding checks. An identity mismatch remains terminal. A successful
internal result is reduced to a measurement after the request returns.

Daemon peer/seat authorization, queueing, persistent retry-accounting writes,
PAM conversation, graphical unlock and credential delivery are outside this
measurement. Keep their integration tests separate.

## Build and command

```sh
cargo +1.88.0 build --release --locked -p irlume-auth \
  --features ir-only-evaluation --example ir_request_evaluation
```

```text
ir_request_evaluation (--preflight|--evaluate) USER DETECTOR RECOGNIZER FLIR
  --service SERVICE [--adapter PATH] [--cancel-on-stdin]
```

Model paths must be absolute existing files. `--preflight` checks readiness
without opening cameras. `--evaluate` requires a freshly attended start through
the reviewed supervisor. Neither the flag nor an earlier readiness result proves
participant readiness for another attempt.

There is no diagnostic budget override. The evaluator uses the production
window selected for the service, starting before request-time configuration,
enrollment loading and admission. A zero, unbounded production window is refused.
Model initialization is measured separately. Preflight does not retain its
enrollment snapshot or unsealed key for evaluation.

The executable requires real and effective root, disables core dumps and process
dumpability, refuses debug/virtual-camera overrides, and suppresses dependency
stderr before model loading. Cancellation input treats any byte, EOF or read
error as cancellation. Blocking driver/model calls still need the supervisor's
external watchdog. A panic or unsuccessful output write cannot supply a completed
measurement.

## Read-only account state

Account reads acquire the existing lock without creation or waiting. A short
transaction holds a compatible fresh UID, checks both pending journals, and
pins primary, secondary and key-envelope file identities and bytes. The lock is
released before capture so ordinary revocation can proceed.

Later reads reacquire the lock and compare the pin. The final secondary check
uses the production pure boundary predicate with freshly read data and the same
request key. Encrypted primary loading contributes its key to later reads;
there is no second copy or unseal. A pending primary replacement or secondary
intent refuses rather than invoking recovery. Missing locks, unavailable state,
changed account/file identities and files above the diagnostic 8 MiB bound also
refuse. Production can repair some of these states, so such a refusal is not a
prediction that normal authentication would deny.

Transient camera leases, emitter journaling/restoration and the anonymous
supervisor ledger retain their existing behavior. The read-only restriction is
on protected account state. Descriptor release does not prove optical emitter-off.

## Report contract

The new namespace is `operation: "ir_request_evaluation"`, `schema: 1`.
The older one-shot namespace and schemas 1 through 4 remain supported separately.

- `phase`: `preflight` or `evaluation`.
- `result`: preflight-only `{"kind":"ready"}`; evaluation-only
  `{"kind":"would_grant","identity_acceptance":"best_template|centroid|both"}`;
  or `{"kind":"refused","cause":"..."}` / `{"kind":"incomplete","cause":"..."}`.
- `scope`: `primary`, `secondary`, or null before resolution.
- `window_ms`, `elapsed_ms`: selected request window and elapsed request time.
- `initialization_ms`: executable model initialization and its camera-free
  prerequisites; null when it was not entered or a library caller did not measure it.
- `counts`: `assessments`, `captures`, `detections`, `pad`, `identity`.
- `timings_ms`: nullable `load`, `capture`, `detection`, `pad`, `identity` totals.

`assessments` counts returned invocations of the shared stage runner, including
early refusals. Other counters count entered stages, including failures. The
identity stage includes alignment, embedding and adaptation, not just comparison.
Null timing means a stage was not entered; zero can mean less than one millisecond.
Timings are wall-clock intervals, not CPU time; do not infer missing work by
subtracting rounded stage totals from elapsed time.

Counters are bounded to 1,000,000 and reported milliseconds to 120,000. Overflow
makes the measurement incomplete. A cancelled, expired or revoked candidate has
no acceptance label. No score, threshold, username, profile label, path, serial,
embedding, image or raw error is serialized. Records are limited to 16 KiB.

## Attended supervisor

Use the existing [harness workflow](../scripts/ir-evaluation/README.md), with all
four modules installed in the reviewed root-owned directory: `runner.py`,
`host.py`, `harness.py`, `request_contract.py`.

For request mode, use host configuration **schema 2**. Keep the existing assets,
subject UID, protected files, camera paths and `service: "irlumed.service"`.
Replace `budget_ms` with `expected_window_ms` and add:

```json
{
  "schema": 2,
  "request_service": "kde",
  "expected_window_ms": 15000,
  "watchdog_seconds": 45,
  "source_commit": "REVIEWED_40_CHARACTER_COMMIT",
  "source_tree": "REVIEWED_40_CHARACTER_TREE"
}
```

This fragment is not a complete configuration. The source IDs and asset hashes
must identify the reviewed build. The expected window is checked against both
reports; it is never passed as an override. Choose a longer watchdog that covers
startup and cleanup. The runner CLI and fresh `READY`/`START` interaction stay the
same. Use a new anonymous attempt ID for every invocation.

Request-mode topology permits a separate index-0 IR interface with either no
metadata (`"metadata": null`) or its same-name index-1 companion. It also permits
the production four-node shared layout: RGB image/metadata at indexes 0/1, IR
image/metadata at 2/3, with exact sibling and name pairing. It does not discover
another target. The schema-1 harness keeps its original topology restriction.

Before and after execution, request mode requires no persistent swap (zram must
have no backing device), verifies asset and declared installed-file identities,
and compares the account's primary, secondary, key, recovery, lock and pending
journal state. These account hashes stay in memory; only the preservation verdict
is written. The receipt binds source IDs, asset hashes, actual exit, trace and
cleanup results. A report with the wrong namespace, phase or window, a nonzero
exit, incomplete output or unresolved cleanup stops the ledger. A would-grant
impostor/attack/empty attempt also stops it for review.

The supervisor disables its own process dumpability before reading any account
state and stops if that protection fails. A zero core-size limit alone does not
protect against Linux piped core handlers. The supplied source IDs are reviewed
operator assertions; the supervisor verifies the binary hash but does not prove
source-to-binary provenance independently.

## Offline checks

The focused tests include encrypted read-only state, conflicting account holds,
FIFO and busy locks, primary/secondary request parity, presence retry versus
terminal identity failure, cancellation, late journal/revocation, report privacy,
strict parsing, process exit and legacy compatibility. The full-entry fixture
uses a private namespace, synthetic sysfs and `/dev/null`/`/dev/zero` aliases;
capture and inference inputs are synthetic. It is not a camera trial.

Run the repository gates and:

```sh
cargo +1.88.0 test --locked -p irlume-core --lib
cargo +1.88.0 test --locked -p irlume-auth --features ir-only-evaluation --lib --examples
python3 -m unittest discover -s scripts/ir-evaluation -p 'test_*.py'
python3 scripts/ir-evaluation/check_binary.py target/release/examples/ir_request_evaluation
```
