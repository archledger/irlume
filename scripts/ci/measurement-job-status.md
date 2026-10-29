# Contained-job runner checkpoint

This is unfinished, CPU-only test infrastructure supporting #1164. It is not
GPU certification, a supported end-to-end VM runner, or authorization to change
production authentication. H is the host coordinator; G is the guardian.

Keep the pull request in draft until the remaining implementation and
qualification gates are complete. Passing source tests does not qualify a live
service or VM. `native_authorized` and `full_contract_proven` remain false.

## Completed source work

- [x] Preserve the earlier contained-job source/build foundations.
- [x] Implement source-only loading, immutable input ownership, runtime-manifest
  and ELF validation.
- [x] Implement and test the static environment-clearing launcher.
- [x] Implement process, filesystem and Python runtime evidence collectors.
- [x] Implement the bounded runtime preparer and closed startup-witness codec.
- [x] Implement typed service transport and rooted startup protocol.
- [x] Wire the concrete startup-only G entry and H coordinator.
- [x] Recheck retained input identities and hashes without renewing their
  acquisition deadlines or the rooted startup witness lifetime.
- [x] Retain original input/runtime/attempt custody after uncertain creation.
- [x] Close required non-gate owners before admission completion, including
  deadline and failure handling after the active record is removed.
- [x] Handle prompt peer exit after a complete COMMIT write without relaxing
  partial-write checks, deadlines, DONE, EOF or terminal validation.
- [x] Complete scoped source reviews and regression/mutation checks for these
  components.

## Remaining work, in order

- [x] Select, prepare and freeze the actual inert runtime and profile using the
  tested launcher and current source; verify their manifest and dependency
  closure without increasing security or resource limits.
- [x] Qualify startup-only H/G with the real service manager and actual closed
  startup evidence. This step must not start a VM. Done on 2026-10-29 with a
  scratch admission directory on two hosts: systemd 259.10 on btrfs and
  systemd 262.1 on ext4. Each run reached `startup-only-complete` (preflight,
  LAUNCH, connect, witness, READY, COMMIT, DONE and the terminal check), and
  H's peer pidfd matched the invocation in 3 of 3 lookups. The startup
  observation used 1104 and 1096 of its 1536 operations.
- [ ] Close the open containment items below before claiming containment.
- [ ] Complete and qualify the full H/E runtime closure required by the runner.
- [ ] Prepare and verify descriptor-bound VM base/payload images and required
  firmware; preserve original inputs and failed-attempt evidence.
- [ ] Implement exclusive writable-overlay ownership and freeze it only after
  the exact writer has terminated.
- [ ] Finish bounded failed-attempt recovery and continuous admission ownership,
  including uncertain creation, timeout and host-loss cases.
- [ ] Complete native Admission and the final runner/entry-point integration.
- [ ] Obtain explicit owner approval for the VM host and each VM launch, and
  coordinate available CPU, memory and device resources before execution.
- [ ] Run boot-only qualification on a fresh disposable guest.
- [ ] Run the selected native cases: `Bounds(Complete)`,
  `Loss(BeforeRegistration)` and `Bounds(WithheldWait)`, with quarantine last;
  validate effective mutations in fresh guests.
- [ ] Complete final review and applicable repository/CI gates before making
  the pull request ready for review or merging.

### Open containment items

- G sees the inode, the containing mount's device and the path of each
  runtime mapping, but not the mapped bytes. On btrfs an inode number is
  unique per subvolume only, and the tree checks (root device and
  same-device members) hold at each scan, not between scans. Binding the
  mapped bytes to the hashed file would close this.
- Restrict path-socket connects from the future QEMU child with Landlock
  (`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`, ABI 9) through the launcher.
- Evaluate `ProtectControlGroupsEx=strict`: G can still read the host cgroup
  tree's unit names and process counts.
- Check whether G inherits the user's session keyring.
- With a private PID namespace, G sees H's peer PID as 0. G checks the peer's
  uid, gid, namespace, liveness and socket node, and H stays the verifier of
  G's unit, invocation and start time.

Provider testing, biometric/corpus work, production authentication, GPU enablement
and the full 21-case campaign are outside this checkpoint's deliverable. Do not
close #1164 on the strength of this source checkpoint.

## Validation retained with this checkpoint

All 36 `scripts/ci/test-measurement-*.py` suites pass (782 tests), with
`TMPDIR` unset and with a long `TMPDIR`. The portable 69-test and controller
43-test suites also pass. Each change in the 2026-10-29 series was written
test first, and its mutation controls fail at least one test. The startup-only
native runs above used a pinned runtime prepared from the same source.

Ruff, formatting and source-boundary checks pass. The scoped production reviews
are clear. The H/controller integration test uses a fake manager/peer and a stub
witness decoder. The COMMIT race test uses a real socketpair with injected
pidfd readiness, not an actual peer-process exit. Neither establishes live
startup or VM qualification.

One earlier parallel transport run exceeded a one-second wall-clock assertion.
The isolated test and later full serial runs passed without weakening checks;
the original failure is retained and its precise cause is unproven. Full
workspace build/test, clippy, documentation and hardware qualification are not
claimed for this checkpoint as a whole.

Focused tests can be rerun from the repository root with Python 3.11+ and the
selected dependencies already available:

```sh
python3 -B scripts/ci/test-measurement-job-rooted-host.py
python3 -B scripts/ci/test-measurement-job-rooted-host-inputs.py
python3 -B scripts/ci/test-measurement-job-guardian.py
python3 -B scripts/ci/test-measurement-job-phase-rechecks.py
bash scripts/test-measurement-job.sh
```

Do not treat a Git push as a backup of VM disks, compiled launchers or local
runtime artifacts. This checkpoint preserves source, tests and this task list;
required non-source evidence and inputs remain separately retained.
