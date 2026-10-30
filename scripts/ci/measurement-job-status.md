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
  observation used 1104 and 1096 of its 1536 operations. Both hosts reached
  `startup-only-complete` again with `KeyringMode=private` and
  `ProtectControlGroupsEx=strict`, with the same operation counts and 3 of 3
  lookups. With the mapped-bytes check (startup witness v2) both reached it
  again on 2026-10-30, using 1170 and 1172 operations, and H accepted G's
  rows: 72 mappings of 18 files, 4019 pages, of which 3684 were compared and
  335 were private copies, none in a code mapping.
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

- Mapped bytes, narrowed and still open: on btrfs an inode number
  is unique per subvolume only, so maps alone cannot tell a runtime file from
  a snapshot copy. G now reads each readable mapping of a runtime file from
  its own `/proc/self/mem`, then its `/proc/self/pagemap` entries; every page
  still backed by a file must equal the hashed file's page (zero-filled past
  the end), and an executable mapping may have no private copies. H checks
  G's rows with its own runtime's page digests (startup witness v2), but G
  reports which pages are private copies, so H's check is not an independent
  measurement. Still open: pages the loader or G wrote before the check
  (RELRO, `.got`, `.data`; about 190 to 310 pages of a Python 3.14 process,
  mostly libpython) are counted, not compared, so a snapshot copy that
  differs only in those pages is caught by the tree checks at each scan and
  not by this check. The binding holds at each maps read; code that ran
  before the check could have replaced its own mappings. Active uprobes or
  breakpoints on runtime files make G refuse.
- Path-socket connects, narrowed and still open: before it execs G, the
  launcher's `--guardian` arm enforces a Landlock domain. It exits 77 unless
  the ABI is 9 or later (both hosts report 10) and `control.sock` beside the
  config, opened `O_PATH|O_NOFOLLOW`, is a socket with mode 0600. The domain
  handles `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` and `MAKE_SOCK` with one rule,
  `RESOLVE_UNIX` on that node's inode, and scopes abstract UNIX sockets. G
  and every descendant get EACCES on connect(2) or addressed sendmsg(2) to
  any other pathname socket created outside the domain and on bind(2) of a
  pathname socket, and EPERM on abstract sockets created outside it. Like
  any Landlock domain it also makes renames and links across directories
  fail with EXDEV; G does neither. Not covered: inherited or connected
  descriptors, socketpairs, SCM_RIGHTS and other socket families. The
  unit's `NoNewPrivileges=` is the prerequisite; systemd 259 and 262 have no
  Landlock option. Bubblewrap tests with live listeners outside the domain
  check each case and fail all 30 mutation controls. Still open: a witness
  of the denials from inside G's unit, and a nested layer with no rules for
  the future QEMU child.
- With a private PID namespace, G sees H's peer PID as 0. G checks the peer's
  uid, gid, namespace, liveness and socket node, and H stays the verifier of
  G's unit, invocation and start time.

Provider testing, biometric/corpus work, production authentication, GPU enablement
and the full 21-case campaign are outside this checkpoint's deliverable. Do not
close #1164 on the strength of this source checkpoint.

## Validation retained with this checkpoint

All 36 `scripts/ci/test-measurement-*.py` suites pass (835 tests), with
`TMPDIR` unset and with a long `TMPDIR`. G runs with `KeyringMode=private`,
read back by H: a user manager's services otherwise share its session
keyring, which G's private user namespace does not replace (probed on
systemd 259.10 and 262.1). G also runs with `ProtectControlGroupsEx=strict`,
so it no longer sees the host cgroup tree. systemd can fall back to a host
view without saying so, so G proves the effect itself: its unified cgroup is
`/`, the root of its own cgroup namespace; that directory's inode is the
unit's `ControlGroupId`, which H reads from the manager and sends in LAUNCH
v3; and its `cgroup.procs` lists only G. The witness requires a cgroup
namespace other than H's and one read-only cgroup2 at `/sys/fs/cgroup`,
alone or over the host copy with at most one legacy hierarchy. Probes with
G's profile showed both: alone on archhost (systemd 262.1), over the host
copy and its net_cls on the laptop (systemd 259.10). In the startup-only
reruns H recorded the unit's `ControlGroupId` (288107 on the laptop, 10337 on
archhost), G bound to it, and each witness shows G's own cgroup namespace and
its host's shape. The portable 69-test and controller 43-test suites also
pass. Each change in the 2026-10-29 series was written test first, and its
mutation controls fail at least one test. The startup-only native runs above
used a pinned runtime prepared from the same source, with two files patched
to count startup operations.

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
