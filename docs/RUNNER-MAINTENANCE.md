# Trusted runner maintenance

The self-hosted runners (minihost; archhost, on NixOS since 2026-09-29) have
operational requirements that have each silently
red-shifted the nightly hardware suite for days. Each is quick once known.
This is the runbook for them.

## 1. Capture promotion (runners with the restricted helper)

`scripts/ci/irlume-ci-capture.py` is the root-installed, source-bound capture
the hardware suite's strobe stage uses where an administrator installed it.
archhost used it until its runner was removed on 2026-09-28; no current
runner has it. It executes only the ELF
recorded in `/usr/local/lib/irlume-ci/capture.json`, which binds three facts:

```json
{
  "schema": 1,
  "source_tree": "<40-hex git tree of the exact sources>",
  "sha256": "<digest of /usr/local/lib/irlume-ci/burst_dump>",
  "device": "<approved IR node, for example /dev/video2>"
}
```

The binding is deliberate: a runner compromise must not turn into arbitrary
camera access. The consequence is that **every new source tree needs an
administrator promotion** before the strobe stage captures again; the manifest
binds the whole tree, so any merge counts, not only camera changes. From
2026-09-11 to 2026-09-14 the manifest still named the v0.12.0 tree, and from
2026-09-20 the v0.14.0 one, and every run on newer heads failed there.

The stage now reads the manifest first. On a tree it does not name, it warns
(`IR capture not run`) and skips the capture until seven days after the
manifest was written, so the rest of the suite and coverage keep running;
from then on it fails, even on nights the camera is away, and `ci-alert`
opens its issue. It captures the device the
manifest names, not the first IR node doctor lists, so check the device too
when you promote: the IR node's number can change when cameras are replugged.

Promote before a release, after camera changes, and at least weekly while
main moves:

1. Ship the exact tree to the runner host (rsync a clean checkout, no
   `.git` needed for the build itself).
2. Build the example from that tree:
   `cargo build --release --locked -p irlume-camera --example burst_dump`
   (isolated `CARGO_TARGET_DIR`).
3. Record the tree hash on your build machine:
   `git rev-parse HEAD^{tree}`. The manifest binds the TREE, not the commit.
4. On the runner host, as root, atomically install and rebind:

```sh
sudo install -m0755 -o root -g root <burst_dump> /usr/local/lib/irlume-ci/burst_dump.new
sudo mv -f /usr/local/lib/irlume-ci/burst_dump.new /usr/local/lib/irlume-ci/burst_dump
# write capture.json with the new source_tree and sha256, then:
sudo chmod 0644 /usr/local/lib/irlume-ci/capture.json  # root:root, no group/world write
```

5. Verify with one real invocation (opens the IR camera once, bounded),
   passing the manifest's `device` as `<device>`:

```sh
sudo /usr/local/libexec/irlume-ci-capture <tree> <device> | tar -t
```

Six `frame*.pgm` files plus `means.txt`, and one emitter proof line on
stderr, means the promotion took. The run's `IR camera strobe-burst capture`
step warns while the approval is stale and fails once it is more than seven
days old, at which point the daily `ci-alert` workflow flags the suite red;
this page is how you fix it.

minihost, which has carried `ir-camera` since 2026-09-28, has no installed
helper; its lane uses the direct `sudo burst_dump` fallback and needs no
promotion.

## 2. Restart a runner after host group changes

A runner process snapshots its supplementary groups at start. If you add the
runner user to a group later (or create a group it gains), the live process
keeps the old set, and any test comparing the process groups against the
group database can never reconcile. This red-shifted every minihost nightly
from 2026-09-12: the runner had been up since 2026-09-08, user `test` later
gained group `archledger` (954), and
`irlume-kwallet-init`'s credential-normalization test failed with
`supplementary groups differ` on every run.

After any host-side group change, restart the runner service:

```sh
sudo systemctl restart actions.runner.archledger-irlume.<host>.service
grep ^Groups /proc/$(pgrep -u <runner-user> Runner.Listener | head -1)/status
id <runner-user>   # the two lists must agree
```

## 3. Release-build memory on minihost

The hardware-checks lane builds with LTO and can need several gigabytes
at link time; minihost has 7.5 GiB total and routinely has only a few
hundred MiB available. A link there dies as `signal: 9, SIGKILL` from the
OOM killer. The runner service carries `OOMScoreAdjust=500` (drop-in
`60-oom-score.conf`), so under memory pressure the kernel kills the CI build
before the host's other services. If that signature appears in a
hardware-checks or hardware-suite log, free memory on minihost, then rerun
the failed job; archhost (30 GiB) can also take the lane — briefly stopping
the minihost runner service moves the next job there.

## 4. Toolchain and PAM tools for the coverage lane

The coverage job needs `rustc` and the system `llvm-cov` on the same LLVM
major; `scripts/ci/setup-coverage-tools.sh` stops with `LLVM mismatch`
otherwise. That happened on minihost on 2026-09-11: the runner's PATH put
`~/.cargo/bin` first, so a rustup 1.88 default (LLVM 20) shadowed
distribution Rust (LLVM 22). The runner's `.env` and `.path` now list
`/usr/local/sbin:/usr/local/bin:/usr/bin:/home/test/.cargo/bin`. After
editing either file, restart the runner service while it is idle, then
check what a job will see:

```sh
env -i HOME=/home/test PATH="$(cat /home/test/actions-runner/.path)" \
  bash -c 'command -v rustc llvm-cov; rustc -vV | grep ^LLVM; llvm-cov --version | grep -i "llvm version"'
```

The coverage step sets `IRLUME_REQUIRE_PAM_TOOLS=1`, so `pamtester` (AUR on
Arch) and `pam_wrapper` must be installed on the runner; a missing tool fails
the PAM lane instead of skipping it.

## 5. archhost runs NixOS: declarative environment, restart after switch

archhost re-joined the fleet on NixOS (2026-09-29, qualified green on the
full suite, run 36537023186). Its whole runner environment is declared in
`/etc/nixos/ssh-bootstrap.nix` on the host: the toolchain (`rustc` and
`llvm-cov` are both 21.x there, so the same-major check passes), the pinned
ONNX Runtime and TFLite runtimes under
`/var/lib/github-runner/archhost/`, the `pam_wrapper` build, the sudoers
rule for the direct `sudo burst_dump` route, and the bind-mounted
`/bin`, `/usr/bin` and `/usr/lib` (plus an `ID=arch` os-release shadow)
that the bwrap-based CLI tests need, because NixOS ships none of them at
those paths and `flock -c` execs the invoking user's login shell.

Two rules specific to that host:

- Restart the runner service after every `nixos-rebuild switch`: the unit's
  bind paths resolve `/run/current-system` when the unit starts, so a new
  generation leaves the live runner looking at the old environment.
- The runner unit's systemd sandbox knobs (ProtectSystem, PrivateTmp,
  CapabilityBoundingSet, …) are deliberately relaxed: the module's defaults
  block the bubblewrap sandboxes and the setuid `sudo` the hardware lane
  needs. Re-tightening them without a full suite run will red-shift the
  nightly.

## Watching for all of them

The `ci-alert` workflow (`.github/workflows/ci-alert.yml`) checks every
scheduled workflow once a day, the nightly hardware suite and the weekly
install matrix included. A workflow whose latest completed run on main failed,
or whose latest success is older than its schedule's longest gap plus one day
(48 h for the nightly suite), gets its own `ci-alert`-labeled tracking issue,
titled `CI health: hardware-suite.yml failing or stale` for the suite. If that
issue opens, this page is the first place to look.
