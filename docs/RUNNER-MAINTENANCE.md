# Trusted runner maintenance

The self-hosted runners (minihost, archhost) carry two operational
requirements that have each silently red-shifted the nightly hardware suite
for days. Both are quick once known. This is the runbook for both.

## 1. Capture promotion on archhost

`scripts/ci/irlume-ci-capture.py` is the root-installed, source-bound capture
the hardware suite's strobe stage uses on archhost. It executes only the ELF
recorded in `/usr/local/lib/irlume-ci/capture.json`, which binds three facts:

```json
{
  "schema": 1,
  "source_tree": "<40-hex git tree of the exact sources>",
  "sha256": "<digest of /usr/local/lib/irlume-ci/burst_dump>",
  "device": "/dev/video2"
}
```

The binding is deliberate: a runner compromise must not turn into arbitrary
camera access. The consequence is that **every new source tree that changes
the capture path needs an administrator promotion**, or the suite fails at
`IR camera strobe-burst capture` with `capture build is not approved`. From
2026-09-11 to 2026-09-14 the manifest still named the v0.12.0 tree, and every
run on newer heads failed there.

Promote after merging camera-affecting changes (anything touching
`crates/irlume-camera`, or before a release):

1. Ship the exact tree to archhost (rsync a clean checkout, no `.git`
   needed for the build itself).
2. Build the example from that tree:
   `cargo build --release --locked -p irlume-camera --example burst_dump`
   (isolated `CARGO_TARGET_DIR`).
3. Record the tree hash on your build machine:
   `git rev-parse HEAD^{tree}`. The manifest binds the TREE, not the commit.
4. On archhost, as root, atomically install and rebind:

```sh
sudo install -m0755 -o root -g root <burst_dump> /usr/local/lib/irlume-ci/burst_dump.new
sudo mv -f /usr/local/lib/irlume-ci/burst_dump.new /usr/local/lib/irlume-ci/burst_dump
# write capture.json with the new source_tree and sha256, then:
sudo chmod 0644 /usr/local/lib/irlume-ci/capture.json  # root:root, no group/world write
```

5. Verify with one real invocation (opens the IR camera once, bounded):

```sh
sudo /usr/local/libexec/irlume-ci-capture <tree> /dev/video2 | tar -t
```

Six `frame*.pgm` files plus `means.txt`, and one emitter proof line on
stderr, means the promotion took. The daily `ci-alert` workflow will flag
the suite red if you forget; this page is how you fix it.

minihost has no installed helper; its lane uses the direct `sudo burst_dump`
fallback and needs no promotion.

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

The PR hardware-checks lane builds with LTO and can need several gigabytes
at link time; minihost has 7.5 GiB total and routinely has only a few
hundred MiB available. A link there dies as `signal: 9, SIGKILL` from the
OOM killer while the same job passes on archhost. If that signature appears
in a hardware-checks or hardware-suite log, free memory on minihost or let
the job land on archhost (briefly stopping the minihost runner service moves
the next queued job there), then rerun the failed job.

## Watching for all three

The `ci-alert` workflow (`.github/workflows/ci-alert.yml`) checks every
scheduled workflow once a day, the nightly hardware suite and the weekly
install matrix included. A workflow whose latest completed run on main failed,
or whose latest success is older than its schedule's longest gap plus one day
(48 h for the nightly suite), gets its own `ci-alert`-labeled tracking issue,
titled `CI health: hardware-suite.yml failing or stale` for the suite. If that
issue opens, this page is the first place to look.
