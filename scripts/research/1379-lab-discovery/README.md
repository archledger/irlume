# Book 2 discovery guard proof (B03)

This disposable QEMU guest has no physical device, disk or network;
`-no-user-config` keeps a host `qemu.conf` from adding one. A
guest-only kernel driver publishes a simulated IPU3 graph: two media
devices named like the pinned `ipu3-cio2` and `ipu3-imgu` drivers, four
CSI-2 receivers, two ImgU pipes and three sensors. It mirrors what the
pinned drivers publish (names, entity functions, pads, link flags,
capabilities and control ids) without buffers or streaming. Sensor names,
port order, control ranges and frame sizes are synthetic until an approved
passive inventory of the exact Book 2 exists. The driver logs the
operations through which discovery can change its state (subdevice and
video opens and releases, control set attempts, link changes, format and
selection sets) to a root-only debugfs file, which the PID 1 supervisor
prints as `EFFECT` records for the host verifier. The worker's seccomp
filter admits only discovery ioctls, so every state change it can request
passes through that log.

Build from clean checkouts of Linux
[`988117cc1bb17338c586a4e21ade88b5397eac33`](https://github.com/gregkh/linux/tree/988117cc1bb17338c586a4e21ade88b5397eac33)
and libcamera `v0.8.0`
([`df8e348d64b4932a0676256ed24f0da3ee9438bc`](https://github.com/libcamera-org/libcamera/tree/df8e348d64b4932a0676256ed24f0da3ee9438bc),
fetched with the real tag) as an ordinary user, with a verified `bc` on
`PATH`, `MESON` set to a verified Meson 1.9.1 binary, QEMU x86-64 11.1.3
with TCG, Python 3.11 or newer and a fresh scratch directory under
`/tmp/opencode`:

```sh
lab=scripts/research/1379-lab-discovery
MESON="$meson" bash "$lab/build_discovery_guest.sh" "$linux" "$libcamera" "$scratch/build"
g++ -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-sanitize-recover=all \
    "$lab/lab/test_lab_contract.cpp" "$lab/lab/lab_contract.cpp" -o "$scratch/test_lab_contract"
"$scratch/test_lab_contract"
python3 -B -m unittest discover -s "$lab" -p test_run_discovery.py
```

The build refuses a pinned checkout that is, contains or lies inside a
path it deletes or rewrites. It copies its own inputs to `inputs/` in the
new build directory, hashes that copy into `inputs.sha256` and builds only
from it. It hardlinks the pinned Linux tree, adds only the driver directory
and its two `Kconfig`/`Makefile` lines, checks that change set with
`git status` through a private index, and rechecks that the pinned
checkout is still clean. Meson runs with `--wrap-mode=nodownload`, a
native file that disables CMake and libyuv forced to its unused fallback,
so a missing dependency fails the build instead of fetching a subproject
and pkg-config finds no package outside the private view. Meson still
finds the compiler's `atomic`, `dl` and `threads` libraries. Every `NEEDED`
entry of a staged libcamera file must be one of nine allowed libraries,
and the lab image does not ship the isolated IPA proxy. The guest kernel enables KASAN and lock
proving; any kernel `BUG`, `WARNING`,
KASAN or lockdep report refuses the run.

`topology` reads both media devices under a scope that admits only the
two media nodes and requires the graph to equal the graph records of
`contract/front.contract`. `sim-controls` shows that re-registering the
graph keeps the device number and topology version but changes the kernfs
inode, which is why device numbers and versions alone cannot detect a
replacement. It also checks that adding an entity bumps the version and
that a third media device appears. Both cases compare their effect records
exactly with `contract/expected-effects.txt`.

`stock-baseline` boots `stock.cpio`: unpatched libcamera v0.8.0 built with
only the IPU3 pipeline and IPA, IPA signing through gnutls, and no udev,
libdw, libunwind or tracing. A private `PKG_CONFIG_LIBDIR` exposes only
`gnutls`, `yaml-0.1` and their required files, and the runtime closure is
resolved from `NEEDED` entries without running anything. The supervisor
enables the IR link, grants every node, and starts the worker as UID 65532
under two seccomp stages: deny by default, discovery ioctls only, no
process creation, no exec. The run must show the stock effects exactly:
the global link reset, both ImgUs opened, flip writes on the IR sensor
before it fails validation, and three flip writes and two formats on each
RGB sensor. This case validates the observer; it never passes on the lab
image.

The lab image carries libcamera v0.8.0 with `libcamera/book2-lab.patch` and
the files in `lab/` and `libcamera/`. The supervisor parses
`contract/front.contract`, refuses a live graph that differs from it, binds
it to this boot (media and node device numbers, kernfs inodes, topology
versions, IPA identity) and writes a read-only reservation to
`/run/book2-lab/reservation`. The worker may open only the front role's
nodes: both media devices, the front sensor, its receiver and video node,
and ImgU pipe 1 with its five nodes. Pipe 1 is chosen so that a handler
assuming ImgU 0 fails. Inside libcamera the guard checks the whole
reservation before any effect. Every open and ioctl passes its gate, which
admits only the listed effects. The lab IPU3 handler never resets links,
initializes only the reserved pipe and port, and registers one camera.
Pinned libcamera probes every entity node with `access()` during
enumeration, which a front-only device grant cannot satisfy, so the lab
patch removes that probe and leaves each decision to the open.

| Case | Change before the worker runs | Required result |
| --- | --- | --- |
| `lab-front` | none | one camera, exactly the listed effects |
| `graph-ir-link-enabled` | IR link enabled after reserving | refuse `link-state`, no worker effect |
| `graph-extra-entity` | entity added after reserving | refuse `version`, no worker effect |
| `hotplug-extra-media` | third media device after reserving | refuse `unreserved-open`, no worker effect |
| `sim-port-variant` | front sensor on port 3 at boot | supervisor refuses before reserving |
| `effect-unlisted-link` | link effect removed from the reservation | refused at the link, after the listed sensor effects; hold `partial-effects` |
| `effect-unlisted-ctrl` | test-pattern control removed from the reservation | refused at that control, after the flips; hold `partial-effects` |
| `effect-unlisted-fmt` | both format effects removed from the reservation | refused at the first format, after the IPA loads; hold `partial-effects` |
| `replace-before-discovery` | graph re-registered after reserving | same number and version, new inode; refuse `identity` before any open |
| `generation-during-discovery` | entity added inside the front format set | hold `version` after that effect, no camera |
| `hotplug-during-discovery` | media device added inside the front format set | hold `extra-media` after that effect, no camera |
| `replace-during-discovery` | graph re-registered while the worker waits after the front format | hold `snapshot`, then `HOLD replaced` |
| `worker-cgroup-sibling` | no worker; a root probe joins the worker's device cgroup | the front sensor opens; the IR and rear sensors are refused with `EPERM` |
| `replace-after-discovery` | graph re-registered before release | ownership unknown |

Every open is bracketed by the registration's kernfs inode: equal before
and after the open, with a matching `st_rdev`. Before each listed effect the
guard rereads the media device set, both topologies and every bound inode:
a change refuses the effect. After the effect it rereads them again: a
change latches a hold. When the reservation lists more than one update of
a link, the expected state is that of the last update applied, in the
order the guard admitted them or the driver logged them.

Two test-only pause points in the simulated driver hold the worker inside
the front link enable or the front format set, after the driver applies
it, until the supervisor writes `resume`, or for at most 20 s. While the
worker waits, a case can replace the IPA module, or re-register the graph
at the format pause; the link pause holds the CIO2 graph lock. A
re-registered graph is seen by the guard's recheck after that effect,
which latches a hold. The guard's route check refuses a replaced module
when the factory runs (`ipa-identity`). No case changes the state between
that recheck and the check before the next effect.

The supervisor writes a canary record just before each lab launch. After
the worker exits, it classifies the attempt from trusted evidence only:
exit status, driver log and open counts, kernfs inodes, the media set and
the live graph. The log must start with one `dropped 0` header, number its
records without gaps and hold exactly one canary, and the open counts must
list every granted node, each listed count at zero. Missing or malformed
evidence holds as `observer`; dropped records, another process, an
ungranted node or an open handle hold as `dropped`, `foreign-process`,
`ungranted-node` or `open-handles`.
`Known` needs every listed effect exactly once, counted per control record,
and the bound IPA module mapped in the worker; a format record must also
carry the media bus code the contract lists as its result. Only then does
the stand-in second
backend `/lab/ir-stub` run. A refusal with no worker effect releases
without continuing the schedule. Anything else is `HOLD <reason>` and
blocks the second backend.

The worker cannot add receipt lines: its standard descriptors are a pipe
and its log file. The cgroup probe and the IR stub start with an `O_PATH`
handle of `/` as their standard descriptors, the stub keeping only its
stdout pipe, and check that they cannot write them. The supervisor reduces its report to
`CAMERAS <n>` or `START_FAILED <n>` and the guard's verdict to printable
ASCII, and escapes worker log bytes. The verifier splits the serial log on
`\n` only and refuses a receipt line with a control character. It also
checks four outcome rules independently of the case table: no release
after refusal once a worker effect exists, no second backend after a hold
or without a known owner release, and a replacement receipt that proves the
same number and a new inode.

The lab factory decides the IPA route once, at the branch, before any
proxy exists, and can only build the threaded proxy. The lab IPU3 handler
runs the same check as a preflight right after the graph check, before
any effect. The route must satisfy all of these:

- a valid signature;
- no `LIBCAMERA_*`, `HOME` or `XDG_CONFIG_HOME` in the environment and no
  configuration file;
- the contract's module name and version;
- the bound path, device, inode and size;
- a SHA-256 of the module bytes equal to the build's digest.

While the worker is alive, the supervisor requires the bound inode in
`/proc/<worker>/maps` before it reports `IPA_ROUTE threaded <sha256>`. It
reports `IPA_MAPPED_UNBOUND`, which no case accepts, when another file is
mapped at the bound path or the bound file under another path. Such a
mapping, or a known owner whose worker did not map the bound module, holds
the attempt as `ipa-route`, and the second backend stays blocked.

| Case | Change before the worker runs | Required result |
| --- | --- | --- |
| `ipa-bad-signature` | one bit of `ipa_ipu3.so.sign` flipped | refuse `ipa-signature`, IPA not mapped |
| `ipa-force-isolation` | `/etc/libcamera/configuration.yaml` forcing isolation | refuse `configuration` |
| `ipa-env-override` | `LIBCAMERA_IPA_FORCE_ISOLATION=1` | refuse `environment` |
| `ipa-identity-mismatch` | module replaced by a byte-identical copy | refuse `ipa-identity` (new inode) |
| `ipa-replaced-before-factory` | module replaced while the worker waits after the front link | the factory refuses `ipa-identity` after the preflight admitted; hold `partial-effects` |

The first four end with a release and no next phase, because the graph
stays as reserved and the worker made no effect. `ipa-replaced-before-factory`
holds `partial-effects` instead: its sensor and link effects come before
the factory's refusal. The environment and configuration
cases are refused by the same check at the start of discovery, before the
route preflight runs; the route guard repeats it. Without the route guard,
a corrupted signature makes the unchanged factory construct the isolated
proxy after the sensor effects. Only the worker's seccomp filter, which
refuses the proxy's socket pair, then keeps the proxy process from
starting.

Run the complete set twice, each case in a fresh emulator instance:

```sh
for round in 1 2; do
    for case in topology sim-controls stock-baseline lab-front graph-ir-link-enabled \
        graph-extra-entity hotplug-extra-media sim-port-variant effect-unlisted-link \
        effect-unlisted-ctrl effect-unlisted-fmt replace-before-discovery \
        generation-during-discovery hotplug-during-discovery replace-during-discovery \
        replace-after-discovery worker-cgroup-sibling ipa-bad-signature ipa-force-isolation \
        ipa-env-override ipa-identity-mismatch ipa-replaced-before-factory; do
        python3 -B "$lab/run_discovery.py" "$scratch/build" "$scratch/r$round-$case" "$case" || exit 1
    done
done
```

Every run needs a new receipt directory and uses its own nonce. B03 passes
only when every case passes in both rounds, and the five B01/B02 cases in
`scripts/research/1379-lab-boot` still pass on an image built from the same
revision. Keep `build.sha256`, `inputs.sha256`, `guest.config` and each
case's serial log and verifier output with the signed source revision and
tool versions. Do not attach a guest image to a support issue.

These results concern the simulated graph in this guest only. They say
nothing about the real Book 2 graph, its drivers' effects, teardown,
optical state or authentication. B04 through B11 need their own plan and
B12 remains a separate attended-device decision; no hardware run or
reporter contact follows from this result.
