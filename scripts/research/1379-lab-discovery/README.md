# Book 2 discovery guard proof (B03)

This disposable QEMU guest has no physical device, disk or network. A
guest-only kernel driver publishes a simulated IPU3 graph: two media
devices named like the pinned `ipu3-cio2` and `ipu3-imgu` drivers, four
CSI-2 receivers, two ImgU pipes and three sensors. It mirrors what the
pinned drivers publish (names, entity functions, pads, link flags,
capabilities and control ids) without buffers or streaming. Sensor names,
port order, control ranges and frame sizes are synthetic until an approved
passive inventory of the exact Book 2 exists. The driver logs every state
change userspace causes to a root-only debugfs file, which the PID 1
supervisor prints as `EFFECT` records for the host verifier.

Build from clean checkouts of Linux
[`988117cc1bb17338c586a4e21ade88b5397eac33`](https://github.com/gregkh/linux/tree/988117cc1bb17338c586a4e21ade88b5397eac33)
and libcamera `v0.8.0`
([`df8e348d64b4932a0676256ed24f0da3ee9438bc`](https://github.com/libcamera-org/libcamera/tree/df8e348d64b4932a0676256ed24f0da3ee9438bc),
fetched with the real tag) as an ordinary user, with a verified `bc` on
`PATH` and a fresh scratch directory under `/tmp/opencode`:

```sh
lab=scripts/research/1379-lab-discovery
bash "$lab/build_discovery_guest.sh" "$linux" "$libcamera" "$scratch/build"
python3 -B -m unittest discover -s "$lab" -p test_run_discovery.py
for case in topology sim-controls; do
    python3 -B "$lab/run_discovery.py" "$scratch/build" "$scratch/check-$case" "$case" || exit 1
done
```

The build hardlinks the pinned Linux tree, adds only the driver directory
and its two `Kconfig`/`Makefile` lines, checks that change set with
`git status` through a private index, and rechecks that the pinned
checkout is still clean. The guest kernel enables KASAN and lock proving;
any kernel `BUG`, `WARNING`, KASAN or lockdep report refuses the run.

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

| `replace-before-discovery` | graph re-registered after reserving | same number and version, new inode; refuse `identity` before any open |
| `generation-during-discovery` | entity added inside the front format set | hold `version` after that effect, no camera |
| `replace-after-discovery` | graph re-registered before release | ownership unknown |

Every open is bracketed by the registration's kernfs inode: equal before
and after the open, with a matching `st_rdev`. Before each listed effect the
guard rereads both topologies and every bound inode: a change refuses the
effect. After the effect it rereads them again: a change latches a hold.
After the worker exits, the supervisor classifies the attempt from trusted
evidence only: exit status, driver log and open counts, kernfs inodes, the
media set and the live graph. `Known` needs every listed effect exactly
once; only then does the stand-in second backend `/lab/ir-stub` run. A
refusal with no worker effect releases without continuing the schedule.
Anything else is `HOLD <reason>` and blocks the second backend. The
verifier also enforces these outcome rules independently of the case
table.

These results concern the simulated graph in this guest only. They say
nothing about the real Book 2 graph, its drivers' effects, teardown,
optical state or authentication.
