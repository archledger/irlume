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

These results concern the simulated graph in this guest only. They say
nothing about the real Book 2 graph, its drivers' effects, teardown,
optical state or authentication.
