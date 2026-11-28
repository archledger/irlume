# Embedded Book 2 Discovery Guards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove B03 in the disposable guest. A lab build of pinned libcamera must refuse each of these before its effect: an unexpected graph, an unlisted discovery effect, a replaced or changed graph and any IPA route other than the pinned threaded one. The supervisor must start no second backend once ownership is unknown.

**Architecture:** A guest-only kernel driver publishes a simulated IPU3 graph and logs every state change it receives. A static supervisor running as PID 1 reserves that graph, grants a worker only the front role's nodes and launches it against a private lab build of libcamera v0.8.0. The lab build checks the reservation before any effect, passes every open and ioctl through a gate, binds each descriptor to its reserved registration and admits only the pinned threaded IPA route. A host verifier rechecks the receipts and the raw effect log.

**Tech Stack:** Linux v7.3.5 `988117cc1bb17338c586a4e21ade88b5397eac33`, libcamera v0.8.0 `df8e348d64b4932a0676256ed24f0da3ee9438bc`, QEMU x86-64 11.1.3 with TCG, GCC 16.2.1 (C17 and C++20), Meson 1.9.1, host gnutls 3.8.14 and libyaml 0.2.5, Python 3.

**Spec:** [Supervised capture lab design][spec], section 1 and row B03, with [ADR-0042][adr]. The guest, early policy and worker boundary come from the [B01/B02 plan][b02]. This plan covers B03 only. B04 through B11 need a later plan; B12 is outside both.

## Decisions this plan fixes

The spec requires the B03 results but leaves the test vehicle and the replacement interlock open.

1. **Vehicle.** QEMU emulates no CIO2 or ImgU, and vimc does not exercise the IPU3 handler. A guest-only driver mirrors what the pinned `ipu3-cio2`, `ipu3-imgu`, `ov5693`, `ov8865` and `ov7251` drivers publish: names, entity functions, pads, link flags, capabilities and control sets. Sensor names, port order, control ranges and frame sizes are synthetic until an approved passive inventory of the exact Book 2 exists. A stock libcamera run against the same graph is the sensitivity control.
2. **Interlock: pin through open and use.** Re-registration restarts `topology_version` at 0 ([mc-device.c][k-mc-reset], [mc-entity.c][k-gobj]), and unregistering a media device frees its minor while old descriptors stay open ([mc-devnode.c][k-devnode-unreg]). So the device number, device info and version cannot detect a replacement. Each kernfs node id is unique within a boot ([dir.c][k-kernfs-id], [kernfs.h][k-kernfs-ino]), so a node's identity is the inode of `/sys/dev/char/<major>:<minor>`. Every open is bracketed: the inode must match before the open, the descriptor's `st_rdev` must match, and the inode must match after; otherwise the descriptor closes before any ioctl. Effects use only those descriptors and reserved entity ids. A stale media descriptor gets `-EIO` ([mc-devnode.c][k-devnode-eio]), a stale V4L2 one `-ENODEV` ([v4l2-dev.c][k-v4l2-enodev]), and entity ids never repeat within a registration ([mc-entity.c][k-gobj]). The gate rereads topology and identities before and after each effect: a change before refuses, a change after holds. The bracket assumes opens have no effect, which holds for these pinned drivers. Video nodes use `v4l2_fh_open` ([ipu3-cio2.c][k-cio2-open], [ipu3-v4l2.c][k-imgu-fh]). Subdev opens initialize only per-file state or have no hook ([ipu3-cio2.c][k-cio2-state], [ipu3-v4l2.c][k-imgu-open], [ov7251.c][k-ov7251-ops]). Media opens reach no driver ([mc-device.c][k-mc-open]). A driver with open side effects needs a different interlock.
3. **Front-only handler.** Stock [`match()`][c-match] requests a disable for every mutable link of both media devices, and [registration][c-register] opens both ImgUs. It then walks the ports until two cameras register. For each port, [`CIO2Device::init`][c-cio2-init] opens the sensor, clears flips ([camera_sensor_legacy.cpp][c-flips]), writes the test pattern ([camera_sensor_legacy.cpp][c-pattern]) and enables the link before checking the format. If the IR sensor precedes the second RGB sensor, RGB discovery writes it and enables its link. The lab handler never calls `disableLinks()`, initializes only the reserved ImgU and port, and registers one camera.
4. **Observer.** The simulated driver logs subdev and video opens and releases, control set attempts from `try_ctrl`, changed links from `link_notify`, and subdev format and selection sets. The core calls `try_ctrl` on every set before testing for a change ([v4l2-ctrls-core.c][k-try-ctrl]); unchanged link requests return before any driver hook ([mc-entity.c][k-setup-link]). Each record carries a sequence number, process and graph instance. Media opens reach no driver and are not logged.
5. **IPA route.** The lab factory decides once at the [branch][c-factory], constructs only the threaded proxy and has no isolated branch. A preflight with the same predicate runs before the first discovery effect. [Isolation is forced][c-signature] by `ipa.force_isolation`, which a [configuration file][c-config-files] or an [environment override][c-overrides] can set; both refuse.

## Global Constraints

- No physical device passthrough, installed boot change, host cgroup/BPF/kernel mutation, live Book 2, real camera node, strobe, PAM, daemon, model, account, TPM or keyring. No host `sudo`, system-wide installation or access to another worktree.
- The simulated driver and its test-only controls build only into the disposable guest kernel, from a private worktree of the pinned Linux tree, never for the host. Its source uses `SPDX-License-Identifier: GPL-2.0-or-later`.
- libcamera comes from a private worktree of the pinned tag (`git describe --exact-match` prints `v0.8.0`). The stock image is unpatched; the lab image adds only the files in `libcamera/` and one patch. Both install only into staged roots.
- Copy runtime libraries only from installed host packages, recording package, version and SHA-256. Configure libcamera through a private `PKG_CONFIG_LIBDIR` exposing only `gnutls`, `yaml-0.1` and the `.pc` files they require; disable `udev`, `libdw`, `libunwind` and `tracing`. No network fetch during the build.
- QEMU keeps the fixed B01/B02 option vector except `-m 1024`, a 180 s wall timeout and `panic=-1 panic_on_warn=1 kasan.fault=panic` in `-append`. Case parameters come only from the runner's fixed table.
- The guest kernel keeps every B01/B02 setting except `MEDIA_SUPPORT` and adds media, debugfs, KASAN and lock proving. `MODULES`, `DEVMEM`, `DEVPORT`, `IO_URING`, `X86_X32_ABI` and `DEVTMPFS_MOUNT` stay off. Any kernel `BUG`, `WARNING`, KASAN or lockdep report refuses the run.
- No frames, streaming, configuration, start or IR emitter. The worker only discovers, waits and stops.
- B03 passes only for the simulated graph in this guest. Nothing follows about the real Book 2 graph, the real drivers' effects, timing, teardown, optical state or authentication. Unclear, skipped or failed required checks are refusal, not a partial pass.
- B01/B02 receipts stay green after the shared policy refactor.
- Keep commits local, signed with `git commit -S -s` and DCO only. No AI attribution, issue, PR, publication or reporter contact.

## Review Focus

- `link_state_without_version`: a link flag changes but `topology_version` does not, so a version-only guard admits. Task 3 `graph-ir-link-enabled` must refuse with no worker effect.
- `same_number_replacement`: a replacement keeps device number, device info and version; only the kernfs inode differs. Task 4 `replace-before-discovery` must record both facts and show no worker record.
- `silent_observer`: a log that records nothing makes every refusal look clean. Task 2 `stock-baseline` must show the stock effects; Task 1 verifier tests reject gaps, drops and empty logs.
- `partial_effects_released`: a refusal after listed effects is treated as clean and the schedule continues. Task 4 requires `HOLD` and `SECOND_BACKEND_BLOCKED unknown` for `effect-unlisted-link` and `generation-during-discovery`.
- `isolation_by_configuration`: a configuration file, not the environment, forces isolation. Task 5 `ipa-force-isolation` must refuse before any proxy exists.

## Files

New files live in `scripts/research/1379-lab-discovery/` unless a path says otherwise.

| File | Responsibility |
| --- | --- |
| `kernel/book2-lab-sim/{book2_lab_sim.c,Kconfig,Makefile}` | Guest-only simulated graph, effect log and test controls. |
| `kernel-discovery.config`, `build_discovery_guest.sh` | Kernel, stock and lab libcamera, guest binaries and both images from verified inputs. |
| `lab/discovery_requests.h` | Discovery ioctl requests and their class, shared by the seccomp filter and the gate. |
| `lab/lab_contract.{h,cpp}`, `lab/test_lab_contract.cpp` | Contract and reservation format, topology snapshot, graph and effect checks shared by supervisor and libcamera; host tests. |
| `contract/front.contract`, `contract/expected-effects.txt` | Reviewed contract for the simulated graph and exact effect records per case. |
| `libcamera/lab_guard.{h,cpp}`, `libcamera/book2-lab.patch` | Open bracket, ioctl gate, IPA route guard and front-only IPU3 handler. |
| `guest/discovery_supervisor.cpp`, `guest/discovery_worker.cpp`, `guest/ir_stub.c` | PID 1 supervisor, libcamera worker and stand-in second backend. |
| `run_discovery.py`, `test_run_discovery.py`, `README.md` | Bounded launch, receipt and effect verification, reproduction. |
| `scripts/research/1379-lab-boot/guest/{cgroup_device.c,device_policy.c,lab.h}`, `scripts/research/1379-lab-boot/build_guest.sh` | Cgroup device rules split out of the B02 policy code without behavior change. |

Commands run from the worktree root. `D=scripts/research/1379-lab-discovery`, `B=scripts/research/1379-lab-boot`, `SCRATCH` is a fresh absolute `/tmp/opencode` directory, `LINUX` and `LIBCAMERA` are clean checkouts at the pins and `MESON` is the Stage A Meson 1.9.1. Test-only perturbations exist only in the guest supervisor and simulated driver. Before building, require 8 GiB free under `/tmp/opencode`; otherwise remove only reproducible outputs of completed stages whose evidence is archived, and record what was removed.

### Task 1: Simulated IPU3 graph and guest harness

**Files:** `kernel/book2-lab-sim/*`, `kernel-discovery.config`, `build_discovery_guest.sh`, `guest/discovery_supervisor.cpp`, `contract/front.contract`, `run_discovery.py`, `test_run_discovery.py`, `README.md`; in `$B`, `guest/{cgroup_device.c,device_policy.c,lab.h}` and `build_guest.sh`.

**Interfaces:**
- `bash "$D/build_discovery_guest.sh" "$LINUX" "$LIBCAMERA" "$SCRATCH/build"` writes `bzImage`, `lab.cpio`, `guest.config`, `inputs.sha256` and `build.sha256`. Task 2 adds `stock.cpio`.
- `python3 -B "$D/run_discovery.py" BUILD NEW_RECEIPT CASE` runs one boot. `check_discovery(text: str, nonce: str, case: str, returncode: int) -> Receipt`, where `Receipt.events` and `Receipt.effects` are `tuple[str, ...]`.
- Serial lines are `BOOK2_DISCOVERY_V1 <nonce> <event>`. An effect event is `EFFECT <seq> <instance> <worker|supervisor|other> <kind> <args>`; the dump ends `EFFECTS_END <count> dropped=<n>`. Kinds: `open|release <node>`, `ctrl <node> <id>=<value>`, `link <src>:<pad> <sink>:<pad> <flags>`, `fmt <node> <pad> <active|try> <code> <w>x<h>`, `sel <node> <pad> <target> <rect>`, `control <command>`. Node names write spaces as `_`; ids, codes and flags are hex.
- Contract graph records, one per line: `BOOK2_LAB_CONTRACT_V1`; `media <cio2|imgu> <driver> <model>`; `entity <role> <name> <function> <sink|source>...`; `node <entity> <video|subdev>`; `link <role> <src>:<pad> <sink>:<pad> <flags>`.
- Root-only debugfs directory `book2_lab_sim/`: `effects` and `open_counts` to read, `control` to write `replace`, `add-entity`, `add-media` or `bump-on-front-fmt`. Kernel parameter `book2_lab_sim.front_port=` (default 0).
- `int attach_device_rules(int cgroup_fd, const struct device_rule *rules, size_t count)` with `struct device_rule { unsigned int major, minor; short access; }`. `attach_device_filter` becomes a wrapper with unchanged B02 results.

- [ ] **Write verifier tests and RED.** `test_zero_exit_without_receipt_fails`, `test_kernel_warning_kasan_or_lockdep_fails`, `test_effect_gap_duplicate_or_drop_fails`, `test_effect_from_other_process_fails`, `test_unsafe_launch_options_are_absent`, `test_case_parameters_come_from_fixed_table`. Run `python3 -B -m unittest discover -s "$D" -p test_run_discovery.py` against a stub verifier; all must fail.
- [ ] **Implement the simulated graph.** Mirror the pinned sources. Media device `ipu3-cio2` holds `ipu3-csi2 0..3` (`MEDIA_ENT_F_VID_IF_BRIDGE`, sink pad 0, source pad 1) and video nodes `ipu3-cio2 0..3` (`VIDEO_CAPTURE_MPLANE | STREAMING`); sensor links start with flags 0 and receiver-to-video links are `ENABLED | IMMUTABLE` ([links][k-cio2-links], [nodes][k-cio2-nodes]). Media device `ipu3-imgu` holds `ipu3-imgu 0..1` (`MEDIA_ENT_F_PROC_VIDEO_STATISTICS`, five pads) with nodes `input`, `parameters`, `output`, `viewfinder` and `3a stat`; take caps and flags from [ipu3-v4l2.c][k-imgu-nodes], [ipu3-v4l2.c][k-imgu-links] and [ipu3.c][k-imgu-defaults]. Sensors: `ov5693 2-0036` (`SBGGR10_1X10`, 2592x1944) front on port 0, `ov7251 4-0060` (`Y10_1X10`, 640x480) IR on port 1, `ov8865 3-0010` (`SBGGR10_1X10`, 3264x2448) rear on port 2. This order lets the [stock loop][c-register] reach the IR sensor. Give each sensor its pinned driver's control ids and read-only flags plus the selection targets libcamera requires. Give each sensor, receiver group and ImgU its own platform parent so sensor ids stay unique. Video nodes answer only `QUERYCAP`, `ENUM_FMT` and `G_FMT`; there are no buffers. Keep 8192 records with a sticky drop counter. `replace` re-registers both media devices. `add-entity` adds an unlinked entity to `ipu3-cio2`. `add-media` registers a third media device. `bump-on-front-fmt` adds an entity during the next active front sensor format set, outside the graph mutex.
- [ ] **Build verified inputs.** Create `git -C "$LINUX" worktree add --detach "$SCRATCH/linux" 988117cc1bb17338c586a4e21ade88b5397eac33`. Copy the driver to `drivers/media/test-drivers/book2-lab-sim/`, add one `source` line to that directory's `Kconfig` and one `obj-` line to its `Makefile`. `git status --porcelain` must show exactly those two files and the new directory. Merge `kernel-discovery.config` and verify each requested line as `$B/build_guest.sh` does; the driver builds with `ccflags-y := -Werror`. Build the supervisor with `g++ -std=c++20 -static -O2 -Wall -Wextra -Werror` against the exported UAPI, linking `$B/guest/cgroup_device.c` built as strict C17, and require no `INTERP` or `NEEDED`. The image holds `/init` (the supervisor), its directories and `/dev/console`; PID 1 mounts devtmpfs on `/dev` only after attaching the deny filter.
- [ ] **Implement cases `topology` and `sim-controls`.** Both start as B01 does: fresh mounts, then deny attached and verified before inventory. They emit `DENY_ATTACHED`, mount devtmpfs, then emit `PRE_INVENTORY_DENIED` after an `EPERM` open of the first media node. Next come a sysfs-only inventory and `INTENT_RECORDED`. PID 1 then briefly enters a scope admitting only the two media nodes, reads topology, closes them and returns to quarantine. `topology` prints the topology; the host compares it with the graph records of `front.contract`. `sim-controls` must log `REPLACED same_devt=1 same_version=1 new_inode=1`, `VERSION_BUMPED`, `EXTRA_MEDIA_PRESENT` and `SIM_CONTROLS_PASS` with contiguous records.
- [ ] **Run GREEN and commit.** Run the unit tests, both cases, and the five B01/B02 cases on a rebuilt B02 image. Commit `test(research): simulate the Book 2 IPU3 graph in the guest`.

### Task 2: Stock libcamera baseline in the guest

**Files:** `build_discovery_guest.sh`, `lab/discovery_requests.h`, `guest/discovery_worker.cpp`, `guest/discovery_supervisor.cpp`, `contract/expected-effects.txt`, `run_discovery.py`, `test_run_discovery.py`, `README.md`.

**Interfaces:**
- The worker's environment is only `LC_ALL=C`. Fd 3 is the guard verdict pipe, fd 4 the supervisor control pipe and fd 5 its report pipe. The worker installs its second seccomp stage, writes `READY`, waits for `go` and runs `CameraManager::start()`. It reports `CAMERAS <n> <id>...`, waits for `release`, stops and exits 0. The supervisor bounds each wait.
- `pid_t launch_worker(const WorkerSpec &spec)` gives each granted node to guest UID 65532 with mode `0600`, and the cgroup admits only those device numbers; other nodes stay root-only and denied. It then forks and enters the worker cgroup. It closes descriptors above 5, sets guest UID/GID 65532 with no supplementary groups, sets no new privileges, installs the first seccomp stage and executes the worker. The first stage denies by default, with these exceptions:
  - `ioctl` is allowed only for the requests in `lab/discovery_requests.h`.
  - `socket`, `socketpair`, `sendmsg` and `recvmsg` return `EPERM`.
  - `fork`, `vfork` and `clone` without `CLONE_THREAD` kill the process.
  - `clone3` returns `ENOSYS`.

  The second stage kills on `execve` and `execveat`. The supervisor sends `go` only after `/proc/<pid>/status` shows `Seccomp_filters: 2`.
- `contract/expected-effects.txt` has one `[case]` section per case holding exact `EFFECT` lines without sequence numbers. Opens and effects compare in order; releases after `release` compare as a multiset.

- [ ] **Write the baseline expectation and RED.** Derive `[stock-baseline]` from the pinned call path:
  - The supervisor enables the IR link; the worker then [disables it][c-disable].
  - Both ImgU subdevs and all ten nodes [open][c-imgu-init].
  - All three sensors open with flip attempts; only `ov5693` and `ov8865` get test-pattern attempts ([properties][c-props]).
  - All three sensor links are enabled, and the IR sensor releases after its format check fails.
  - Both RGB sensors get an [active format set][c-loadipa].

  Add `test_baseline_requires_ir_sensor_effects` and `test_positive_case_without_effects_fails`, then run them RED.
- [ ] **Build stock libcamera.** Use a worktree at `v0.8.0`. Run `meson setup` with `--prefix=/usr --buildtype=debugoptimized -Dpipelines=ipu3 -Dipas=ipu3 -Dudev=disabled -Dlibdw=disabled -Dlibunwind=disabled -Dtracing=disabled`, with every application, binding, test and documentation option disabled. Install to `DESTDIR` with `--strip`. Then require all of these:
  - `libcamera.so.0.8` has no `RUNPATH` or `RPATH` ([installed check][c-installed]).
  - No `NEEDED` entry names `libudev`, `libdw`, `libunwind` or `lttng`.
  - A `.sign` file sits beside `ipa_ipu3.so`.
  - The Meson summary names gnutls ([meson.build][c-crypto]).

  Resolve the library closure from `readelf -d` in `/usr/lib` without executing anything; fail on unresolved names. Build the worker against the staged root. `stock.cpio` holds the supervisor, worker, staged libcamera, closure and `/lib64/ld-linux-x86-64.so.2`.
- [ ] **Implement `stock-baseline`.** Grant every simulated node, enable the IR link from the supervisor, run the stock worker and compare the whole log with the section. The case passes with `STOCK_EFFECTS_OBSERVED` and a `CAMERAS 2` report. It validates the observer only and can never pass on the lab image.
- [ ] **Run GREEN and commit.** Run the unit tests, `stock-baseline` and the Task 1 cases. Commit `test(research): record stock libcamera discovery effects in the guest`.

### Task 3: Reservation contract and front-only lab handler

**Files:** `lab/lab_contract.{h,cpp}`, `lab/test_lab_contract.cpp`, `lab/discovery_requests.h`, `contract/front.contract`, `contract/expected-effects.txt`, `libcamera/lab_guard.{h,cpp}`, `libcamera/book2-lab.patch`, `guest/discovery_supervisor.cpp`, `build_discovery_guest.sh`, `run_discovery.py`, `test_run_discovery.py`. `lab.cpio` gains the lab libcamera build and worker.

**Interfaces** (namespace `book2lab`, shared by supervisor and libcamera):
- Contract records added to the Task 1 graph:
  - `front <sensor> <csi2> <video> <imgu>`
  - `grant <entity|media-role>`
  - `effect link <role> <src>:<pad> <sink>:<pad> <flags>`
  - `effect ctrl <entity> <id>=<value>[,<id>=<value>]`
  - `effect fmt <entity> <pad> <code> <w>x<h>`
  - `ipa <path> <pipeline> <name> <version>`

  A reservation starts `BOOK2_LAB_RESERVATION_V1 <nonce>`, repeats the contract and adds these bindings:
  - `bind-media <role> <major>:<minor> <inode> <topology_version> <path>`
  - `bind-node <entity> <id> <major>:<minor> <inode> <path>`
  - `bind-ipa <path> <dev> <inode> <size> <sha256>`

  Unknown, duplicate or missing records refuse. `Node` is a parsed `bind-node`; `Role` is `cio2` or `imgu`.
- Shared functions:
  - `int read_snapshot(int media_fd, Snapshot *out)`
  - `std::optional<Reservation> parse_reservation(std::string_view text)`
  - `std::string serialize(const Reservation &r)`
  - `Verdict compare_graph(const Reservation &r, Role role, const Snapshot &s)`
  - `Verdict match_effect(const Reservation &r, const Effect &e, EffectLedger *used)`
  - `Verdict check_environment(const char *const *envp, const std::vector<std::string> &config_paths)`

  `Verdict` is `{bool ok; std::string reason;}`. The reasons are `device-info`, `version`, `entity-set`, `pad-set`, `link-set`, `link-state`, `interface`, `front-binding`, `extra-media`, `unlisted-effect`, `effect-reused`, `environment` and `configuration`.
- libcamera side, `lab_guard.h`, namespace `libcamera::book2lab`:
  - `Guard &guard()` loads `/run/book2-lab/reservation` once and latches refusal if it is absent or invalid.
  - `Verdict admitDiscovery(MediaDevice &cio2, MediaDevice &imgu)`
  - `int admitOpen(const std::string &path, int flags, const Node **node)` returns a descriptor or `-EPERM`.
  - `int admitIoctl(const Node *node, unsigned long request, const void *arg)`
  - `int admitMediaIoctl(const MediaDevice &media, unsigned long request, const void *arg)`
  - `Verdict finalCheck()`

  After a hold latch every effect refuses. The guard writes one `VERDICT <admit|refuse|hold> <reason>` line to fd 3. The line is only a label: outcomes rest on the driver log, process state and inodes.

- [ ] **Write host tests and RED.** In `test_lab_contract.cpp`: `link_state_change_without_version_change_refuses`, `extra_entity_refuses`, `front_binding_on_wrong_port_refuses`, `extra_media_device_refuses`, `effect_reused_refuses`, `ctrl_set_with_extra_control_refuses`, `unknown_or_duplicate_record_refuses`, `libcamera_environment_or_configuration_refuses`. Build with `g++ -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined`, run them and expect failures. Add `[lab-front]` and the negative sections to `expected-effects.txt`; the stock image must fail `lab-front`.
- [ ] **Write the contract.** `front.contract` binds the front role to `ov5693 2-0036`, `ipu3-csi2 0`, `ipu3-cio2 0` and `ipu3-imgu 1`, so a handler that assumes ImgU 0 fails.
  - Grants: both media nodes; the front sensor, receiver and video node; `ipu3-imgu 1` and its five nodes.
  - Effects: one flip set `HFLIP=0,VFLIP=0`, one `TEST_PATTERN=0`, one front link enable and one active `SBGGR10_1X10` 2592x1944 format on pad 0.
  - Nothing for the rear or IR sensor, other ports or ImgU 0.

  The `[lab-front]` section lists, in order:
  1. The six ImgU 1 opens.
  2. The front sensor open.
  3. The control attempts `HFLIP=0`, `VFLIP=0` and `TEST_PATTERN=0`.
  4. The link.
  5. The receiver and video opens.
  6. The format.
- [ ] **Implement the guard and handler.** Patch `MediaDevice::populate` to keep its topology version, and `MediaDevice::open` and `V4L2Device::open` to call `admitOpen`. Route every media ioctl site and [`V4L2Device::ioctl`][c-v4l2-ioctl] through the gate. The gate classifies requests as follows:
  - Read-only requests pass: `QUERYCAP`, `QUERY_EXT_CTRL`, `QUERYMENU`, `G_EXT_CTRLS`, `ENUM_FMT`, `ENUM_FRAMESIZES`, `G_FMT` and `G_SELECTION`; subdev `QUERYCAP`, `ENUM_MBUS_CODE`, `ENUM_FRAME_SIZE`, `G_FMT`, `G_SELECTION` and `G_ROUTING`; media `DEVICE_INFO`, `G_TOPOLOGY` and `ENUM_ENTITIES`.
  - Subdev `S_CLIENT_CAP` and `TRY` formats are per file and pass.
  - `S_EXT_CTRLS`, active subdev `S_FMT` and `SETUP_LINK` must each match an unused listed effect.
  - Everything else refuses.

  Replace the rest of `PipelineHandlerIPU3::match()` after both `acquireMediaDevice` calls with this sequence:
  1. `admitDiscovery` requires fresh snapshots of both devices to equal the reservation and the populate version, and no unreserved media device in sysfs.
  2. No `disableLinks()` call.
  3. `init` runs for the reserved ImgU index only.
  4. `CIO2Device::init` runs for the reserved port only.
  5. `loadIPA` runs.
  6. `finalCheck` runs before `registerCamera`.
  7. Exactly one camera registers.
- [ ] **Implement the supervisor reservation and cases.** Parse the contract and bind it to the inventory. Write the reservation as mode `0444` in a root-owned `0755` directory. Grant only the listed nodes and launch the lab worker with no retained device descriptor. Each case's expected outcome:
  - `lab-front` passes with exactly the listed effects and `CAMERAS 1`.
  - These three each refuse with no worker effect, after the supervisor changes the graph post-reservation:
    - `graph-ir-link-enabled`: the supervisor enables the IR link.
    - `graph-extra-entity`: the supervisor runs `add-entity`.
    - `hotplug-extra-media`: the supervisor runs `add-media`.
  - `sim-port-variant` boots with `book2_lab_sim.front_port=3`; the supervisor refuses before reserving and starts no worker.
  - `effect-unlisted-link` drops the link effect from the reservation and refuses at the link, after the listed sensor effects.
- [ ] **Run GREEN and commit.** Run the host C++ and Python tests, the six cases, `stock-baseline` and the Task 1 cases. Commit `test(research): bound Book 2 discovery to a reserved front graph`.

### Task 4: Identity interlock, generation changes and next-phase gating

**Files:** `libcamera/lab_guard.cpp`, `guest/discovery_supervisor.cpp`, `guest/ir_stub.c`, `contract/expected-effects.txt`, `build_discovery_guest.sh`, `run_discovery.py`, `test_run_discovery.py`.

**Interfaces:**
- `int openBracketed(const Node &node, const std::string &path, int flags)` runs these checks in order:
  1. Stat `/sys/dev/char/<major>:<minor>` and require the bound inode.
  2. Open the path.
  3. Require the descriptor's `fstat` `st_rdev` to match.
  4. Stat again and require the bound inode.

  Any mismatch closes the descriptor, latches refusal and returns `-EPERM`. `admitOpen` uses it for every open.
- `Verdict recheck()` rereads both topologies and every bound inode. The gate calls it before each listed effect, where a mismatch refuses, and after it, where a mismatch latches hold. `finalCheck` calls it again.
- `enum class Ownership { Known, RefusedClean, Unknown }` and `Ownership classify_attempt(const AttemptEvidence &e)` in the supervisor.
  - `Known` needs all of these:
    - The worker exited 0 within bounds.
    - Every `open_counts` entry is zero, with no drops.
    - Worker records equal the case section.
    - Inodes and versions are unchanged.
    - Link state equals the reservation plus the listed effects.
  - `RefusedClean` needs the same, but the worker has no record beyond opens and releases.
  - Anything else is `Unknown`.
- `/lab/ir-stub` touches no device and prints `IR_STUB_RAN`. The supervisor starts it only for `Known`.

- [ ] **Write tests and RED.** Add `test_release_after_worker_effects_fails`, `test_second_backend_after_hold_fails` and `test_replacement_receipt_requires_equal_number_and_new_inode`. Add sections `[replace-before-discovery]`, `[generation-during-discovery]` and `[replace-after-discovery]`. They must fail on the Task 3 image.
- [ ] **Implement the bracket and rechecks** as specified in the interfaces; refusing before an open leaves no worker record.
- [ ] **Implement the supervisor outcome.**
  - `Known` emits `OWNER_RELEASED`, `SECOND_BACKEND_STARTED` and `IR_STUB_RAN`.
  - `RefusedClean` emits `RELEASED_AFTER_REFUSAL` and `SECOND_BACKEND_BLOCKED refused`.
  - `Unknown` emits `HOLD <reason>` and `SECOND_BACKEND_BLOCKED unknown`, then powers off without another launch.
- [ ] **Add the generation cases.**
  - `replace-before-discovery`: the supervisor runs `replace` after reserving and logs `REPLACED same_devt=1 same_version=1 new_inode=1`. The worker refuses at its first bracket. The reserved objects are gone, so the outcome is `Unknown`.
  - `generation-during-discovery`: arms `bump-on-front-fmt`. The listed effects through the format set appear, then hold, and no camera registers. Outcome: `Unknown`.
  - `replace-after-discovery`: the supervisor runs `replace` after the worker reports and before `release`. Outcome: `Unknown`.

  Existing cases change outcome. `effect-unlisted-link` and the three Task 3 graph cases become `Unknown`, because the graph no longer matches the reservation. `sim-port-variant` ends `REFUSED_BEFORE_RESERVATION` and `SECOND_BACKEND_BLOCKED refused`. `lab-front` becomes `Known`. Only Task 5's refusals, which leave the graph as reserved, end `RefusedClean`.
- [ ] **Run GREEN and commit.** Run all tests and every B03 case so far. Commit `test(research): refuse replaced or changed Book 2 graphs before effects`.

### Task 5: Admit only the pinned threaded IPA route

**Files:** `libcamera/lab_guard.{h,cpp}`, `libcamera/book2-lab.patch`, `lab/lab_contract.{h,cpp}`, `lab/test_lab_contract.cpp`, `contract/front.contract`, `guest/discovery_supervisor.cpp`, `run_discovery.py`, `test_run_discovery.py`.

**Interfaces:**
- `bool IPAManager::admitThreadedRoute(IPAModule *m)` computes `isSignatureValid(m)` once and requires all of these:
  - The result is true.
  - The module path, `stat` device, inode and size equal `bind-ipa`.
  - The gnutls SHA-256 of the module bytes equals `bind-ipa`.
  - `info()` reports pipeline name `ipu3`, module name `ipu3` and pipeline version 1.
  - `check_environment` passes.

  The lab `createIPA` calls it after `module()` and then constructs only `T::Threaded`; the patched template never names `T::Isolated`.
- `bool IPAManager::labPreflight(const char *name, uint32_t minVersion, uint32_t maxVersion)` runs the same check without constructing anything. The lab IPU3 `match()` calls it immediately after `admitDiscovery`, before any effect.
- The supervisor hashes the module and writes `bind-ipa`. After `CAMERAS`, it requires the bound device and inode in `/proc/<worker>/maps` and a live worker showing `Seccomp_filters: 2`, then emits `IPA_ROUTE threaded <sha256>` or `IPA_NOT_MAPPED`.

- [ ] **Write tests and RED.** Host tests:
  - `env_override_variants_refuse`: each of the six [overrides][c-overrides] plus `LIBCAMERA_IPU3_TUNING_FILE`.
  - `configuration_file_refuses`.
  - `isolated_branch_absent_from_lab_factory`, which reads the patched header.

  Add guest sections `[ipa-bad-signature]`, `[ipa-force-isolation]`, `[ipa-env-override]` and `[ipa-identity-mismatch]`, each with no worker effect. On the Task 4 image, `ipa-bad-signature` must fail: sensor effects appear, then the isolated proxy's process creation is killed.
- [ ] **Implement the route guard** as specified in the interfaces; on refusal `match()` returns false before `CIO2Device::init`.
- [ ] **Add the IPA cases.** Each test path runs after the reservation and before launch:
  - Corrupt one byte of `ipa_ipu3.so.sign`.
  - Write `/etc/libcamera/configuration.yaml` with `ipa: force_isolation: true`.
  - Start the worker with `LIBCAMERA_IPA_FORCE_ISOLATION=1`.
  - Replace the module with a byte-identical copy, which has a new inode.

  Each must end `RefusedClean` with `IPA_NOT_MAPPED` and a worker still alive at its report, so no process creation was killed. `lab-front` adds `IPA_ROUTE threaded <sha256>`.
- [ ] **Run GREEN and commit.** Run all tests and every B03 case. Commit `test(research): admit only the pinned threaded IPU3 IPA route`.

### Task 6: Verify the exact candidate and stop

**Files:** `README.md`, plus private evidence outside the source tree.

**Interfaces:** The packet records the signed source head, pins, host tool and package versions, `inputs.sha256`, `build.sha256`, the effective guest config, each case's serial receipt and verifier output, and host test logs. `B03 = passed` only when every case below passed twice from new receipt directories.

- [ ] **Rebuild and rerun.** Rebuild from verified inputs and run the host C++ and Python suites. Run these cases twice: `topology`, `sim-controls`, `stock-baseline`, `lab-front`, `graph-ir-link-enabled`, `graph-extra-entity`, `hotplug-extra-media`, `sim-port-variant`, `effect-unlisted-link`, `replace-before-discovery`, `generation-during-discovery`, `replace-after-discovery`, `ipa-bad-signature`, `ipa-force-isolation`, `ipa-env-override`, `ipa-identity-mismatch`. Then run the five B01/B02 cases. Also check:
  - `shellcheck`, strict C and C++ builds, and `-Werror` for the driver.
  - The docs gates: `python3 -B scripts/ci/sync-docs.py --check`, `python3 scripts/ci/test-sync-docs.py`, `python3 scripts/check-agents-md.py` and offline Lychee.
  - `grep -nP '\x{2014}'` on changed text.
  - The branch touches no workspace, product, package or CI path.
- [ ] **Self-review and independent review.** Review the trusted launch order, each refusal point against its trusted record, the stock-versus-lab difference and the README scope. Request one whole-branch review. Fix each confirmed finding with a failing check first, then rerun the affected cases.
- [ ] **Record and archive.** Write `RESULTS.md` under `/mnt/archledger-gp/artifacts/irlume/<date>-1379-discovery-proof/`. Archive it to pCloud with `--immutable` and verify with `rclone check --download`. Update the ledger, then commit `docs: record the Book 2 discovery guard proof scope` with `git commit -S -s`.
- [ ] **Stop after this slice.** B03 qualifies only the simulated graph in this guest. B04 through B11 need their own plan. No hardware, reporter contact or later stage follows from this result.

[spec]: ../specs/2026-11-28-embedded-book2-lab-boundary-design.md
[adr]: ../../architecture/adr/0042-embedded-book2-rgb-ir-class.md
[b02]: 2026-11-28-embedded-book2-dummy-boot.md
[k-kernfs-id]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/fs/kernfs/dir.c#L658-L681
[k-kernfs-ino]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/include/linux/kernfs.h#L352-L373
[k-mc-reset]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/mc/mc-device.c#L751
[k-mc-open]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/mc/mc-device.c#L48-L56
[k-gobj]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/mc/mc-entity.c#L151-L181
[k-devnode-unreg]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/mc/mc-devnode.c#L266-L287
[k-devnode-eio]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/mc/mc-devnode.c#L75-L115
[k-v4l2-enodev]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/v4l2-core/v4l2-dev.c#L385-L428
[k-setup-link]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/mc/mc-entity.c#L1310-L1333
[k-try-ctrl]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/v4l2-core/v4l2-ctrls-core.c#L2706-L2711
[k-cio2-open]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/pci/intel/ipu3/ipu3-cio2.c#L1165
[k-cio2-state]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/pci/intel/ipu3/ipu3-cio2.c#L1334-L1336
[k-cio2-links]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/pci/intel/ipu3/ipu3-cio2.c#L1406-L1416
[k-cio2-nodes]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/pci/intel/ipu3/ipu3-cio2.c#L1544-L1596
[k-imgu-open]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/staging/media/ipu3/ipu3-v4l2.c#L19-L49
[k-imgu-fh]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/staging/media/ipu3/ipu3-v4l2.c#L947
[k-imgu-nodes]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/staging/media/ipu3/ipu3-v4l2.c#L1057-L1113
[k-imgu-links]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/staging/media/ipu3/ipu3-v4l2.c#L1233-L1263
[k-imgu-defaults]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/staging/media/ipu3/ipu3.c#L464-L472
[k-ov7251-ops]: https://github.com/gregkh/linux/blob/988117cc1bb17338c586a4e21ade88b5397eac33/drivers/media/i2c/ov7251.c#L1474-L1476
[c-match]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/pipeline/ipu3/ipu3.cpp#L848-L898
[c-register]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/pipeline/ipu3/ipu3.cpp#L1040-L1079
[c-loadipa]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/pipeline/ipu3/ipu3.cpp#L1151-L1196
[c-cio2-init]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/pipeline/ipu3/cio2.cpp#L115-L175
[c-imgu-init]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/pipeline/ipu3/imgu.cpp#L333-L377
[c-flips]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/sensor/camera_sensor_legacy.cpp#L213-L221
[c-pattern]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/sensor/camera_sensor_legacy.cpp#L290-L301
[c-props]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/sensor/camera_sensor_properties.cpp#L485-L526
[c-disable]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/media_device.cpp#L463-L480
[c-v4l2-ioctl]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/v4l2_device.cpp#L534-L540
[c-factory]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/include/libcamera/internal/ipa_manager.h#L34-L55
[c-signature]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/ipa_manager.cpp#L289-L312
[c-overrides]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/global_configuration.cpp#L99-L123
[c-config-files]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/global_configuration.cpp#L155-L208
[c-installed]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/source_paths.cpp#L40-L52
[c-crypto]: https://github.com/libcamera-org/libcamera/blob/df8e348d64b4932a0676256ed24f0da3ee9438bc/src/libcamera/meson.build#L84-L106
