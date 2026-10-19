# NPU provider selection and reporting

Native NPU loading is closed. No installation/launch profile is admitted, no
setting bypasses the refusal before OpenVINO native entry, and the `CERTIFIED`
table is empty. CPU authentication remains authoritative. Provider selection,
identity matching and reporting are groundwork for later admission; they do
not enable generic NPU runtime support.

Upstream distributions, distro packages and administrator-installed source
runtimes follow the same rules. `intel-npu-stack` is an optional reference
installation; its package name grants no permission. The default-off `npu`
build feature does not bypass loading admission or model certification.

## Recognizer device selection

`recognizer_device` in `/etc/irlume/settings.conf` (`IRLUME_RECOGNIZER_DEVICE`
on the daemon overrides it) names the recognizer's intended device: `auto`
(the default), `cpu`, `npu` or `gpu` (#1053). The selection never lowers a
gate:

- `auto` ranks certified devices. No accelerator placement is admitted and
  certified today, so `auto` keeps the recognizer on CPU, exactly the
  switch-gated behavior.
- `cpu` keeps every probe on the CPU reference and skips NPU discovery and
  compile; the placement reason names the selection.
- `npu` attempts NPU placement under the same admission and certification
  gates; the separate `npu`/`IRLUME_NPU` kill switch still wins.
- `gpu` is accepted and reported, but no build admits GPU placement yet; the
  recognizer stays on CPU with that reason.

An IR adapter keeps the recognizer on CPU whatever the selection (ADR-0022
§2). An empty, unknown, duplicated or non-UTF-8 value, or an unreadable
`settings.conf`, is a journal warning and resolves to `auto`; authentication
never fails over the device preference. The selection joins the same single
startup settings snapshot as both accelerator switches and the provider
selection, and a restart applies a change.

The GPU has its own kill switch beside the selection (ADR-0033 section 8):
`gpu` in `/etc/irlume/settings.conf` and `IRLUME_GPU` on the daemon.
An absent source leaves admission and certification to decide. An off,
empty, malformed, non-UTF-8, duplicate or unreadable source disables GPU
use; either disabling source wins, including against an enabling value
from the other source. Both default and accelerator builds report the
GPU-disabled reason from the governing startup snapshot. The NPU-named
keys never leak into it.

Root and ordinary status callers receive these fixed public selection and
switch reasons. Native provider error text remains privileged; ordinary
callers receive its categorical projection.

GPU groundwork ships behind the same closed loading admission as the NPU
(ADR-0033 sections 2 to 4): discovery refuses before `dlopen`, a system
exposing more than one GPU refuses placement until a reviewed rule selects
one device. The identity observation is the complete ADR-0033 section 3
set: runtime and GPU plugin builds (`Core::versions("GPU")`),
plugin-reported name, capabilities, architecture, execution units,
memory, and the provider endpoint, plus the loaded GuC/HuC firmware.
Firmware reads walk every tile and GT, reject unreadable or conflicting
reports, and allow xe's documented GuC-only GTs only alongside a complete
agreeing pair. The plugin's `DEVICE_PCI_INFO` is parsed and must bind
exactly one render node whose sysfs address and `vendor`/`device`
attributes (`/sys/class/drm/renderD*/device`) match it; the firmware
belongs to that node. The loader family the plugin resolved (`libOpenCL`
or `libze_loader`, from `/proc/self/maps`) and the fixed compile
configuration `batch=1;PERFORMANCE_HINT=LATENCY;INFERENCE_PRECISION_HINT=f16`
are identity fields. Every native library the enumeration mapped is
hashed through one open file whose inode is kept, under ADR-0022's
inode discipline: the whole file-backed executable inventory (minus the
process executable, as the NPU execution inventory excludes it) plus
the IR and ONNX frontends beside the core, because ICD enumeration maps
foreign ICD libraries (a Mesa Rusticl ICD ran in the measured
processes). `GPU_DRIVER_VERSION` is never read: reading it through the
C API kills the process on the measured 2026.2.1 builds, so driver
identity comes from the hashed mapped-library manifest.

This observation cannot key certification; the loading-admission and
certification gates decide. The ignored `gpu_hw_*` tests collect the
evidence. `gpu_hw_identity_binds_plugin_render_node_and_libraries` runs
as root (debugfs joins the identity) and checks the binding, firmware,
loader family and manifest on a real GPU;
`gpu_hw_compile_parity_and_retirement_under_the_fixed_configuration`
compiles the recognizer on `GPU.0` under the fixed configuration,
requires `EXECUTION_DEVICES` to name the GPU, checks a parity canary
against the CPU reference and re-verifies the mapped libraries after
the compile (the retirement trigger). Run them like the `npu_hw_*` lane:

```sh
ulimit -c 0; cargo test -p irlume-vision --features npu --release \
  --lib -- --ignored gpu_hw_ --test-threads 1 --nocapture
```

`IRLUME_NPU_LIBRARY` selects a non-standard C API file, with
`LD_LIBRARY_PATH` pointing the test process at that runtime root. Both
lanes need the recognizer weights, from `IRLUME_NPU_TEST_MODELS`, an
installed `/usr/share/irlume/models` tree or the repository `models/`
tree. No certification table entry or loading profile exists.

### Explicit cache controls

Run all three cache-control processes from a root shell so GPU identity can
read debugfs. Set the selected provider/model and CPU/TFLite runtime variables
explicitly in that shell, as described in
[the identity research note](research/2026-10-11-gpu-identity.md); privilege
elevation may otherwise discard them. The recipe creates a private root-owned
directory for the miss and subsequent hit.

The opt-in cache control is outside the generic `gpu_hw_` sweep. Select it
separately with an explicit mode. Miss and hit require an existing absolute
UTF-8, caller-owned directory; the first miss refuses a nonempty directory
without clearing it. Retain that directory unchanged for the subsequent
automatic import. Bypass requires the directory variable to be unset.
Use the same provider, models and GPU configuration for all three processes.

```sh
ulimit -c 0
control=onnx::gpu_tests::gpu_groundwork_tests::gpu_cache_hw_model_cache_provenance_control
cache_dir="$(mktemp -d /tmp/irlume-gpu-cache.XXXXXX)"
IRLUME_GPU_CACHE_CONTROL_MODE=miss IRLUME_GPU_CACHE_CONTROL_DIR="$cache_dir" \
  cargo test -p irlume-vision --features npu --release --lib -- \
  --ignored --exact "$control" --test-threads 1 --nocapture
IRLUME_GPU_CACHE_CONTROL_MODE=hit IRLUME_GPU_CACHE_CONTROL_DIR="$cache_dir" \
  cargo test -p irlume-vision --features npu --release --lib -- \
  --ignored --exact "$control" --test-threads 1 --nocapture
env -u IRLUME_GPU_CACHE_CONTROL_DIR IRLUME_GPU_CACHE_CONTROL_MODE=bypass \
  cargo test -p irlume-vision --features npu --release --lib -- \
  --ignored --exact "$control" --test-threads 1 --nocapture
```

Require exact Core and compiled cache-directory readbacks, `NO` for miss
and bypass, and `YES` for the automatic import. These are separate-process
model-cache observations, not globally cold driver/compiler/OS state, a
performance result or full certification. Each control makes twelve
recognizer reference calls and counts zero endurance inferences; platform
identity warm-up is separate. The recipe makes no power transition and
does not supply the retained-model endurance or suspend protocols.
The historical campaign remains bound to its recorded source and binary
in [the cache receipt](research/2026-10-12-gpu-cache-provenance.md).

## Select a C API file

Automatic selection checks `libopenvino_c.so.2621` first, then
`libopenvino_c.so.2620`. For each soname, it checks these directories in order:

1. `/usr/lib64`
2. `/usr/lib/x86_64-linux-gnu`
3. `/usr/lib`
4. `/usr/local/lib64`
5. `/usr/local/lib/x86_64-linux-gnu`
6. `/usr/local/lib`

For another installation prefix, an administrator can select an absolute C API
file with `npu_library` in `/etc/irlume/settings.conf`. For example:

```ini
npu_library=/opt/my-openvino/runtime/lib/intel64/libopenvino_c.so.2621
```

`IRLUME_NPU_LIBRARY` on the daemon overrides that machine key. Selection is read
when the engine starts or rebuilds; restart the daemon after changing the
provider. Socket clients cannot select a provider.

The selected path and its canonical target are validated separately. The
canonical filename must be one of the accepted sonames or
`libopenvino_c.so.2026.2.0` / `libopenvino_c.so.2026.2.1`. The file and its
installation ancestors must be root-owned without group/other writes, and
symlinks must be root-owned with trusted targets and ancestors. The selected
alias remains the path in the legacy identity; the native loading path, once
admitted, uses the validated canonical endpoint.

An empty, relative, malformed, duplicate, unreadable or untrusted authoritative
selection keeps the recognizer on CPU. A malformed assignment to the exact
`npu_library` key is a refusal too. An explicit selection never falls through
to another provider. Automatic lookup advances only when a candidate is absent;
other lookup or validation failures stop it. User library-search environment
variables are not C API selection sources.

`IRLUME_NPU` and the separate `npu` machine key are kill switches. Either can
disable NPU use; an unreadable settings file or an empty, unknown or non-UTF-8
switch value disables it too. Recognized on values leave admission and
certification to decide. They cannot enable native loading.

## AppArmor provider paths

The daemon profiles grant read and executable-map access to OpenVINO and Level
Zero libraries in the six automatic search directories above, including their
versioned `openvino-*/` plugin directories. Cache writes and locks are limited
to `/var/cache/irlume/npu/`; accelerator discovery and firmware reads are
read-only, while the accelerator device node needs read and write access.
These rules prepare confinement for a future admitted runtime. They do not
establish loading admission, model certification or enforcing hardware coverage.

For an administrator-selected installation outside those directories, both
executable-path profiles include the optional
`/etc/apparmor.d/local/irlumed-npu` file. Keep this file root-owned without
group/other writes, and grant only the installation paths that need access.
For the `/opt/my-openvino/runtime/lib/intel64/` selection above, the following
rules cover the ancestor metadata checks and the C API file read before the
closed loading-admission gate:

```text
/opt/ r,
/opt/my-openvino/ r,
/opt/my-openvino/runtime/ r,
/opt/my-openvino/runtime/lib/ r,
/opt/my-openvino/runtime/lib/intel64/ r,
/opt/my-openvino/runtime/lib/intel64/libopenvino_c.so.2621 r,
/opt/my-openvino/runtime/lib/intel64/libopenvino_c.so.2026.2.1 r,
```

Adjust the file rules for the selected alias and its actual canonical target,
and add every ancestor if a symlink leads outside this prefix. Selecting a file
does not add AppArmor permission. Avoid a blanket `/opt/** mr,` or rules for
user-writable libraries. A future admitted layout also needs read and map rules
for its actual core, plugins, frontends, compiler, Level Zero and other native
dependencies; the C API example above covers only the current pre-load gate.

Parse the installed executable-path profile with
`apparmor_parser -QK /etc/apparmor.d/usr.bin.irlumed` (or
`usr.local.bin.irlumed` for a source installation), then reload that profile
with `apparmor_parser -r` and restart the daemon after a provider change.
Validate under enforce: the documented selection must reach the closed
loading-admission refusal, doctor must report CPU with unknown runtime
observation, and its audit interval must have no related AppArmor denial.
An admitted runtime additionally needs actual NPU identity, cache and marker
coverage under enforce before it is qualified.

## Loading admission remains future work

A loading profile must establish the launch environment, effective native
loader search paths, plugin/driver and compiler/frontend configuration, and
trust of every code-loading location. It must keep one provider for the
process lifetime and require a restart to change it. Root ownership of one
C API file and post-load content checks do not establish that contract.

The current gate refuses before `dlopen`, binding loading or device
enumeration. Opening it requires a separately reviewed implementation and
installation/launch conformance evidence. Enforcing AppArmor validation and
any additional layout-specific profile rules remain future work; selecting a
file supplies neither loading admission nor AppArmor enforcement evidence.

## Exact identity and portable qualification

The legacy path-based identity remains the authority for diagnostics, cache
directories, identity-specific markers and exact-key certification matching.
It retains the selected C API alias and original library-manifest membership.
The broader execution inventory is separate and does not rewrite that digest.

Portable qualification uses a versioned execution key (`irlume-npu-execution-v2`)
that omits directory prefixes but binds library basenames and content hashes,
hardware class, loaded firmware, runtime/plugin/driver/compiler versions and
the fixed compile configuration. Its inventory includes all observed absolute
file-backed executable mappings, including unrelated shared native code, plus
the known compiler loader, compiler, IR frontend and ONNX frontend hashed
before compilation.

The main executable, identified through `/proc/self/exe`, is excluded only
from the portable key to avoid a key that changes when its certification entry
is compiled into that executable. It remains in the mapped-file/inode checks.
If it cannot be identified in the inventory, inventory construction refuses.
Every observed shared native library remains keyed. Anonymous executable
mappings and non-executable data files are outside the execution inventory.
An executable file mapped later without an inventory entry, or a deleted or
replaced mapped file, refuses placement. The inventory is checked before and
after every inference, including parity. A failed check discards the result
and retires the model to CPU. These snapshots do not detect code loaded and
unloaded entirely between checks or replace pre-load admission.
Distinct paths with the same basename
make the portable key ambiguous and refuse portable qualification, even if
their bytes match.

Equivalent root-managed layouts can match the same portable key only when all
its fields match. Different bytes or execution settings do not inherit that
key. Exact entries retain exact matching; they do not become portable entries.
The model digest, CPU producer, consumer thresholds, decision fingerprint and
live CPU/NPU reference checks remain binding under
[ADR-0022](adr/0022-npu-inference-under-per-model-certification.md). The inventory
does not prove native dependency closure or replace loading admission. Real
installation relocation and model certification still need their own evidence.

## Read the status

`irlume doctor` and `irlume status --json` report separate engine facts:

| Doctor row | Status field | Meaning |
|---|---|---|
| `npu-runtime` | `recognizer.runtime_available` | `true` when discovery completed with a runtime/platform identity; `false` when discovery returned an error other than loading-admission refusal; omitted when unreported |
| `npu-qualification` | `recognizer.qualified` | When runtime availability is `true`, whether the recognizer is currently placed on NPU after qualification and placement checks; otherwise omitted |
| `recognizer-device` | `recognizer.device` | Current engine placement: `cpu` or `npu` |
| `recognizer-selection` | `recognizer.selection` | The governing device selection (`recognizer_device`): `auto`, `cpu`, `npu` or `gpu` |
| `npu-platform` | `recognizer.platform` | Exact platform identity digest, when discovery obtained one |

A loading-admission refusal reports no runtime observation. So does a failure
in cache or marker preparation before discovery runs. Successful discovery
retains its availability and platform digest if later marker cleanup, cache
setup or placement fails. Missing fields also allow older daemons to remain
decodable; absence never means a confirmed `false`. Doctor reports missing
runtime and qualification observations as `unknown`.

Engine placement is not a per-account guarantee. An authentication whose
matchable scans have missing or different CPU-producer tags uses CPU probes,
including legacy enrollments. Enrollment and self-tests use CPU. An IR adapter
also keeps the recognizer on CPU.

Apart from the fixed public selection/switch reasons above, non-root Health
replies use fixed CPU-fallback categories: discovery not reported, runtime
unavailable, or recognizer unavailable. Native error details
are available only to root peers; the privileged journal also retains bounded
detailed reasons. Consumers should use the fields, not parse reason text. See
[Machine API](MACHINE-API.md) for the reporting contract.
