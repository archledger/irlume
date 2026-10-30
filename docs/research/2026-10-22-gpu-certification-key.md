# GPU certification key: which mapped libraries can change the output

> **Superseded (2026-10-30):** GPU inference was removed by
> [ADR-0038](../adr/0038-remove-gpu-inference.md). The research, measurements and
> conclusions below remain historical evidence for that decision.

Research record for the ADR-0033 amendment of 2026-10-22 ("the
certification key binds the numerics set"), #1164. Analysis only: no
loading admission, no `CERTIFIED` entry, CPU authentication stays
authoritative. Archives live on the shared project store under
`artifacts/irlume/2026-10-22-1053-xe-decisions/research/` (`recert-cadence/`,
`recert-design/`), each with a `SHA256SUMS` manifest and a `SOURCES.txt`
naming every fetched file's URL, commit or tag and fetch time.

## The inventory

The UX5406S identity lane of 2026-10-22 (Fedora 44, kernel 7.2.11,
Arc 140V on `xe`, OpenVINO 2026.2.1 from the intel-npu-stack candidate
packages, intel-compute-runtime 26.35.39758.11, IGC 2.41.9, identity
`1f570994`) maps and hashes 37 libraries. Their roles, from `readelf -d`,
`rpm -q --requires`, the Fedora 44 spec files at the commits that built
the installed packages, and the upstream sources at the installed tags:

| Library (package) | Can change the GPU output | Why |
|---|---|---|
| `libopenvino.so` (openvino) | yes | graph transformations and host constant folding |
| `libopenvino_intel_gpu_plugin.so` (openvino-plugins) | yes | fusions, kernel selection, the embedded OpenCL C kernel sources and their build options, weight reorders |
| `libopenvino_onnx_frontend.so` | yes | converts the ONNX graph into OpenVINO operations |
| `libopenvino_c.so`, `libopenvino_ir_frontend.so` | no | C API shim; the IR frontend is asked first and declines a buffer input |
| `libigdrcl.so` (intel-opencl, compute runtime) | yes | runs the OpenCL C build (FCL, opencl-clang, IGC), passes the platform and workaround tables, loads and dispatches kernels |
| `libigc.so`, `libigdfcl.so` (intel-igc-libs) | yes | the GPU code generator and its frontend wrapper |
| `libopencl-clang.so` (intel-opencl-clang) | yes | runs clang and the SPIR-V translator on the kernel sources |
| `libclang-cpp.so`, `libLLVM.so` (llvm) | yes | the OpenCL C frontend and the optimizer IGC and opencl-clang link at run time |
| `libLLVMSPIRVLib.so` (spirv-llvm-translator) | yes | LLVM IR to SPIR-V and back, floating-point flags included |
| `libigdgmm.so` (intel-gmmlib) | not shown | surface layout and cache metadata, no arithmetic; a wrong layout would change every output |
| `libm.so.6` (glibc) | not for this model | host constant folding in LLVM and OpenVINO; glintr100 is Conv 103, PRelu 50, BatchNormalization 51, Add 49, Flatten 1, Gemm 1, whose folding needs only division and square root, both correctly rounded |
| `libc`, `ld-linux`, `libdl`, `libpthread`, `librt` (glibc), `libstdc++`, `libgcc_s` (gcc) | no | host runtime, loader, unwinder |
| `libtbb`, `libtbbmalloc` (tbb) | no | host threads; 41 cache-matrix processes gave identical outputs |
| `libz`, `libzstd`, `liblzma`, `libxml2`, `libtinfo`, `libedit`, `libffi` | no | lossless compression and dependencies pulled in by LLVM and libxml2 |
| `liblldCommon`, `liblldELF` (llvm) | no | used only when kernels carry debug information |
| `libSPIRV-Tools.so` (spirv-tools) | no | shader-dump disassembly only |
| `libOpenCL.so.1` (OpenCL-ICD-Loader) | no | forwards calls to the vendor driver |
| `libpugixml` | no | XML metadata |
| `libonnxruntime.so`, `libtensorflowlite_c.so` (irlume) | not on the GPU side | the CPU reference and the face mesh, already bound by the entry's ONNX Runtime version and CPU digest |

Fedora's IGC builds with `IGC_OPTION__LLVM_MODE=Prebuilds` against the
system LLVM, LLD, SPIR-V translator and clang (intel-igc spec, Fedora
branch), and the installed `libigc.so.2.41.9` needs `libLLVM.so.22.1` and
`libLLVMSPIRVLib.so.22.1`; intel-opencl-clang builds with
`USE_PREBUILT_LLVM=ON` and needs `libclang-cpp.so.22.1` and
`libLLVM.so.22.1`. Upstream IGC 2.41.9 in its Source mode applies Intel
patches to LLVM that the Prebuilds mode cannot apply, so a Fedora IGC and
an Intel release IGC of the same version are different compilers, and a
system LLVM update alone can change the kernels. Intel's release IGC
packages link LLVM statically.

## How often the exact set moves

Bodhi (`https://bodhi.fedoraproject.org/updates/?packages=<source>&releases=F44&status=stable`,
queried 2026-10-22) lists stable updates to the source packages of those
libraries on 9 dates between 2026-07-22 and 2026-10-22: intel-compute-runtime
with intel-igc (07-22), llvm (07-23), intel-compute-runtime (07-31),
glibc (08-06), intel-gmmlib (08-20), gcc (08-22), intel-gmmlib (09-13),
glibc (10-01), intel-compute-runtime with intel-igc and intel-opencl-clang
(10-03). irlumed itself also maps systemd and OpenSSL libraries, which add
07-27, 09-02, 09-17 and 10-20: 13 dates, about one a week. OpenVINO comes
from maintainer-controlled packages and is not counted. linux-firmware
moved 4 times; its 20261019 build, installed on the UX5406S on
2026-10-21, left the Lunar Lake GuC and HuC versions unchanged (70.72.1
and 9.4.13 in both the 2026-10-12 and the 2026-10-22 identity dumps).

Binding only the compute runtime's drivers, IGC, opencl-clang, clang,
LLVM and the SPIR-V translator moves on 4 of those dates; adding gmmlib
moves on 6.

A re-certification is a campaign: the 2026-10-21 UX5406S runs took about
70 minutes of machine time (identity, cache control, real frames and
corpora in 3,291 s, cache matrix, power-management diagnostic, retained
run with a proven suspend) plus attended steps, and the ADR-0022 section
7.3 items no GPU run has measured would add more. The certification table
is compiled into the binary, so a new entry also needs a release.

## What the startup canary covers

The section 8 canary of ADR-0022, which ADR-0033 applies to the GPU,
hashes the raw outputs of three fixed synthetic inputs (`chip(k)`,
k = 0 to 2, element i = ((i(37 + 16k)) mod 255 - 127.5) / 128) on the CPU
session and on the accelerator, and requires both digests to equal the
entry's, at every engine build and after a detected system suspend. On a
static graph the kernels are chosen by shape, not by data, so a library
that changes the compiled program (a different kernel, contraction or
reassociation, a different folded constant) changes those output bits.

Its blind spots: behaviour that depends on input values the synthetic
inputs never reach (denormals, non-finite values, value-dependent fast
paths); a nondeterminism that appears at inference after the build-time
check passed; reliability (crashes, hangs, leaks, suspend faults), which
section 10 bounds to one restart and then CPU; and real-corpus drift,
which it infers from bit equality but does not measure. Configuration
that changes the compiler (IGC environment keys, the compute runtime's
persistent cache) is outside any library binding and belongs to the
launch profile of #1162.

## Options compared

- Bind every mapped library and re-certify each identity: the strongest
  statement, 13 re-bindings in 92 days, each a campaign and a release;
  between them a GPU placement falls back to CPU.
- Ship a pinned GPU stack in a private prefix: puts the numerics set under
  maintainer control, but glibc, libstdc++, the daemon's dependencies and
  the firmware still move (8 production dates if they stay bound), it
  contradicts ADR-0022 section 5 ("never bundles OpenVINO"), and irlume
  would carry the security updates of the compute runtime, IGC, LLVM and
  OpenVINO, which Intel ships about monthly.
- Bind the numerics set and keep the rest under the inventory check with
  the canary (the amendment): 6 dates with gmmlib bound, at the cost of
  the blind spots above for support-library updates, narrowed by an
  extended reference set run twice whenever the support set differs from
  the certified one.
- Certify the compiled blob, or let a new identity inherit verdicts when
  its corpus outputs are bit-identical to a certified one's: both remain
  open. Blob byte-determinism and whether importing a blob still maps the
  compiler are unmeasured; inheritance would make numerics-set re-bindings
  cheap and is a candidate follow-up.

Other stacks state the same limit: cuBLAS promises bit-wise reproducible
results only for a given toolkit version on the same architecture and SM
count, and PyTorch and TensorFlow do not promise determinism across
releases. No primary source found certifies bit-exact results across
driver updates without pinning or re-verifying.

## Not verified

- Whether the f32 fully connected layer ran on oneDNN or on OpenCL
  kernels, and whether any kernel folds a transcendental through host
  libm.
- The production daemon's complete inventory under the real unit
  (dynamically loaded TCTI and NSS modules); the 13 dates are a lower
  bound.
- Whether any of the 9 updates actually changed GPU output bits: the
  identity rebinds regardless, and no output was measured across them.
- The canary's blind spots come from the code structure, not from fault
  injection.
