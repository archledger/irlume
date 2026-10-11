# GPU platform identity probe (ADR-0033 section 3)

- **What:** #1053 identity measurements behind the complete GPU
  identity slice. A C probe read the GPU plugin's device properties
  through the real installed C API, matched the plugin's PCI report
  against the DRM render node sysfs tree, and recorded which native
  libraries the GPU enumeration mapped. The purpose was to establish,
  on the shipped 2026.2.1 builds, exactly what an ADR-0033 section 3
  identity can observe, which loader stack the plugin resolves, and
  what the driver-version property does. Platform facts only; no
  biometric data.
- **Where and when:** 2026-10-11. minihost (Alder Lake-N integrated
  GPU, 24-EU class, `/dev/dri/renderD128`; OpenVINO 2026.2.1
  root-owned archive under `/opt/openvino-2026.2.1-lib`) and the
  UX5406S laptop (Lunar Lake Arc 140V integrated GPU, `renderD128`;
  Fedora RPM `/usr/lib64/libopenvino_c.so.2621`).
- **How:** a C probe through the real C API (`ov_core_get_property`
  on the enumerated `GPU.0`), plus reads of
  `/sys/class/drm/renderD*/device` (address, `vendor`, `device`) and
  `/proc/self/maps`. On minihost the runtime was reached only through
  the test process `LD_LIBRARY_PATH`; no installed loader or system
  library changed on either host.
- **Primary sources:** OpenVINO tag 2026.2.1
  `src/plugins/intel_gpu/src/plugin/plugin.cpp` `get_property`
  (`DEVICE_PCI_INFO` formatted `{domain: %u bus: %u device: 0x%x
  function: %u}`, with `GPU_DEVICE_ID` and
  `GPU_EXECUTION_UNITS_COUNT` around lines 586 to 673);
  `src/common/zero_loader/src/zero.api.cpp` (Level Zero builds dlopen
  `libze_loader.so.1`) while the OpenCL backend links
  `libOpenCL.so.1`; the kernel's `pci-sysfs.c` `vendor` and `device`
  attributes; the DRM render node's `device` symlink into its PCI
  device directory.

## minihost findings

Runtime build `2026.2.1-21919-ede283a88e3-releases/2026/2`, reached
through the test process `LD_LIBRARY_PATH` only.

| Observation | Value |
|---|---|
| `DEVICE_PCI_INFO` | `{domain: 0 bus: 0 device: 0x2 function: 0}` = `0000:00:02.0` |
| sysfs render node | `renderD128` at `0000:00:02.0`, vendor `0x8086`, device `0x46d1` |
| `GPU_DEVICE_ID` | `0x46d1`, equal to the sysfs device attribute |
| `DEVICE_ARCHITECTURE` | `GPU: vendor=0x8086 arch=v12.4.0` |
| `GPU_EXECUTION_UNITS_COUNT` | 24 |
| `GPU_DEVICE_TOTAL_MEM_SIZE` | 7125323776 |
| `DEVICE_TYPE` | integrated |
| Capabilities | FP32 BIN FP16 INT8 GPU_USM_MEMORY EXPORT_IMPORT |
| GPU plugin build (`Core::versions("GPU")`) | `2026.2.1-21919-ede283a88e3-releases/2026/2` |
| Loader family | OpenCL ICD: `libOpenCL.so.1.0.0`, `libigdrcl.so`, `libigc.so.2.41.0`, `libigdgmm.so.12.10.0`; Mesa `libRusticlOpenCL.so.1.0.0` also mapped |

The plugin's PCI report and the render node agree on address, vendor
and device: `0000:00:02.0` is `renderD128`'s sysfs address, and
`GPU_DEVICE_ID` equals the node's `device` attribute.

## UX5406S findings

Fedora RPM 2026.2.1, GPU plugin build `2026.2.1-000--`.

| Observation | Value |
|---|---|
| `DEVICE_PCI_INFO` | same `0000:00:02.0` BDF as minihost |
| sysfs render node | `renderD128` at `0000:00:02.0` |
| `GPU_DEVICE_ID` | `0x64a0` |
| `DEVICE_ARCHITECTURE` | `GPU: vendor=0x8086 arch=v20.4.4` |
| `GPU_EXECUTION_UNITS_COUNT` | 64 |
| `GPU_DEVICE_TOTAL_MEM_SIZE` | 30629367808 |
| Capabilities | the minihost set plus `GPU_HW_MATMUL` |
| GPU plugin build (`Core::versions("GPU")`) | `2026.2.1-000--` |
| Loader family | OpenCL ICD: `libOpenCL.so.1.0.0`, `/usr/lib64/intel-opencl/libigdrcl.so`, `libigc.so.2.41.9`, `libigdgmm.so.12.10.0`; no Rusticl mapped |

## The GPU_DRIVER_VERSION defect

- Reading `GPU_DRIVER_VERSION` through `ov_core_get_property` kills
  the process with SIGSEGV. Deterministic on both measured builds:
  the root-owned archive on minihost and the Fedora RPM on the
  UX5406S. Exact repro: create the core, enumerate `GPU.0`, call the
  property read for `GPU_DRIVER_VERSION`; the call never returns and
  the process dies.
- A bare device index as the device name crashes the same way:
  passing `"0"` where `"GPU.0"` is expected segfaults on both builds.
  The implementation therefore always names the device `GPU.N`.
- Design consequence: the identity never reads `GPU_DRIVER_VERSION`.
  Driver identity comes from the hashed mapped-library manifest
  below, which already makes a driver or compute-runtime rebuild a
  different identity under the one-open-file inode discipline.

## Loader stacks

- Both measured builds resolved the OpenCL ICD family: the plugin
  links `libOpenCL.so.1`, and no Level Zero loader (`libze_loader`)
  was mapped on either host, matching the upstream sources (the
  `zero.api.cpp` dlopen path belongs to Level Zero builds).
- On minihost, ICD enumeration also mapped Mesa's
  `libRusticlOpenCL.so.1.0.0` beside the Intel driver libraries: a
  foreign ICD ran enumeration code inside the process. This is why
  the manifest inventories every file-backed executable mapping
  rather than a guessed name closure.
- Manifest scope, as implemented: every file-backed executable
  mapping from `/proc/self/maps` (minus the process executable, as the
  NPU execution inventory excludes it), plus the IR and ONNX frontends
  beside the core (which compiling loads), each hashed through one
  open file whose inode is kept, re-verified against the maps after
  compile.

## Property surface

`SUPPORTED_PROPERTIES` lists every key above. All of them, including
the numeric-looking ones (`DEVICE_PCI_INFO`, `GPU_DEVICE_ID`,
`GPU_EXECUTION_UNITS_COUNT`, `GPU_DEVICE_TOTAL_MEM_SIZE`), return as
strings through `ov_core_get_property`; the consumer parses. The
fixed compile configuration the identity carries is
`batch=1;PERFORMANCE_HINT=LATENCY;INFERENCE_PRECISION_HINT=f16`, and
a test-only platform compiles on `GPU.0` under it, requires
`EXECUTION_DEVICES` to name that GPU, and re-verifies the mapped
libraries after the compile (the retirement trigger).

## Standing

This is measurement evidence only. Loading admission stays closed
(production discovery refuses before `dlopen`), `CERTIFIED` stays
empty, and CPU authentication stays authoritative. The record feeds
the identity implementation and its `gpu_hw_*` hardware tests; it
places nothing.
