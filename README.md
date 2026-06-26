# irlume

> *irlume* = **IR** (infrared) + **lume** (illumination) — it recognizes you by
> active infrared light, so it works in the dark and resists screen/photo spoofs.

**Secure face authentication for Linux — engineered to meet or beat Windows Hello.**

`irlume` is a PAM-based face-unlock system for Linux (login, sudo, lockscreen,
display managers). It is the from-scratch successor to
[linhello](../linhello), rebuilt around a **commercially-clean, fully
permissive model stack** under a copyleft umbrella, with **real IR liveness**
and **TPM-bound** secrets.

## Status

🚧 **Scaffold / pre-alpha.** Architecture and interfaces are stubbed; no
working authentication yet. **Not suitable for production use.**

## Why it's different

| | Windows Hello | `visage` (closest FOSS) | **irlume** |
|---|---|---|---|
| Liveness / anti-spoof | IR only (bypassable, CVE-2021-34466) | none | **algorithmic IR PAD gate** |
| Camera injection defense | ESS device-trust (newer HW) | none | **device-trust + cross-spectrum RGB↔IR** |
| Template protection | TPM-bound | raw f32 in SQLite | **TPM-sealed release secret** |
| Model licensing | proprietary | non-commercial weights | **permissive, bundleable** |

## Model bill-of-materials (all permissive, GPLv3-compatible)

| Stage | Model | License |
|---|---|---|
| Detection | **YuNet** `face_detection_yunet_2023mar.onnx` | MIT |
| Recognition | **AuraFace** `glintr100.onnx` (512-D ArcFace) | Apache-2.0 |
| Liveness | self-built algorithmic IR gate (no weights) | — |

> Do **not** substitute InsightFace buffalo_l/antelopev2 or YuNet's bundled
> SCRFD: their non-commercial weights conflict with GPL's downstream-commercial
> freedom. See [`models/README.md`](models/README.md).

## Architecture

Privilege-separated. The thin **`pam_irlume.so`** module and **`irlume`** CLI are
untrusted clients of the privileged **`irlumed`** daemon, which alone owns the
camera, IR emitter, models, templates and TPM. They speak over a Unix socket;
the daemon authenticates peers with `SO_PEERCRED`. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

```
crates/
  irlume-common    IPC protocol, paths, errors
  irlume-camera    V4L2 RGB+IR capture, UVC-XU IR emitter
  irlume-vision    YuNet detect → align → AuraFace embed (ONNX via ort)
  irlume-liveness  algorithmic IR PAD gate
  irlume-core      matcher, template storage, TPM sealing
  irlume-daemon    irlumed — privileged hardware/model owner + IPC server
  irlume-pam       pam_irlume.so — thin PAM client
  irlume-cli       irlume — enroll/verify/selftest/doctor
```

## Build

```sh
cargo build            # builds the scaffold (native deps are commented out)
cargo test             # runs the cosine/authorization unit tests
```

Native dependencies (`ort`, `nokhwa`, `tss-esapi`, `pamsm`) are listed but
commented in the `Cargo.toml`s so the scaffold compiles offline. Enable them per
crate as you implement.

## Roadmap

- **P1 — prove the pipeline:** YuNet → align → AuraFace → cosine match → unlock;
  daemon/PAM split; `SO_PEERCRED`. **Gate: `irlume selftest align` (same crop →
  cosine ≈ 1.0).**
- **P2 — the security thesis:** IR liveness gate (NIR skin, bright-pupil,
  cross-spectrum overlap, device-trust) + ISO/IEC 30107-3 self-testing.
- **P3 — hardening:** TPM sealing; fixed threshold tuned for FMR ≤ 1e-4 across
  demographics; mandatory non-biometric fallback.
- **P4 — (optional) certification:** iBeta ISO/IEC 30107-3 PAD; FIDO.

## Performance & hardware acceleration

Two layers (same model as [howrs](https://github.com/Eason0729/howrs)):

1. **ONNX Runtime execution provider** — the big win, selected at build time via
   `irlume-vision` cargo features: `cuda`, `openvino`, `coreml`, `tensorrt`.
   Default is CPU (ONNX Runtime's own SIMD + thread pool). Most compute lives
   here, not in our Rust.
2. **Our glue loops** (alignment warp, cosine fold) auto-vectorize via LLVM.
   Tune with `RUSTFLAGS` / `.cargo/config.toml` (`target-cpu=x86-64-v2 +avx2` for
   a portable AVX2 floor, or `target-cpu=native` for self-built binaries).

Hand-written SIMD intrinsics are intentionally avoided — for a once-per-unlock
auth pipeline the compute is dominated by ONNX Runtime, and a 512-D cosine is
negligible. Bundling **int8-quantized** models is the other free speedup.

## License

**GPL-3.0-or-later.** Fully open source. Modifications stay free; nobody can lock
this down. Contributions welcome under the
[DCO](CONTRIBUTING.md) — no CLA, no commercial relicensing.

Donations are optional and entirely up to you (links: _TBD_).
