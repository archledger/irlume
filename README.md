# lumen

> **Placeholder name.** `lumen` (Latin: *light* — the IR illumination at its
> core) is a working title. Rename across the tree with a single find-replace.

**Secure face authentication for Linux — engineered to meet or beat Windows Hello.**

`lumen` is a PAM-based face-unlock system for Linux (login, sudo, lockscreen,
display managers). It is the from-scratch successor to
[linhello](../linhello), rebuilt around a **commercially-clean, fully
permissive model stack** under a copyleft umbrella, with **real IR liveness**
and **TPM-bound** secrets.

## Status

🚧 **Scaffold / pre-alpha.** Architecture and interfaces are stubbed; no
working authentication yet. **Not suitable for production use.**

## Why it's different

| | Windows Hello | `visage` (closest FOSS) | **lumen** |
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

Privilege-separated. The thin **`pam_lumen.so`** module and **`lumen`** CLI are
untrusted clients of the privileged **`lumend`** daemon, which alone owns the
camera, IR emitter, models, templates and TPM. They speak over a Unix socket;
the daemon authenticates peers with `SO_PEERCRED`. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

```
crates/
  lumen-common    IPC protocol, paths, errors
  lumen-camera    V4L2 RGB+IR capture, UVC-XU IR emitter
  lumen-vision    YuNet detect → align → AuraFace embed (ONNX via ort)
  lumen-liveness  algorithmic IR PAD gate
  lumen-core      matcher, template storage, TPM sealing
  lumen-daemon    lumend — privileged hardware/model owner + IPC server
  lumen-pam       pam_lumen.so — thin PAM client
  lumen-cli       lumen — enroll/verify/selftest/doctor
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
  daemon/PAM split; `SO_PEERCRED`. **Gate: `lumen selftest align` (same crop →
  cosine ≈ 1.0).**
- **P2 — the security thesis:** IR liveness gate (NIR skin, bright-pupil,
  cross-spectrum overlap, device-trust) + ISO/IEC 30107-3 self-testing.
- **P3 — hardening:** TPM sealing; fixed threshold tuned for FMR ≤ 1e-4 across
  demographics; mandatory non-biometric fallback.
- **P4 — (optional) certification:** iBeta ISO/IEC 30107-3 PAD; FIDO.

## License

**GPL-3.0-or-later.** Fully open source. Modifications stay free; nobody can lock
this down. Contributions welcome under the
[DCO](CONTRIBUTING.md) — no CLA, no commercial relicensing.

Donations are optional and entirely up to you (links: _TBD_).
