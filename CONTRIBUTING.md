# Contributing to irlume

Thanks for your interest! irlume is **GPL-3.0-or-later** and intends to stay
fully open source forever. There is **no CLA** and no commercial relicensing —
your contributions remain under the same copyleft terms everyone else enjoys.

## Developer Certificate of Origin (DCO)

We use the [DCO](https://developercertificate.org/) instead of a CLA. It's a
lightweight statement that you wrote (or have the right to submit) the code you
contribute. Just sign off your commits:

```sh
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <you@example.com>` line. By signing off
you certify the DCO. That's it — no forms, no rights assignment.

## Ground rules for a security project

- **Never commit biometric data** — no captured frames, embeddings, or
  templates, even as test fixtures. Use synthetic or your own clearly-consented
  data, kept out of the repo.
- **Keep the model BOM permissive.** Any new model must be clean at all three
  layers (code, weights, training data). No InsightFace buffalo_l/antelopev2 or
  other non-commercial weights — they conflict with GPL.
- **Liveness/PAD changes** should come with a self-test against the relevant
  ISO/IEC 30107-3 attack class — run `irlume padcapture` / `irlume padreport` and
  include the per-species APCER/BPCER numbers. See
  [`docs/PAD_SELFTEST.md`](docs/PAD_SELFTEST.md) for the methodology and protocol.
- Run `cargo fmt`, `cargo clippy`, and `cargo test` before opening a PR.

## Where to start

Look for `todo!()` / `TODO` markers — each maps to a roadmap phase in the
README. The Phase-1 alignment self-test (`irlume selftest align`) is the highest-
leverage first piece.
