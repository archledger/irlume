## What & why

<!-- What this changes and the reason. Link any issue. -->

## Testing

<!-- How it was verified. Note hardware validated on, if any. -->

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo fmt --check` clean
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` clean
- [ ] Docs/CHANGELOG updated if user-facing
- [ ] Hardware-validated (if it touches PAM, the daemon, or capture)
