# Parser fuzzing

This is a separate Cargo workspace. From this directory, fetch the committed
dependencies and seed the target's generated corpus before fuzzing:

```sh
cargo fetch --locked
mkdir -p corpus/ipc_request
cp -n seeds/ipc_request/* corpus/ipc_request/
cargo +nightly-2026-07-15 fuzz run ipc_request -- -max_total_time=45 -rss_limit_mb=4096
```

Each target uses its checked-in `seeds/<target>/` inputs.
The CI job preserves accumulated corpus entries across runs.

Generated corpus files stay under the ignored `corpus/` directory. Do not commit
them.
