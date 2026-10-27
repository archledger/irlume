# Parser fuzzing

This is a separate Cargo workspace. From this directory, fetch the committed
dependencies and seed the target's generated corpus before fuzzing:

```sh
cargo fetch --locked
mkdir -p corpus/native_metadata
cp -n seeds/native_metadata/* corpus/native_metadata/
python3 generate-native-metadata-seeds.py corpus/native_metadata
cargo +nightly-2026-07-15 fuzz run native_metadata -- -max_total_time=45 -rss_limit_mb=4096
```

Other targets use their checked-in `seeds/<target>/` inputs without a generator.
The CI job preserves accumulated corpus entries across runs.

## Native metadata seeds

`generate-native-metadata-seeds.py` constructs two synthetic ELF64 parser
inputs from reviewable source rather than storing binary artifacts in Git.
They are data for `native_metadata::inspect`, never loaded or executed:

- `needed.elf`: a 255-byte ET_DYN with a read-only PT_LOAD, a PT_DYNAMIC
  table and one `DT_NEEDED` string, `libfixture.so`. It contains no machine
  code, interpreter or executable segment.
- `truncated.elf`: its first 180 bytes, ending in a partial dynamic entry.

The generator preserves the original bytes. Its tests pin both SHA-256
digests, require non-executable file modes, and reject conflicting files or
symlinks without overwriting them. A matching existing seed is left intact;
other corpus entries are never changed. Run the checks with:

```sh
python3 test-generate-native-metadata-seeds.py
```

Generated corpus files stay under the ignored `corpus/` directory. Do not
commit them or remove these starting inputs to silence a scanner.
