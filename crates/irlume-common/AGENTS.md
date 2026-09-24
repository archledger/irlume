# AGENTS.md: irlume-common

The root [AGENTS.md](../../AGENTS.md) applies. This crate is the single home of
the wire protocol (`Request`, `Response` in `src/lib.rs`), the socket client
(`src/client.rs`), config (`src/config.rs`) and shared tables. It depends on no
other irlume crate, and nearly every crate depends on it
([crates/README.md](../README.md)).

## Rules

- Wire changes follow [crates/irlume-daemon/AGENTS.md](../irlume-daemon/AGENTS.md)
  "Wire compatibility"; the `ipc_request` fuzz target parses `Request`.
- This code is linked into PAM and setuid stacks. A new override that picks
  what to trust (a socket or helper path) is read through `client::secure_env`,
  which ignores it under secure execution; a plain `std::env::var` there would
  let a user redirect root. The config readers (`config_root`'s
  `IRLUME_CONFIG_DIR`, the `IRLUME_<KEY>` overrides) use `std::env`, so a
  client's read is advisory: the daemon re-decides every value a client acts on
  (recipe step 4).
- Config files are written only through `write_kv` or `write_kvs`. They refuse,
  before any I/O, a key or value that would not read back as one line, and
  never rebuild a file they cannot read.
- `cameras.conf` has two readers: `read_camera_pin`, which camera selection
  uses, and the strict observer (`parse_camera_conf`, pure, and
  `observe_camera_conf`) that irlumed reports at start and checks before a
  save; `camera_conf_observation_agrees_with_read_camera_pin_on_files_irlume_writes`
  keeps them in step. The grammar is the `parse_camera_conf` doc, the rows of
  `parse_camera_conf_follows_the_grammar` and the docs/SETUP.md files table. A
  fix that makes the code match it is a `fix(config)` with a new test row;
  accepting or rejecting a new shape (or key beyond `CAMERA_SELECTION_KEYS`)
  needs the maintainer and an ADR-0029 amendment. No fuzz target covers it.
- PAM service names are classified once, in `src/pam_service.rs`. A new or
  changed entry is sourced, not guessed: name the distro, greeter or lock
  screen that ships the `/etc/pam.d` file ([CONTRIBUTING.md](../../CONTRIBUTING.md)).
- Secrets crossing the wire or held in memory use `SecretBytes`.

## Recipe: add a config key

1. Machine policy goes in `settings.conf`.
2. Add a reader beside the `*_visible()` readers in `src/config.rs`: an optional
   `IRLUME_<KEY>` override, then `observe_kv("settings.conf", key)`, mapping
   `Value`, `Absent` (the documented default) and `Unknown` (a file this process
   cannot read).
3. Resolve `Unknown` to the safe default in the decision function, as
   `privileged_face_consent_required` does (ADR-0018). Booleans use `truthy`
   or `falsy`; an opt-in accepts only an explicit affirmative.
4. The daemon decides. Clients show the value through `PreferencesState`; a
   client that acts on its own read is re-checked by the daemon, as the PAM
   module's read of `privileged_face_consent` is.
5. Write related keys together with `write_kvs`.
6. Test under `let _g = testenv::lock();` with `IRLUME_CONFIG_DIR` pointed at a
   temp dir, including an unreadable file.
7. Document the key in [docs/SETUP.md](../../docs/SETUP.md) (files and
   environment tables), the TUI Preferences page if shown there, and the
   CHANGELOG.
