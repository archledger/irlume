#![no_main]
//! The daemon's IPC request parser.
//!
//! Any unprivileged local process can connect to /run/irlume.sock and write
//! bytes. irlumed reads a line and runs `serde_json::from_str::<Request>()`
//! (crates/irlume-daemon/src/main.rs). This target replays that exact call on
//! fuzzer input: it must return Err on garbage, never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<irlume_common::Request>(s);
    }
});
