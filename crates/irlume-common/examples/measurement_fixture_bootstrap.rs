// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Private fixture experiment, not a production launcher or public API.

#[cfg(all(
    irlume_hw_evidence,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "musl",
    target_feature = "crt-static"
))]
#[path = "measurement_fixture_bootstrap/bootstrap.rs"]
mod bootstrap;

fn main() {
    #[cfg(all(
        irlume_hw_evidence,
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl",
        target_feature = "crt-static"
    ))]
    bootstrap::main();

    #[cfg(not(all(
        irlume_hw_evidence,
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl",
        target_feature = "crt-static"
    )))]
    std::process::exit(77);
}
