// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Private CPU-only mount-lifetime experiment, not a native launcher.

#[cfg(all(
    irlume_hw_evidence,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "musl",
    target_feature = "crt-static"
))]
#[path = "measurement_generation_fixture/generation.rs"]
mod generation;

fn main() {
    #[cfg(all(
        irlume_hw_evidence,
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl",
        target_feature = "crt-static"
    ))]
    generation::main();
    #[cfg(not(all(
        irlume_hw_evidence,
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl",
        target_feature = "crt-static"
    )))]
    std::process::exit(77);
}
