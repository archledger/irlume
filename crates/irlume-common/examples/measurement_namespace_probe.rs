// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Private kernel namespace observation, not a launch capability.

#[cfg(all(
    irlume_hw_evidence,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "musl",
    target_feature = "crt-static"
))]
#[path = "measurement_namespace_probe/probe.rs"]
mod probe;

fn main() {
    #[cfg(all(
        irlume_hw_evidence,
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl",
        target_feature = "crt-static"
    ))]
    probe::main();
    #[cfg(not(all(
        irlume_hw_evidence,
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl",
        target_feature = "crt-static"
    )))]
    std::process::exit(77);
}
