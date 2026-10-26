// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Private portable lifecycle experiment. No native execution in any build.

#[cfg(test)]
#[path = "measurement_job_fixture/lifecycle.rs"]
mod lifecycle;

#[cfg(test)]
#[path = "measurement_job_fixture/kernel.rs"]
mod kernel;

fn main() {
    std::process::exit(77);
}
