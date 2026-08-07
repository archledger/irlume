// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Answer one question for installers: can THIS TFLite runtime library
//! actually be loaded by the same resolver production uses? A `-f` test
//! cannot (a truncated or wrong-architecture .so is still a regular file),
//! and recreating the loader's symbol contract in shell would drift from
//! it. Exit 0 = loadable; exit 1 with the resolver's own diagnosis on
//! stderr otherwise. Loads the library and nothing else: no model, no
//! camera, no daemon state.
//!
//! Usage: tflite_runtime_probe <absolute-library-path>

use irlume_vision::tflite::{tflite_runtime, TFLITE_LIB_ENV};

fn main() {
    let path = std::env::args_os()
        .nth(1)
        .expect("usage: tflite_runtime_probe <absolute-library-path>");
    std::env::set_var(TFLITE_LIB_ENV, path);

    if let Err(error) = tflite_runtime() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
