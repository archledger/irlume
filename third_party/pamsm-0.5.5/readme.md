# PAM SM

[![Crates.io version shield](https://img.shields.io/crates/v/pamsm.svg)](https://crates.io/crates/pamsm)
[![Crates.io license shield](https://img.shields.io/crates/l/pamsm.svg)](https://crates.io/crates/pamsm)

Rust FFI wrapper to implement PAM service modules for Linux.

**[Documentation](https://docs.rs/pamsm/) -**
**[Cargo](https://crates.io/crates/pamsm) -**
**[Repository](https://github.com/rcatolino/pam_sm_rust)**

## Features

This crate supports the following optional features:
 * `libpam`: this enables the extension trait `PamLibExt` and linking against `libpam.so` for its native implementation.
