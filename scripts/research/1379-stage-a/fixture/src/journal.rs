// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub(super) fn record_intent(case_dir: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(case_dir)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected private fixture case directory",
        ));
    }
    let dir = File::open(case_dir)?;
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(case_dir.join("attempt.hold"))?;
    marker.write_all(b"stage-a-fixture-v1\n")?;
    marker.sync_all()?;
    dir.sync_all()
}
