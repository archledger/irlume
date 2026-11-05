// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! File boundary for camera-tune evidence. These records never authorize capture.

use irlume_camera::measurement::MeasurementRecord;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

// Two 4096-round arms fit comfortably, including pretty-printed JSON.
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const LEAF: &str = "record.tmp";

#[cfg(test)]
#[path = "measurement_records_tests.rs"]
mod tests;

fn read_records(file: File) -> Result<Vec<MeasurementRecord>, String> {
    let mut text = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() as u64 > MAX_BYTES {
        return Err("measurement artifact exceeds 16 MiB".into());
    }
    let records: Vec<MeasurementRecord> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if records.is_empty() {
        return Err("measurement artifact contains no records".into());
    }
    for record in &records {
        record.evaluate_acceptance().map_err(|e| format!("{e:?}"))?;
    }
    Ok(records)
}

pub(crate) fn read_reference(path: &str) -> Result<Vec<MeasurementRecord>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("cannot read {path}: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("reference is not a regular file".into());
    }
    read_records(file)
}

fn shared_path(path: &Path) -> Result<(), String> {
    if ["/tmp", "/var/tmp"]
        .iter()
        .any(|root| path.starts_with(root))
    {
        return Err("the daemon has private /tmp and /var/tmp; choose a shared directory".into());
    }
    Ok(())
}

pub(crate) fn output_path(raw: &str) -> Result<String, String> {
    let leaf = raw.rsplit('/').next().unwrap_or_default();
    if matches!(leaf, "" | "." | "..") {
        return Err("output must name a file".into());
    }
    let absolute = std::path::absolute(raw).map_err(|e| e.to_string())?;
    let parent = absolute
        .parent()
        .ok_or("output has no parent")?
        .canonicalize()
        .map_err(|e| format!("cannot resolve output parent: {e}"))?;
    shared_path(&parent)?;
    let path = parent.join(absolute.file_name().ok_or("output has no filename")?);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err("output already exists".into()),
        Err(e) => return Err(e.to_string()),
    }
    path.into_os_string()
        .into_string()
        .map_err(|_| "output path is not UTF-8".into())
}

fn directory(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())
}

fn anchored(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn owner() -> u32 {
    // SAFETY: geteuid has no arguments, pointer access or preconditions.
    unsafe { libc::geteuid() }
}

fn private_file(metadata: &fs::Metadata, expected_owner: u32) -> bool {
    metadata.is_file()
        && metadata.uid() == expected_owner
        && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == 1
}

fn trusted_ancestors(path: &Path) -> Result<(), String> {
    // Check from the root down. Another account must not control any component
    // that the daemon will later traverse using the ordinary absolute path.
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        if !metadata.is_dir()
            || ![0, owner()].contains(&metadata.uid())
            || metadata.mode() & 0o022 != 0
        {
            return Err(format!(
                "untrusted shared-state ancestor: {}",
                ancestor.display()
            ));
        }
    }
    Ok(())
}

fn open_created_directory(
    path: &Path,
    display: &Path,
    opened: Result<File, String>,
) -> Result<File, String> {
    match opened {
        Ok(file) => Ok(file),
        Err(error) => {
            // The parent hierarchy was checked and the successful mkdir was
            // exclusive. Never recurse if opening its descriptor failed.
            let cleanup = fs::symlink_metadata(path).and_then(|metadata| {
                if !metadata.is_dir()
                    || metadata.uid() != owner()
                    || metadata.mode() & 0o7777 != 0o700
                {
                    return Err(std::io::Error::other(
                        "created directory identity is no longer safe",
                    ));
                }
                fs::remove_dir(path)
            });
            Err(match cleanup {
                Ok(()) => format!(
                    "cannot open created directory {} (removed): {error}",
                    display.display()
                ),
                Err(cleanup) => format!(
                    "cannot open created directory {}: {error}; retained: {cleanup}",
                    display.display()
                ),
            })
        }
    }
}

/// One invocation's absent output leaf in an exclusively created directory.
/// Descriptor anchoring protects against other accounts, not a hostile root.
pub(crate) struct FreshArtifact {
    root_path: PathBuf,
    root: File,
    path: PathBuf,
    dir: File,
    name: String,
    observed: Option<fs::Metadata>,
    finished: bool,
}

impl FreshArtifact {
    pub(crate) fn create() -> Result<Self, String> {
        let root_path = irlume_common::state_dir()
            .canonicalize()
            .map_err(|e| format!("cannot resolve shared state directory: {e}"))?;
        shared_path(&root_path)?;
        trusted_ancestors(&root_path)?;
        let root = directory(&root_path)?;
        let metadata = root.metadata().map_err(|e| e.to_string())?;
        if metadata.uid() != owner() || metadata.mode() & 0o022 != 0 {
            return Err(
                "shared state directory must be owned by the caller and not writable by others"
                    .into(),
            );
        }
        for _ in 0..16 {
            let name = format!(".verify-record-{:032x}", rand::random::<u128>());
            let child = anchored(&root).join(&name);
            match fs::DirBuilder::new().mode(0o700).create(&child) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("cannot create private measurement directory: {e}")),
            }
            let dir = open_created_directory(&child, &root_path.join(&name), directory(&child))?;
            let path = root_path.join(&name).join(LEAF);
            let artifact = Self {
                root_path,
                root,
                path,
                dir,
                name,
                observed: None,
                finished: false,
            };
            artifact.check_directory()?;
            return Ok(artifact);
        }
        Err("cannot reserve a unique measurement directory".into())
    }

    fn check_directory(&self) -> Result<(), String> {
        let root = fs::symlink_metadata(&self.root_path).map_err(|e| e.to_string())?;
        let current = fs::symlink_metadata(anchored(&self.root).join(&self.name))
            .map_err(|e| e.to_string())?;
        let original = self.dir.metadata().map_err(|e| e.to_string())?;
        if !root.is_dir()
            || !same_file(&root, &self.root.metadata().map_err(|e| e.to_string())?)
            || root.uid() != owner()
            || root.mode() & 0o022 != 0
            || !current.is_dir()
            || !same_file(&current, &original)
            || original.uid() != owner()
            || original.mode() & 0o7777 != 0o700
        {
            return Err("private measurement directory identity or permissions changed".into());
        }
        Ok(())
    }

    pub(crate) fn path(&self) -> Result<String, String> {
        self.check_directory()?;
        self.path
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| "measurement path is not UTF-8".into())
    }

    pub(crate) fn read(&mut self) -> Result<Vec<MeasurementRecord>, String> {
        self.check_directory()?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(anchored(&self.dir).join(LEAF))
            .map_err(|e| format!("no usable fresh artifact: {e}"))?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !private_file(&metadata, owner()) {
            return Err("fresh artifact must be a private, caller-owned regular file".into());
        }
        self.observed = Some(metadata);
        read_records(file)
    }

    fn cleanup(&self) -> Result<(), String> {
        self.check_directory()?;
        for entry in fs::read_dir(anchored(&self.dir)).map_err(|e| e.to_string())? {
            if entry.map_err(|e| e.to_string())?.file_name() != LEAF {
                return Err(
                    "unexpected contents in private measurement directory; retained".into(),
                );
            }
        }
        let leaf = anchored(&self.dir).join(LEAF);
        match fs::symlink_metadata(&leaf) {
            Ok(metadata) => {
                if !private_file(&metadata, owner())
                    || self
                        .observed
                        .as_ref()
                        .is_some_and(|old| !same_file(old, &metadata))
                {
                    return Err("fresh artifact identity or permissions changed; retained".into());
                }
                fs::remove_file(&leaf).map_err(|e| e.to_string())?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && self.observed.is_none() => {}
            Err(e) => return Err(e.to_string()),
        }
        fs::remove_dir(anchored(&self.root).join(&self.name)).map_err(|e| e.to_string())
    }

    pub(crate) fn finish(mut self) -> Result<(), String> {
        self.finished = true;
        self.cleanup()
            .map_err(|e| format!("measurement cleanup at {} failed: {e}", self.path.display()))
    }
}

impl Drop for FreshArtifact {
    fn drop(&mut self) {
        if !self.finished {
            if let Err(error) = self.cleanup() {
                eprintln!("[camera-tune] retained {}: {error}", self.path.display());
            }
        }
    }
}
