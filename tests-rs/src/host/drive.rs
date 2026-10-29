// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host filesystem images, ported from `tests/host_tools/drive.py`.
//!
//! `tempfile.mkstemp` is replaced by a random `/tmp` name that is *not* pre-created, so the
//! `<name>.<format>` image the python code builds does not leak an empty sibling file. The format
//! suffix is appended to an explicit path as well, exactly like python.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand::distributions::Alphanumeric;
use rand::Rng;

use crate::utils;

/// Filesystem formats this facility knows how to create.
pub const KNOWN_FILEFS_FORMATS: [&str; 1] = ["ext4"];

/// Facility for creating and working with filesystems (python `FilesystemFile`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemFile {
    path: PathBuf,
}

impl FilesystemFile {
    /// Default image size in MiB, matching python's `size=256`.
    pub const DEFAULT_SIZE_MIB: u64 = 256;
    /// Default filesystem format.
    pub const DEFAULT_FORMAT: &'static str = "ext4";

    /// Creates a new filesystem image backed by a file.
    pub fn new(path: Option<&Path>, size_mib: u64, fs_format: &str) -> Result<Self> {
        let path = Self::backing_path(path, fs_format)?;
        if path.is_file() {
            bail!("File already exists: {}", path.display());
        }
        // python: dd status=none if=/dev/zero of=<path> bs=1M count=<size>
        utils::check_output(&format!(
            "dd status=none if=/dev/zero of={} bs=1M count={size_mib}",
            path.display()
        ))
        .context("allocating the filesystem image")?;
        utils::check_output(&format!("mkfs.ext4 -qF {}", path.display()))
            .context("formatting the filesystem image")?;
        Ok(Self { path })
    }

    /// Creates a filesystem image with python's default size and format.
    pub fn with_defaults(path: Option<&Path>) -> Result<Self> {
        Self::new(path, Self::DEFAULT_SIZE_MIB, Self::DEFAULT_FORMAT)
    }

    /// Resolves the image path for `path`/`fs_format` without touching the filesystem.
    pub fn backing_path(path: Option<&Path>, fs_format: &str) -> Result<PathBuf> {
        if !KNOWN_FILEFS_FORMATS.contains(&fs_format) {
            bail!("Format not in: + {:?}", KNOWN_FILEFS_FORMATS);
        }
        let base = match path {
            // Force the image onto disk rather than tmpfs: vhost-user-blk backends use O_DIRECT,
            // which tmpfs does not support.
            None => std::env::temp_dir().join(random_temp_name()),
            Some(path) => path.to_path_buf(),
        };
        Ok(PathBuf::from(format!("{}.{fs_format}", base.display())))
    }

    /// Returns the path of the backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Resizes the image to `new_size_mib` MiB and grows the filesystem inside it.
    pub fn resize(&self, new_size_mib: u64) -> Result<()> {
        utils::check_output(&format!(
            "truncate --size {new_size_mib}M {}",
            self.path.display()
        ))
        .context("truncating the filesystem image")?;
        utils::check_output(&format!("resize2fs {}", self.path.display()))
            .context("growing the filesystem")?;
        Ok(())
    }

    /// Returns the size of the backing file in bytes.
    pub fn size(&self) -> Result<u64> {
        let metadata = std::fs::metadata(&self.path)
            .with_context(|| format!("stat {}", self.path.display()))?;
        Ok(metadata.len())
    }
}

impl fmt::Display for FilesystemFile {
    /// Renders python's `repr`: `<FilesystemFile path=... size=...>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let size = self
            .size()
            .map(|size| size.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        write!(
            f,
            "<FilesystemFile path={} size={size}>",
            self.path.display()
        )
    }
}

impl Drop for FilesystemFile {
    /// Removes the image, matching python's `__del__` best-effort cleanup.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Builds a `mkstemp`-style base name, without creating the file.
fn random_temp_name() -> String {
    let suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();
    format!("tmp{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backing_path_appends_the_format() {
        let path = FilesystemFile::backing_path(Some(Path::new("/tmp/disk")), "ext4")
            .expect("valid format");
        assert_eq!(path, PathBuf::from("/tmp/disk.ext4"));
    }

    #[test]
    fn unknown_format_is_rejected() {
        let err = FilesystemFile::backing_path(Some(Path::new("/tmp/disk")), "btrfs")
            .expect_err("btrfs is not supported");
        assert!(err.to_string().contains("Format not in: +"), "{err}");
    }

    #[test]
    fn generated_names_are_unique_and_prefixed() {
        let first = FilesystemFile::backing_path(None, "ext4").expect("valid format");
        let second = FilesystemFile::backing_path(None, "ext4").expect("valid format");
        assert_ne!(first, second);
        assert!(first.starts_with(std::env::temp_dir()));
        assert!(first
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .starts_with("tmp"));
        assert!(first.to_string_lossy().ends_with(".ext4"));
        assert_eq!(
            first.parent().expect("parent"),
            std::env::temp_dir().as_path()
        );
    }

    #[test]
    fn display_matches_python_repr() {
        let file = FilesystemFile {
            path: PathBuf::from("/nonexistent/disk.ext4"),
        };
        assert_eq!(
            file.to_string(),
            "<FilesystemFile path=/nonexistent/disk.ext4 size=unknown>"
        );
        // Dropping a missing image must not panic.
        drop(file);
    }
}
