// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Firecracker snapshots, ported from the `Snapshot`/`SnapshotType` half of
//! `tests/framework/microvm.py`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::defs;
use crate::network::NetIfaceConfig;
use crate::utils;

/// Supported snapshot types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotType {
    Full,
    Diff,
    DiffMincore,
}

impl SnapshotType {
    /// Does this snapshot type need rebasing on a base snapshot before restore?
    pub fn needs_rebase(&self) -> bool {
        matches!(self, SnapshotType::Diff | SnapshotType::DiffMincore)
    }

    /// Does taking this snapshot type require dirty page tracking?
    pub fn needs_dirty_page_tracking(&self) -> bool {
        matches!(self, SnapshotType::Diff)
    }

    /// String value expected by the Firecracker API.
    pub fn api_type(&self) -> &'static str {
        match self {
            SnapshotType::Full => "Full",
            SnapshotType::Diff | SnapshotType::DiffMincore => "Diff",
        }
    }

    /// Serialised value used in `snapshot.json`.
    pub fn as_str(&self) -> &'static str {
        match self {
            SnapshotType::Full => "FULL",
            SnapshotType::Diff => "DIFF",
            SnapshotType::DiffMincore => "DIFF_MINCORE",
        }
    }

    /// Parses the serialised value.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "FULL" | "Full" => Ok(SnapshotType::Full),
            "DIFF" | "Diff" => Ok(SnapshotType::Diff),
            "DIFF_MINCORE" | "DiffMincore" => Ok(SnapshotType::DiffMincore),
            other => bail!("unknown snapshot type {other}"),
        }
    }
}

impl std::fmt::Display for SnapshotType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A Firecracker snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub vmstate: PathBuf,
    pub mem: PathBuf,
    pub net_ifaces: Vec<NetIfaceConfig>,
    pub disks: BTreeMap<String, PathBuf>,
    pub ssh_key: PathBuf,
    pub snapshot_type: SnapshotType,
    pub meta: BTreeMap<String, String>,
}

impl Snapshot {
    /// Rebases this incremental snapshot onto `base`.
    pub fn rebase_snapshot(
        &self,
        base: &Snapshot,
        use_snapshot_editor: bool,
        binary_dir: &Path,
    ) -> Result<Snapshot> {
        if !self.snapshot_type.needs_rebase() {
            bail!("Cannot rebase {}", self.snapshot_type);
        }
        if use_snapshot_editor {
            run_snap_editor_rebase(&base.mem, &self.mem, binary_dir)?;
        } else {
            run_rebase_snap_bin(&base.mem, &self.mem)?;
        }

        let mut rebased = self.clone();
        rebased.mem = base.mem.clone();
        Ok(rebased)
    }

    /// Copies the snapshot files into the microVM jail under `<name>.src`.
    pub fn copy_to_chroot(&self, chroot: &Path) -> Result<Snapshot> {
        let mem_src = chroot.join(suffix_name(&self.mem, ".src"));
        hardlink_or_copy(&self.mem, &mem_src)?;
        let vmstate_src = chroot.join(suffix_name(&self.vmstate, ".src"));
        hardlink_or_copy(&self.vmstate, &vmstate_src)?;

        Ok(Snapshot {
            vmstate: vmstate_src,
            mem: mem_src,
            net_ifaces: self.net_ifaces.clone(),
            disks: self.disks.clone(),
            ssh_key: self.ssh_key.clone(),
            snapshot_type: self.snapshot_type,
            meta: self.meta.clone(),
        })
    }

    /// Loads a snapshot saved with [`Snapshot::save_to`].
    pub fn load_from(src: &Path) -> Result<Snapshot> {
        let snapshot_json = src.join("snapshot.json");
        let text = std::fs::read_to_string(&snapshot_json)
            .with_context(|| format!("reading {}", snapshot_json.display()))?;
        let obj: Value = serde_json::from_str(&text)
            .with_context(|| format!("parsing {}", snapshot_json.display()))?;

        let object = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("snapshot.json is not an object"))?;
        let path_of = |key: &str| -> Result<PathBuf> {
            object
                .get(key)
                .and_then(|v| v.as_str())
                .map(|name| src.join(name))
                .ok_or_else(|| anyhow::anyhow!("snapshot.json missing {key}"))
        };

        let net_ifaces = object
            .get("net_ifaces")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .map(NetIfaceConfig::from_json)
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();

        let mut disks = BTreeMap::new();
        if let Some(entries) = object.get("disks").and_then(|v| v.as_object()) {
            for (disk_id, name) in entries {
                let name = name
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("disk {disk_id} is not a string"))?;
                disks.insert(disk_id.clone(), src.join(name));
            }
        }

        let mut meta = BTreeMap::new();
        if let Some(entries) = object.get("meta").and_then(|v| v.as_object()) {
            for (key, value) in entries {
                meta.insert(key.clone(), value.as_str().unwrap_or_default().to_string());
            }
        }

        Ok(Snapshot {
            vmstate: path_of("vmstate")?,
            mem: path_of("mem")?,
            net_ifaces,
            disks,
            ssh_key: path_of("ssh_key")?,
            snapshot_type: SnapshotType::parse(
                object
                    .get("snapshot_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("FULL"),
            )?,
            meta,
        })
    }

    /// Serialises snapshot details to `dst`.
    pub fn save_to(&self, dst: &Path) -> Result<()> {
        std::fs::create_dir_all(dst).with_context(|| format!("creating {}", dst.display()))?;
        for path in [&self.vmstate, &self.mem, &self.ssh_key] {
            hardlink_or_copy(path, &dst.join(file_name(path)?))?;
        }
        let mut disk_names = serde_json::Map::new();
        for (disk_id, path) in &self.disks {
            hardlink_or_copy(path, &dst.join(file_name(path)?))?;
            disk_names.insert(disk_id.clone(), json!(file_name(path)?));
        }

        let mut meta = serde_json::Map::new();
        for (key, value) in &self.meta {
            meta.insert(key.clone(), json!(value));
        }

        let obj = json!({
            "vmstate": file_name(&self.vmstate)?,
            "mem": file_name(&self.mem)?,
            "net_ifaces": self.net_ifaces.iter().map(NetIfaceConfig::to_json).collect::<Vec<_>>(),
            "disks": disk_names,
            "ssh_key": file_name(&self.ssh_key)?,
            "snapshot_type": self.snapshot_type.as_str(),
            "meta": meta,
        });
        let snapshot_json = dst.join("snapshot.json");
        std::fs::write(&snapshot_json, serde_json::to_string(&obj)?)
            .with_context(|| format!("writing {}", snapshot_json.display()))?;
        Ok(())
    }

    /// Deletes the backing files from disk.
    pub fn delete(&self) -> Result<()> {
        std::fs::remove_file(&self.mem).ok();
        std::fs::remove_file(&self.vmstate).ok();
        Ok(())
    }
}

/// If `src` and `dst` are on the same device, hardlink. Otherwise, copy.
pub fn hardlink_or_copy(src: &Path, dst: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let src_meta = std::fs::metadata(src).with_context(|| format!("stat {}", src.display()))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .with_context(|| format!("creating {}", dst.display()))?;
    let dst_meta = std::fs::metadata(dst)?;
    if src_meta.dev() == dst_meta.dev() {
        std::fs::remove_file(dst)?;
        std::fs::hard_link(src, dst)
            .with_context(|| format!("hardlink {} -> {}", src.display(), dst.display()))?;
    } else {
        std::fs::copy(src, dst)
            .with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
    }
    Ok(())
}

/// Runs `snapshot-editor edit-memory rebase`.
pub fn run_snap_editor_rebase(base_snap: &Path, diff_snap: &Path, binary_dir: &Path) -> Result<()> {
    let snap_ed = binary_dir.join("snapshot-editor");
    let args = [
        snap_ed.to_string_lossy().into_owned(),
        "edit-memory".to_string(),
        "rebase".to_string(),
        "--memory-path".to_string(),
        base_snap.to_string_lossy().into_owned(),
        "--diff-path".to_string(),
        diff_snap.to_string_lossy().into_owned(),
    ];
    utils::check_output_args(&args)?;
    Ok(())
}

/// Runs the legacy `rebase-snap` binary.
pub fn run_rebase_snap_bin(base_snap: &Path, diff_snap: &Path) -> Result<()> {
    let rebase_snap = defs::default_binary_dir().join("rebase-snap");
    let args = [
        rebase_snap.to_string_lossy().into_owned(),
        "--base-file".to_string(),
        base_snap.to_string_lossy().into_owned(),
        "--diff-file".to_string(),
        diff_snap.to_string_lossy().into_owned(),
    ];
    utils::check_output_args(&args)?;
    Ok(())
}

fn file_name(path: &Path) -> Result<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", path.display()))
}

/// Appends `suffix` to the extension of `path` (`mem` -> `mem.src`).
fn suffix_name(path: &Path, suffix: &str) -> String {
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    match path.extension() {
        Some(ext) => format!("{stem}.{}{suffix}", ext.to_string_lossy()),
        None => format!("{stem}{suffix}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(dir: &Path) -> Snapshot {
        Snapshot {
            vmstate: dir.join("vmstate"),
            mem: dir.join("mem"),
            net_ifaces: vec![NetIfaceConfig::with_id(0, 30)],
            disks: BTreeMap::from([("rootfs".to_string(), dir.join("rootfs.ext4"))]),
            ssh_key: dir.join("ssh_key"),
            snapshot_type: SnapshotType::Diff,
            meta: BTreeMap::from([("kernel".to_string(), "6.1.168".to_string())]),
        }
    }

    #[test]
    fn type_flags_match_python() {
        assert!(!SnapshotType::Full.needs_rebase());
        assert!(SnapshotType::Diff.needs_rebase());
        assert!(SnapshotType::DiffMincore.needs_rebase());
        assert!(SnapshotType::Diff.needs_dirty_page_tracking());
        assert!(!SnapshotType::DiffMincore.needs_dirty_page_tracking());
        assert_eq!(SnapshotType::Full.api_type(), "Full");
        assert_eq!(SnapshotType::Diff.api_type(), "Diff");
        assert_eq!(SnapshotType::DiffMincore.api_type(), "Diff");
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("fc-snap-{}", std::process::id()));
        let src = dir.join("src");
        let dst = dir.join("dst");
        std::fs::create_dir_all(&src).unwrap();
        for name in ["vmstate", "mem", "ssh_key", "rootfs.ext4"] {
            std::fs::write(src.join(name), name.as_bytes()).unwrap();
        }
        let snapshot = snapshot(&src);
        snapshot.save_to(&dst).unwrap();

        let loaded = Snapshot::load_from(&dst).unwrap();
        assert_eq!(loaded.snapshot_type, SnapshotType::Diff);
        assert_eq!(loaded.disks["rootfs"], dst.join("rootfs.ext4"));
        assert_eq!(loaded.net_ifaces, snapshot.net_ifaces);
        assert_eq!(loaded.meta["kernel"], "6.1.168");
        assert_eq!(
            std::fs::read_to_string(&loaded.mem).unwrap(),
            std::fs::read_to_string(&snapshot.mem).unwrap()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_to_refuses_to_overwrite() {
        let dir = std::env::temp_dir().join(format!("fc-snap-dup-{}", std::process::id()));
        let src = dir.join("src");
        let dst = dir.join("dst");
        std::fs::create_dir_all(&src).unwrap();
        for name in ["vmstate", "mem", "ssh_key", "rootfs.ext4"] {
            std::fs::write(src.join(name), b"x").unwrap();
        }
        let snapshot = snapshot(&src);
        snapshot.save_to(&dst).unwrap();
        assert!(snapshot.save_to(&dst).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn suffix_names_follow_python() {
        assert_eq!(suffix_name(Path::new("/a/mem"), ".src"), "mem.src");
        assert_eq!(suffix_name(Path::new("/a/mem.bin"), ".src"), "mem.bin.src");
    }

    #[test]
    fn rebase_rejects_full_snapshots() {
        let dir = std::env::temp_dir();
        let mut snapshot = snapshot(&dir);
        snapshot.snapshot_type = SnapshotType::Full;
        let err = snapshot
            .rebase_snapshot(&snapshot, false, &dir)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Cannot rebase"), "{err}");
    }
}
