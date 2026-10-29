// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Guest kernel and rootfs artifacts, ported from
//! `tests/framework/artifacts.py`.
//!
//! `pytest.param` catalogues become [`GuestKernel`] vectors: pytest ids are
//! preserved through [`GuestKernel::pytest_id`] so generated pipeline commands
//! can keep selecting tests by id.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use crate::defs;

/// Guest kernel `<major>.<minor>` versions the suite supports.
pub const SUPPORTED_KERNEL_VERSIONS: [&str; 3] = ["5.10", "6.1", "6.18"];

/// Versions for which the non-ACPI (MPTable) variant is also tested.
pub const NO_ACPI_KERNEL_VERSIONS: [&str; 1] = ["5.10"];

/// Logical guest kernel variant and its concrete boot artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestKernel {
    pub version: String,
    pub acpi: bool,
    pub vmlinux: PathBuf,
    pub efi_image: Option<PathBuf>,
    pub debug: bool,
    pub bzimage: Option<PathBuf>,
}

impl GuestKernel {
    /// Builds a logical guest kernel from a Firecracker `vmlinux-*` artifact.
    pub fn from_vmlinux(vmlinux: &Path) -> Result<Self> {
        let name = vmlinux
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| anyhow!("kernel path has no file name: {}", vmlinux.display()))?;
        let (version, acpi) = parse_vmlinux_name(&name)
            .ok_or_else(|| anyhow!("Unsupported guest kernel artifact: {}", vmlinux.display()))?;

        let debug = vmlinux
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n == "debug")
            .unwrap_or(false);

        let (efi_image, bzimage) = match defs::host_arch() {
            // aarch64 uses the Image format, which boots both directly and via EFI.
            "aarch64" => (Some(vmlinux.to_path_buf()), None),
            "x86_64" => {
                // bzImage direct boot also supports the legacy no-ACPI variant.
                let path = vmlinux.with_file_name(name.replacen("vmlinux-", "bzImage-", 1));
                let bzimage = path.exists().then(|| path.clone());
                // Keep EFI eligibility separate from the image format.
                let efi = if acpi { bzimage.clone() } else { None };
                (efi, bzimage)
            }
            arch => bail!("Unsupported host architecture: {arch}"),
        };

        Ok(Self {
            version,
            acpi,
            vmlinux: vmlinux.to_path_buf(),
            efi_image,
            debug,
            bzimage,
        })
    }

    /// Stable id matching the canonical Firecracker kernel artifact.
    pub fn pytest_id(&self) -> String {
        self.vmlinux
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Kernel dimension value independent of the backend boot image
    /// (`linux-<major>.<minor>`, patch version dropped).
    pub fn metric_id(&self) -> String {
        let major_minor = self
            .version
            .split('.')
            .take(2)
            .collect::<Vec<_>>()
            .join(".");
        format!("linux-{major_minor}")
    }

    /// Dotted version tuple, as used by `vm.guest_kernel_version`.
    pub fn version_tuple(&self) -> Vec<u32> {
        self.version
            .split('.')
            .map(|part| part.parse::<u32>().unwrap_or(0))
            .collect()
    }
}

/// Parses a `vmlinux-*` artifact filename into `(version, acpi)`.
///
/// ```text
/// vmlinux-6.1.168        -> ("6.1.168", true)
/// vmlinux-5.10.233-no-acpi -> ("5.10.233", false)
/// bzImage-6.1.168        -> None
/// ```
pub fn parse_vmlinux_name(name: &str) -> Option<(String, bool)> {
    let rest = name.strip_prefix("vmlinux-")?;
    let (version, no_acpi) = match rest.strip_suffix("-no-acpi") {
        Some(version) => (version, true),
        None => (rest, false),
    };
    let mut parts = version.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    if !is_numeric(major) || !is_numeric(minor) {
        return None;
    }
    match parts.next() {
        Some(patch) if !is_numeric(patch) => return None,
        Some(_) => {}
        None => {}
    }
    if parts.next().is_some() {
        return None;
    }
    Some((version.to_string(), !no_acpi))
}

fn is_numeric(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// Returns the artifact paths for guest kernels the suite supports.
pub fn kernels(glob: &str, artifact_dir: &Path) -> Result<Vec<PathBuf>> {
    let pattern = glob_to_regex(glob);
    let mut entries: Vec<PathBuf> = std::fs::read_dir(artifact_dir)
        .with_context(|| format!("reading {}", artifact_dir.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.file_name()
                .map(|name| pattern.is_match(&name.to_string_lossy()))
                .unwrap_or(false)
        })
        .collect();
    entries.sort();

    let mut supported = Vec::new();
    for kernel in entries {
        let name = kernel
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some((version, acpi)) = parse_vmlinux_name(&name) else {
            if name.ends_with(".config") || name.ends_with(".debug") {
                continue;
            }
            bail!("Unsupported guest kernel artifact: {}", kernel.display());
        };
        // Require a patch version (e.g. 6.1.168, not 6.1).
        if version.split('.').count() != 3 {
            bail!(
                "Guest kernel artifact must include a patch version: {}",
                kernel.display()
            );
        }
        let major_minor = version.split('.').take(2).collect::<Vec<_>>().join(".");
        if !SUPPORTED_KERNEL_VERSIONS.contains(&major_minor.as_str()) {
            bail!(
                "Unsupported guest kernel version {version}: {}",
                kernel.display()
            );
        }
        if !acpi && !NO_ACPI_KERNEL_VERSIONS.contains(&major_minor.as_str()) {
            bail!(
                "Unsupported non-ACPI guest kernel version {version}: {}",
                kernel.display()
            );
        }
        supported.push(kernel);
    }
    Ok(supported)
}

/// Returns supported rootfs images matching `glob`.
pub fn disks(glob: &str, artifact_dir: &Path) -> Result<Vec<PathBuf>> {
    let pattern = glob_to_regex(glob);
    let mut entries: Vec<PathBuf> = std::fs::read_dir(artifact_dir)
        .with_context(|| format!("reading {}", artifact_dir.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.file_name()
                .map(|name| pattern.is_match(&name.to_string_lossy()))
                .unwrap_or(false)
        })
        .collect();
    entries.sort();
    Ok(entries)
}

/// Translates a shell-style glob (`*`, `?`) into an anchored regex.
fn glob_to_regex(glob: &str) -> regex::Regex {
    let mut pattern = String::from("^");
    for ch in glob.chars() {
        match ch {
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            other => pattern.push_str(&regex::escape(&other.to_string())),
        }
    }
    pattern.push('$');
    regex::Regex::new(&pattern).expect("generated regex is valid")
}

/// All guest kernels with a supported version, in artifact order.
pub fn all_guest_kernels(artifact_dir: &Path) -> Result<Vec<GuestKernel>> {
    resolve_kernels(kernels("vmlinux-*", artifact_dir)?)
}

/// Guest kernels without the `-no-acpi` suffix.
pub fn acpi_guest_kernels(artifact_dir: &Path) -> Result<Vec<GuestKernel>> {
    Ok(all_guest_kernels(artifact_dir)?
        .into_iter()
        .filter(|kernel| kernel.acpi)
        .collect())
}

/// Guest kernels matching a `<major>.<minor>` prefix.
pub fn guest_kernels_for(version: &str, artifact_dir: &Path) -> Result<Vec<GuestKernel>> {
    resolve_kernels(kernels(&format!("vmlinux-{version}*"), artifact_dir)?)
}

/// The single canonical kernel used when a test pins to one version.
pub fn guest_kernel_default(artifact_dir: &Path) -> Result<Option<GuestKernel>> {
    Ok(guest_kernels_for("6.1", artifact_dir)?.into_iter().next())
}

/// Same as [`guest_kernel_default`] but from the `debug/` artifact subdirectory.
pub fn guest_kernel_default_debug(artifact_dir: &Path) -> Result<Option<GuestKernel>> {
    let debug_dir = artifact_dir.join("debug");
    if !debug_dir.exists() {
        return Ok(None);
    }
    Ok(guest_kernels_for("6.1", &debug_dir)?.into_iter().next())
}

fn resolve_kernels(paths: Vec<PathBuf>) -> Result<Vec<GuestKernel>> {
    paths
        .iter()
        .map(|path| GuestKernel::from_vmlinux(path))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vmlinux_name_accepts_supported_shapes() {
        assert_eq!(
            parse_vmlinux_name("vmlinux-6.1.168"),
            Some(("6.1.168".to_string(), true))
        );
        assert_eq!(
            parse_vmlinux_name("vmlinux-5.10.233-no-acpi"),
            Some(("5.10.233".to_string(), false))
        );
        assert_eq!(
            parse_vmlinux_name("vmlinux-6.18.1"),
            Some(("6.18.1".to_string(), true))
        );
    }

    #[test]
    fn parse_vmlinux_name_rejects_other_artifacts() {
        assert_eq!(parse_vmlinux_name("bzImage-6.1.168"), None);
        assert_eq!(parse_vmlinux_name("vmlinux-6.1.config"), None);
        assert_eq!(
            parse_vmlinux_name("vmlinux-6.1"),
            Some(("6.1".to_string(), true))
        );
        assert_eq!(parse_vmlinux_name("vmlinux-6.1.1.1"), None);
        assert_eq!(parse_vmlinux_name("rootfs-ubuntu.ext4"), None);
    }

    #[test]
    fn metric_id_drops_patch_version() {
        let kernel = GuestKernel {
            version: "5.10.233".to_string(),
            acpi: false,
            vmlinux: PathBuf::from("vmlinux-5.10.233-no-acpi"),
            efi_image: None,
            debug: false,
            bzimage: None,
        };
        assert_eq!(kernel.metric_id(), "linux-5.10");
        assert_eq!(kernel.pytest_id(), "vmlinux-5.10.233-no-acpi");
        assert_eq!(kernel.version_tuple(), vec![5, 10, 233]);
    }

    #[test]
    fn glob_to_regex_is_anchored() {
        let re = glob_to_regex("vmlinux-*");
        assert!(re.is_match("vmlinux-6.1.168"));
        assert!(!re.is_match("bzImage-6.1.168"));
        let re = glob_to_regex("*.ext4");
        assert!(re.is_match("rootfs.ext4"));
        assert!(!re.is_match("rootfs.squashfs"));
    }

    #[test]
    fn kernels_filters_and_sorts_artifacts() {
        let dir = std::env::temp_dir().join(format!("fc-artifacts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in [
            "vmlinux-6.1.168",
            "vmlinux-5.10.233-no-acpi",
            "vmlinux-6.1.168.config",
            "rootfs.ext4",
        ] {
            std::fs::write(dir.join(name), b"").unwrap();
        }
        let found = kernels("vmlinux-*", &dir).unwrap();
        assert_eq!(
            found,
            vec![
                dir.join("vmlinux-5.10.233-no-acpi"),
                dir.join("vmlinux-6.1.168")
            ]
        );
        let disks = disks("*.ext4", &dir).unwrap();
        assert_eq!(disks, vec![dir.join("rootfs.ext4")]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn kernels_rejects_unsupported_version() {
        let dir = std::env::temp_dir().join(format!("fc-artifacts-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vmlinux-4.14.1"), b"").unwrap();
        let err = kernels("vmlinux-*", &dir).unwrap_err().to_string();
        assert!(err.contains("Unsupported guest kernel version"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_patch_version_is_rejected() {
        let dir = std::env::temp_dir().join(format!("fc-artifacts-patch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vmlinux-6.1"), b"").unwrap();
        let err = kernels("vmlinux-*", &dir).unwrap_err().to_string();
        assert!(err.contains("must include a patch version"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
