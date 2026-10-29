// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Guest distro detection, ported from `tests/framework/guest.py`.

use std::path::Path;

/// Distro-specific guest properties, inferred from the rootfs filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestDistro {
    pub hostname: &'static str,
    pub ssh_service: &'static str,
    pub os_release_token: &'static str,
    pub shell_prompt: &'static str,
}

impl GuestDistro {
    /// Returns the distro matching the rootfs name, if recognised.
    pub fn from_rootfs(rootfs_path: &Path) -> Option<Self> {
        let name = rootfs_path
            .file_stem()
            .map(|stem| stem.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if name.contains("ubuntu") {
            return Some(Self::UBUNTU);
        }
        if name.contains("amazon") || name.contains("al2023") {
            return Some(Self::AL2023);
        }
        None
    }

    /// Ubuntu guest properties.
    pub const UBUNTU: Self = Self {
        hostname: "ubuntu-fc-uvm",
        ssh_service: "ssh.service",
        os_release_token: "ID=ubuntu",
        shell_prompt: "ubuntu-fc-uvm:~#",
    };

    /// Amazon Linux 2023 guest properties.
    pub const AL2023: Self = Self {
        hostname: "al2023-fc-uvm",
        ssh_service: "sshd.service",
        os_release_token: "ID=\"amzn\"",
        shell_prompt: "[root@al2023-fc-uvm ~]#",
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detects_ubuntu() {
        let distro = GuestDistro::from_rootfs(&PathBuf::from("rootfs-ubuntu-24.04.ext4")).unwrap();
        assert_eq!(distro, GuestDistro::UBUNTU);
        assert_eq!(distro.ssh_service, "ssh.service");
    }

    #[test]
    fn detects_amazon_linux() {
        assert_eq!(
            GuestDistro::from_rootfs(&PathBuf::from("rootfs-amazonlinux.ext4")).unwrap(),
            GuestDistro::AL2023
        );
        assert_eq!(
            GuestDistro::from_rootfs(&PathBuf::from("rootfs-al2023.ext4")).unwrap(),
            GuestDistro::AL2023
        );
    }

    #[test]
    fn unknown_distro_returns_none() {
        assert_eq!(
            GuestDistro::from_rootfs(&PathBuf::from("rootfs-alpine.ext4")),
            None
        );
    }
}
