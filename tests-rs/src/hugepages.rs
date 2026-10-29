// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Huge page configuration and host capability helpers, ported from
//! `tests/framework/utils_hugepages.py`.
//!
//! The python module only exposes the `HugePagesConfig` enum and the
//! `supports_hugetlbfs_discard()` kernel probe. The port keeps both and adds the
//! pure version comparison plus the API-string mapping so callers can translate
//! between the enum, the Firecracker API value and the `pytest` ids.

use std::fmt;

use crate::defs::host_kernel_version;

/// Kernel release that introduced `hugetlbfs` discard support.
pub const HUGETLBFS_DISCARD_MIN_KERNEL: (u64, u64, u64) = (5, 18, 0);

/// Returns true when the running kernel supports `hugetlbfs` discard.
///
/// Port of `supports_hugetlbfs_discard()`: `get_kernel_version()` uses
/// `platform.release()` truncated to `major.minor.patch`, which is what
/// [`host_kernel_version`] with level 2 returns.
pub fn supports_hugetlbfs_discard() -> bool {
    kernel_supports_hugetlbfs_discard(&host_kernel_version(2))
}

/// Pure form of [`supports_hugetlbfs_discard`] taking an explicit release string.
pub fn kernel_supports_hugetlbfs_discard(kernel_version: &str) -> bool {
    match parse_kernel_version(kernel_version) {
        Some(version) => version >= HUGETLBFS_DISCARD_MIN_KERNEL,
        None => false,
    }
}

/// Parses `major.minor[.patch]` and ignores any vendor suffix (`-45-generic`).
pub fn parse_kernel_version(kernel_version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = [0u64; 3];
    let mut seen = 0usize;
    for (index, part) in kernel_version.split('.').enumerate() {
        if index >= parts.len() {
            break;
        }
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        parts[index] = digits.parse().ok()?;
        seen = index + 1;
    }
    if seen == 0 {
        return None;
    }
    Some((parts[0], parts[1], parts[2]))
}

/// Huge pages configurations supported by Firecracker (`HugePagesConfig`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum HugePagesConfig {
    /// No huge pages (`NONE = "None"`).
    #[default]
    None,
    /// Transparent huge pages (`TRANSPARENT = "Transparent"`).
    Transparent,
    /// Explicit `hugetlbfs` backed 2 MiB pages (`HUGETLBFS_2MB = "2M"`).
    Hugetlbfs2Mb,
}

impl HugePagesConfig {
    /// Every variant, in the declaration order of the python enum.
    pub const ALL: [HugePagesConfig; 3] = [
        HugePagesConfig::None,
        HugePagesConfig::Transparent,
        HugePagesConfig::Hugetlbfs2Mb,
    ];

    /// The value sent to the Firecracker `/machine-config` API, i.e. the python
    /// enum value.
    pub const fn api_value(self) -> &'static str {
        match self {
            HugePagesConfig::None => "None",
            HugePagesConfig::Transparent => "Transparent",
            HugePagesConfig::Hugetlbfs2Mb => "2M",
        }
    }

    /// Parses a value produced by [`Self::api_value`] or used in `pytest` ids.
    pub fn from_api_value(value: &str) -> Option<Self> {
        match value {
            "None" => Some(HugePagesConfig::None),
            "Transparent" => Some(HugePagesConfig::Transparent),
            "2M" => Some(HugePagesConfig::Hugetlbfs2Mb),
            _ => None,
        }
    }

    /// Whether the guest memory has to be backed by `hugetlbfs` pages.
    pub const fn is_hugetlbfs(self) -> bool {
        matches!(self, HugePagesConfig::Hugetlbfs2Mb)
    }

    /// Size of the backing huge page, when a specific size is implied.
    pub const fn page_size_bytes(self) -> Option<u64> {
        match self {
            HugePagesConfig::Hugetlbfs2Mb => Some(2 << 20),
            HugePagesConfig::None | HugePagesConfig::Transparent => None,
        }
    }

    /// Rounds `mem_size_mib` up to a whole number of 2 MiB huge pages.
    ///
    /// Non-`hugetlbfs` configurations return `mem_size_mib` unchanged.
    pub fn aligned_mem_size_mib(self, mem_size_mib: u64) -> u64 {
        if self.is_hugetlbfs() {
            mem_size_mib.next_multiple_of(2)
        } else {
            mem_size_mib
        }
    }
}

impl fmt::Display for HugePagesConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.api_value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_values_match_python_enum() {
        assert_eq!(HugePagesConfig::None.api_value(), "None");
        assert_eq!(HugePagesConfig::Transparent.api_value(), "Transparent");
        assert_eq!(HugePagesConfig::Hugetlbfs2Mb.api_value(), "2M");
        assert_eq!(HugePagesConfig::Hugetlbfs2Mb.to_string(), "2M");
        assert_eq!(HugePagesConfig::default(), HugePagesConfig::None);
    }

    #[test]
    fn api_values_round_trip() {
        for config in HugePagesConfig::ALL {
            assert_eq!(
                HugePagesConfig::from_api_value(config.api_value()),
                Some(config)
            );
        }
        assert_eq!(HugePagesConfig::from_api_value("2m"), None);
        assert_eq!(HugePagesConfig::from_api_value("huge"), None);
    }

    #[test]
    fn only_hugetlbfs_has_a_page_size() {
        assert!(!HugePagesConfig::None.is_hugetlbfs());
        assert!(!HugePagesConfig::Transparent.is_hugetlbfs());
        assert!(HugePagesConfig::Hugetlbfs2Mb.is_hugetlbfs());
        assert_eq!(
            HugePagesConfig::Hugetlbfs2Mb.page_size_bytes(),
            Some(2 << 20)
        );
        assert_eq!(HugePagesConfig::None.page_size_bytes(), None);
    }

    #[test]
    fn mem_size_is_aligned_only_for_hugetlbfs() {
        assert_eq!(HugePagesConfig::None.aligned_mem_size_mib(1025), 1025);
        assert_eq!(
            HugePagesConfig::Transparent.aligned_mem_size_mib(1025),
            1025
        );
        assert_eq!(
            HugePagesConfig::Hugetlbfs2Mb.aligned_mem_size_mib(1025),
            1026
        );
        assert_eq!(
            HugePagesConfig::Hugetlbfs2Mb.aligned_mem_size_mib(1024),
            1024
        );
    }

    #[test]
    fn parses_kernel_versions() {
        assert_eq!(parse_kernel_version("5.18.0"), Some((5, 18, 0)));
        assert_eq!(parse_kernel_version("6.8"), Some((6, 8, 0)));
        assert_eq!(parse_kernel_version("6.8.0-45-generic"), Some((6, 8, 0)));
        assert_eq!(parse_kernel_version("garbage"), None);
    }

    #[test]
    fn discard_probe_matches_packaging_compare() {
        assert!(!kernel_supports_hugetlbfs_discard("5.17.9"));
        assert!(kernel_supports_hugetlbfs_discard("5.18.0"));
        assert!(kernel_supports_hugetlbfs_discard("5.18"));
        assert!(kernel_supports_hugetlbfs_discard("6.1.0"));
        assert!(kernel_supports_hugetlbfs_discard("6.8.0-45-generic"));
        assert!(!kernel_supports_hugetlbfs_discard(""));
    }
}
