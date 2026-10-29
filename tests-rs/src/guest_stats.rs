// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Guest memory statistics, ported from `tests/framework/guest_stats.py`.
//!
//! Python's `MeminfoGuest` takes the whole microVM object and reaches for
//! `vm.ssh`; the port asks for the [`SshConnection`] directly and keeps the
//! `/proc/meminfo` parsing in a pure [`parse_meminfo`] helper so it can be
//! unit-tested without a guest.

use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::network::SshConnection;

/// Timeout used for the guest command, matching the python wrapper's default.
pub const SSH_TIMEOUT: Duration = Duration::from_secs(100);

/// Represents a byte quantity that can be expressed in other units.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ByteUnit {
    value_bytes: u64,
}

impl ByteUnit {
    /// Creates a unit from a value in bytes.
    pub fn new(value_bytes: u64) -> Self {
        Self { value_bytes }
    }

    /// Creates a unit from a value in KiB, rejecting negative values.
    pub fn from_kib(value_kib: i64) -> Result<Self> {
        if value_kib < 0 {
            bail!("value_kib must be non-negative, got {value_kib}");
        }
        Ok(Self::new(value_kib as u64 * 1024))
    }

    /// Returns the value in bytes.
    pub fn bytes(&self) -> u64 {
        self.value_bytes
    }

    /// Returns the value in KiB as a decimal.
    pub fn kib(&self) -> f64 {
        self.value_bytes as f64 / 1024.0
    }

    /// Returns the value in MiB as a decimal.
    pub fn mib(&self) -> f64 {
        self.value_bytes as f64 / (1u64 << 20) as f64
    }

    /// Returns the value in GiB as a decimal.
    pub fn gib(&self) -> f64 {
        self.value_bytes as f64 / (1u64 << 30) as f64
    }
}

/// The contents of `/proc/meminfo` inside the guest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meminfo {
    /// `MemTotal:`.
    pub mem_total: ByteUnit,
    /// `MemFree:`.
    pub mem_free: ByteUnit,
    /// `MemAvailable:`.
    pub mem_available: ByteUnit,
    /// `Buffers:`.
    pub buffers: ByteUnit,
    /// `Cached:`.
    pub cached: ByteUnit,
}

impl Meminfo {
    /// Creates an all-zero `Meminfo`, like the python constructor.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Parses `/proc/meminfo` output, ignoring keys the type does not model.
pub fn parse_meminfo(contents: &str) -> Result<Meminfo> {
    let mut meminfo = Meminfo::new();
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let slot = match key {
            "MemTotal:" => &mut meminfo.mem_total,
            "MemFree:" => &mut meminfo.mem_free,
            "MemAvailable:" => &mut meminfo.mem_available,
            "Buffers:" => &mut meminfo.buffers,
            "Cached:" => &mut meminfo.cached,
            _ => continue,
        };
        let raw = parts
            .next()
            .with_context(|| format!("missing value for {key} in /proc/meminfo"))?;
        let kib: i64 = raw
            .parse()
            .with_context(|| format!("parsing value {raw:?} for {key}"))?;
        *slot = ByteUnit::from_kib(kib)?;
    }
    Ok(meminfo)
}

/// Queries `/proc/meminfo` inside the guest.
#[derive(Debug)]
pub struct MeminfoGuest<'a> {
    ssh: &'a SshConnection,
}

impl<'a> MeminfoGuest<'a> {
    /// Creates a querier bound to the guest connection.
    pub fn new(ssh: &'a SshConnection) -> Self {
        Self { ssh }
    }

    /// Returns the contents of `/proc/meminfo` inside the guest.
    pub fn get(&self) -> Result<Meminfo> {
        let stdout = self
            .ssh
            .check_output("cat /proc/meminfo", SSH_TIMEOUT)
            .context("reading /proc/meminfo from the guest")?
            .stdout;
        parse_meminfo(&stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEMINFO: &str = "\
MemTotal:        1987360 kB
MemFree:          131072 kB
MemAvailable:     524288 kB
Buffers:            4096 kB
Cached:            65536 kB
SwapCached:            0 kB
Active:           999999 kB
";

    #[test]
    fn byte_unit_conversions() {
        let unit = ByteUnit::new(1024 * 1024);
        assert_eq!(unit.bytes(), 1048576);
        assert_eq!(unit.kib(), 1024.0);
        assert_eq!(unit.mib(), 1.0);
        assert_eq!(unit.gib(), 1.0 / 1024.0);
        assert_eq!(ByteUnit::default().bytes(), 0);
        assert_eq!(
            ByteUnit::from_kib(2048).expect("kib").bytes(),
            2 * 1024 * 1024
        );
    }

    #[test]
    fn byte_unit_rejects_negative_kib() {
        let err = ByteUnit::from_kib(-1).expect_err("negative kib must fail");
        assert!(err.to_string().contains("non-negative"));
    }

    #[test]
    fn meminfo_parses_the_modelled_keys_only() {
        let meminfo = parse_meminfo(MEMINFO).expect("parse meminfo");
        assert_eq!(meminfo.mem_total.bytes(), 1987360 * 1024);
        assert_eq!(meminfo.mem_free.kib(), 131072.0);
        assert_eq!(meminfo.mem_available.mib(), 512.0);
        assert_eq!(meminfo.buffers.kib(), 4096.0);
        assert_eq!(meminfo.cached.kib(), 65536.0);
        assert!(meminfo.mem_total.gib() > 1.8 && meminfo.mem_total.gib() < 2.0);
    }

    #[test]
    fn meminfo_defaults_to_zero_for_missing_keys() {
        let meminfo = parse_meminfo("Active: 10 kB\n").expect("parse meminfo");
        assert_eq!(meminfo, Meminfo::new());
    }

    #[test]
    fn meminfo_skips_blank_lines_and_reports_bad_values() {
        let meminfo = parse_meminfo("\n\nMemTotal: 8 kB\n\n").expect("parse meminfo");
        assert_eq!(meminfo.mem_total.bytes(), 8 * 1024);

        let err = parse_meminfo("MemTotal: not-a-number kB\n").expect_err("bad number must fail");
        assert!(err.to_string().contains("parsing value"));
        let err = parse_meminfo("MemTotal:\n").expect_err("missing value must fail");
        assert!(err.to_string().contains("missing value"));
    }
}
