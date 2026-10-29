// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host processor introspection, ported from `tests/host_tools/proc.py`.
//!
//! `psutil`-free: `/proc/cpuinfo` is read directly and `uname -m` is replaced by a `libc::uname`
//! call, so nothing here shells out. Like python, the value keeps the whitespace that followed the
//! `model name` separator.

use anyhow::{Context, Result};

/// Model name reported for ARM hosts where `/proc/cpuinfo` has no `model name` line.
pub const ARM_PROC_MODEL: &str = "ARM";

/// Applies python's `re.sub(".*model name.*:", "", line, count=1)` to a single cpuinfo line.
pub fn model_name_suffix(line: &str) -> Option<String> {
    let name_at = line.rfind("model name")?;
    match line[name_at..].rfind(':') {
        Some(offset) => Some(line[name_at + offset + 1..].to_string()),
        // Without a colon after the field name the python regex does not match at all and the
        // line is returned unchanged.
        None => Some(line.to_string()),
    }
}

/// Returns the value of the first `model name` field of a `/proc/cpuinfo` dump.
pub fn model_name_from_cpuinfo(cpuinfo: &str) -> Option<String> {
    cpuinfo.lines().find_map(model_name_suffix)
}

/// Resolves the processor model from cpuinfo contents and the `uname -m` machine string.
pub fn proc_type_from(cpuinfo: &str, machine: &str) -> String {
    if let Some(model) = model_name_from_cpuinfo(cpuinfo) {
        return model;
    }
    if machine.contains("aarch64") {
        return ARM_PROC_MODEL.to_string();
    }
    String::new()
}

/// Returns the host processor model, mirroring python `proc_type()`.
pub fn proc_type() -> Result<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
        .context("reading /proc/cpuinfo while detecting the processor model")?;
    let machine = uname_machine().unwrap_or_default();
    Ok(proc_type_from(&cpuinfo, &machine))
}

/// Returns the `machine` field of `uname`, i.e. what `uname -m` prints.
pub fn uname_machine() -> Result<String> {
    // SAFETY: `uname` fills a zeroed `utsname` owned by this frame.
    let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `buf` is a valid, writable `utsname`.
    let rc = unsafe { libc::uname(&mut buf) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("calling uname");
    }
    let bytes: Vec<u8> = buf
        .machine
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86_CPUINFO: &str = "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD EPYC 7R32\ncpu MHz\t\t: 2800.000\n\nprocessor\t: 1\nmodel name\t: AMD EPYC 7R32\n";

    #[test]
    fn model_name_suffix_strips_up_to_last_colon() {
        // python keeps the leading space produced by the substitution.
        assert_eq!(
            model_name_suffix("model name\t: AMD EPYC 7R32").as_deref(),
            Some(" AMD EPYC 7R32")
        );
        assert_eq!(model_name_suffix("processor\t: 0"), None);
        assert_eq!(
            model_name_suffix("model name without colon").as_deref(),
            Some("model name without colon")
        );
    }

    #[test]
    fn model_name_uses_last_field_occurrence() {
        assert_eq!(
            model_name_suffix("model name: model name: ARMv8").as_deref(),
            Some(" ARMv8")
        );
    }

    #[test]
    fn cpuinfo_model_is_preferred() {
        assert_eq!(
            model_name_from_cpuinfo(X86_CPUINFO).as_deref(),
            Some(" AMD EPYC 7R32")
        );
        assert_eq!(proc_type_from(X86_CPUINFO, "x86_64"), " AMD EPYC 7R32");
    }

    #[test]
    fn arm_fallback_and_empty_fallback() {
        assert_eq!(
            proc_type_from("processor\t: 0\n", "aarch64"),
            ARM_PROC_MODEL
        );
        assert_eq!(proc_type_from("processor\t: 0\n", "riscv64"), "");
        // A cpuinfo model wins over the machine fallback.
        assert_eq!(proc_type_from(X86_CPUINFO, "aarch64"), " AMD EPYC 7R32");
    }
}
