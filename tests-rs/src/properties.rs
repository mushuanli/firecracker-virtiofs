// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-run environment metadata, ported from `tests/framework/properties.py`.
//!
//! `GlobalProps` is collected once through [`global_props`], mirroring the
//! module-level `global_props = GlobalProps()` in the python harness.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use crate::defs;
use crate::utils;

/// Environment kind detected for this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Ec2,
    Local,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Ec2 => "ec2",
            Environment::Local => "local",
        }
    }
}

/// Metadata attached to test reports and CloudWatch dimensions.
#[derive(Debug, Clone)]
pub struct GlobalProps {
    pub cpu_architecture: String,
    pub cpu_model: String,
    pub cpu_codename: String,
    pub cpu_vendor: String,
    pub cpu_microcode: String,
    pub host_linux_full_version: String,
    /// `major.minor`
    pub host_linux_version: String,
    /// `major.minor.patch`
    pub host_linux_patch: String,
    pub os: String,
    pub host_os: String,
    pub libc_ver: String,
    pub rust_version: String,
    pub buildkite_pipeline_slug: Option<String>,
    pub buildkite_build_number: Option<String>,
    pub buildkite_pr: bool,
    pub buildkite_revision_a: Option<String>,
    pub is_dev_env: bool,
    pub git_commit_id: Option<String>,
    pub git_branch: Option<String>,
    pub git_origin_url: Option<String>,
    pub environment: Environment,
    pub instance: String,
    pub instance_id: String,
    pub ami: String,
    pub is_ec2_virt: bool,
}

impl GlobalProps {
    /// Collects the metadata for the current environment.
    pub fn collect() -> Self {
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let release = defs::host_kernel_version(3);

        let in_git_repo = utils::run_cmd("git rev-parse --show-toplevel")
            .map(|out| out.success())
            .unwrap_or(false);

        let (git_commit_id, git_branch, git_origin_url) = if in_git_repo {
            (
                run_trimmed("git rev-parse HEAD"),
                run_trimmed("git show -s --pretty=%D HEAD"),
                run_trimmed("git config --get remote.origin.url"),
            )
        } else {
            (None, None, None)
        };

        let environment = match crate::imdsv2::imdsv2_get("/meta-data/instance-type") {
            Ok(_) => Environment::Ec2,
            Err(_) => Environment::Local,
        };

        let (instance, instance_id, ami, is_ec2_virt) = if environment == Environment::Ec2 {
            let instance =
                crate::imdsv2::imdsv2_get("/meta-data/instance-type").unwrap_or_default();
            let instance_id =
                crate::imdsv2::imdsv2_get("/meta-data/instance-id").unwrap_or_default();
            let ami = crate::imdsv2::imdsv2_get("/meta-data/ami-id").unwrap_or_default();
            let is_virt = !instance.contains("metal");
            (instance, instance_id, ami, is_virt)
        } else {
            ("NA".to_string(), "NA".to_string(), "NA".to_string(), false)
        };

        Self {
            cpu_architecture: std::env::consts::ARCH.to_string(),
            cpu_model: cpuinfo_value(&cpuinfo, "model name")
                .unwrap_or_else(|| "unknown".to_string()),
            cpu_codename: cpu_codename(&cpuinfo).unwrap_or_else(|| "unknown".to_string()),
            cpu_vendor: cpuinfo_value(&cpuinfo, "vendor_id")
                .unwrap_or_else(|| "unknown".to_string())
                .to_lowercase(),
            cpu_microcode: cpuinfo_value(&cpuinfo, "microcode")
                .unwrap_or_else(|| "unknown".to_string()),
            host_linux_version: host_linux_version(1),
            host_linux_patch: host_linux_version(2),
            host_linux_full_version: release,
            os: get_os_version().unwrap_or_else(|| "NA".to_string()),
            host_os: get_host_os(None),
            libc_ver: libc_version(),
            rust_version: run_trimmed("rustc --version |awk '{print $2}'")
                .unwrap_or_else(|| "NA".to_string()),
            buildkite_pipeline_slug: std::env::var("BUILDKITE_PIPELINE_SLUG").ok(),
            buildkite_build_number: std::env::var("BUILDKITE_BUILD_NUMBER").ok(),
            buildkite_pr: std::env::var("BUILDKITE_PULL_REQUEST")
                .map(|v| v != "false")
                .unwrap_or(false),
            buildkite_revision_a: std::env::var("BUILDKITE_PULL_REQUEST_BASE_BRANCH").ok(),
            is_dev_env: std::env::var("FC_TEST_DEVELOPMENT_ENVIRONMENT").as_deref() == Ok("1"),
            git_commit_id,
            git_branch,
            git_origin_url,
            environment,
            instance,
            instance_id,
            ami,
            is_ec2_virt,
        }
    }

    /// Host Linux version `major.minor` as a tuple, for easy comparison.
    pub fn host_linux_version_tpl(&self) -> (u32, u32) {
        let mut parts = self
            .host_linux_version
            .split('.')
            .map(|p| p.parse::<u32>().unwrap_or(0));
        (parts.next().unwrap_or(0), parts.next().unwrap_or(0))
    }

    /// Whether this run is on an EC2 instance.
    pub fn is_ec2(&self) -> bool {
        self.environment == Environment::Ec2
    }

    /// Flat key/value view used for report metadata.
    pub fn as_map(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert("cpu_architecture".into(), self.cpu_architecture.clone());
        map.insert("cpu_model".into(), self.cpu_model.clone());
        map.insert("cpu_vendor".into(), self.cpu_vendor.clone());
        map.insert("host_linux_version".into(), self.host_linux_version.clone());
        map.insert("os".into(), self.os.clone());
        map.insert("environment".into(), self.environment.as_str().into());
        map.insert("instance".into(), self.instance.clone());
        map.insert(
            "git_commit_id".into(),
            self.git_commit_id.clone().unwrap_or_default(),
        );
        map
    }
}

/// Process-wide metadata, matching python's module-level `global_props`.
pub fn global_props() -> &'static GlobalProps {
    static PROPS: OnceLock<GlobalProps> = OnceLock::new();
    PROPS.get_or_init(GlobalProps::collect)
}

fn run_trimmed(cmd: &str) -> Option<String> {
    utils::run_cmd(cmd)
        .ok()
        .filter(|out| out.success())
        .map(|out| out.stdout.trim().to_string())
}

fn cpuinfo_value(cpuinfo: &str, key: &str) -> Option<String> {
    cpuinfo.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then(|| value.trim().to_string())
    })
}

/// Rough codename map, equivalent to `get_cpu_codename` in `utils_cpuid.py`.
fn cpu_codename(cpuinfo: &str) -> Option<String> {
    let model = cpuinfo_value(cpuinfo, "model name")?.to_lowercase();
    let codename =
        if model.contains("milan") || model.contains("genoa") || model.contains("bergamo") {
            "AMD"
        } else if model.contains("intel") {
            "Intel"
        } else if model.contains("graviton") {
            "ARM"
        } else {
            "unknown"
        };
    Some(codename.to_string())
}

/// `PRETTY_NAME` from `/etc/os-release`.
pub fn get_os_version() -> Option<String> {
    let contents = std::fs::read_to_string("/etc/os-release").ok()?;
    contents
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim().trim_matches('"').to_string())
}

/// Extracts OS information from the kernel version when present (AL2/AL2023).
pub fn get_host_os(kernel_version: Option<&str>) -> String {
    let owned;
    let kv = match kernel_version {
        Some(kv) => kv,
        None => {
            owned = defs::host_kernel_version(3);
            &owned
        }
    };
    let parts: Vec<&str> = kv.split('-').collect();
    if parts.len() < 2 {
        return kv.to_string();
    }
    let misc: Vec<&str> = parts[1].split('.').collect();
    if misc.len() > 2 && (misc[2] == "amzn2" || misc[2] == "amzn2023") {
        return misc[2].to_string();
    }
    kv.to_string()
}

fn host_linux_version(level: usize) -> String {
    defs::host_kernel_version(level)
}

fn libc_version() -> String {
    // python uses platform.libc_ver(); reading the gnu version from the
    // process is not portable, so report the glibc marker when present.
    if Path::new("/lib/x86_64-linux-gnu/libc.so.6").exists()
        || Path::new("/lib/aarch64-linux-gnu/libc.so.6").exists()
    {
        "glibc".to_string()
    } else {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_os_detects_al2023() {
        assert_eq!(
            get_host_os(Some("6.1.41-63.118.amzn2023.x86_64")),
            "amzn2023"
        );
        assert_eq!(get_host_os(Some("6.1.41-63.1.amzn2.x86_64")), "amzn2");
        assert_eq!(get_host_os(Some("6.1.0-13-amd64")), "6.1.0-13-amd64");
        assert_eq!(get_host_os(Some("6.1.0")), "6.1.0");
    }

    #[test]
    fn cpuinfo_parsing() {
        let cpuinfo = "vendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Platinum\n";
        assert_eq!(cpuinfo_value(cpuinfo, "vendor_id").unwrap(), "GenuineIntel");
        assert!(cpuinfo_value(cpuinfo, "microcode").is_none());
    }

    #[test]
    fn global_props_is_stable() {
        let first = global_props();
        let second = global_props();
        assert_eq!(first.host_linux_version, second.host_linux_version);
        assert!(!first.cpu_architecture.is_empty());
    }
}
