// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! KVM backend support, ported from `tests/framework/kvm.py`.
//!
//! [`crate::microvm::MicroVm::basic_config`] delegates here through
//! [`crate::vm_backend::VmBackend::Kvm`]; spawning and killing the Firecracker
//! process are backend-agnostic and live on `MicroVm` itself.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Result};
use serde_json::json;

use crate::http_api::json_body;
use crate::hugepages::HugePagesConfig;
use crate::microvm::{CpuTemplate, DriveConfig, MicroVm};

/// Default host device used for KVM microVMs.
pub const KVM_PATH: &str = "/dev/kvm";

/// Whether this host can run KVM microVMs.
pub fn has_kvm() -> bool {
    Path::new(KVM_PATH).exists()
}

/// Host KVM probe details for diagnostics.
pub fn kvm_probe_details() -> BTreeMap<String, String> {
    let path = Path::new(KVM_PATH);
    let mut details = BTreeMap::new();
    details.insert("device".to_string(), KVM_PATH.to_string());
    details.insert("exists".to_string(), path.exists().to_string());
    details.insert(
        "readable".to_string(),
        access(KVM_PATH, libc::R_OK).to_string(),
    );
    details.insert(
        "writable".to_string(),
        access(KVM_PATH, libc::W_OK).to_string(),
    );
    match std::fs::metadata(path) {
        Ok(metadata) => {
            details.insert(
                "mode".to_string(),
                format!("{:#o}", metadata.permissions().mode() & 0o7777),
            );
        }
        Err(err) => {
            details.insert("stat_error".to_string(), format!("{}: {err}", err.kind()));
        }
    }
    details
}

fn access(path: &str, mode: i32) -> bool {
    use std::ffi::CString;
    let Ok(c_path) = CString::new(path) else {
        return false;
    };
    // SAFETY: `c_path` is a valid NUL-terminated path.
    unsafe { libc::access(c_path.as_ptr(), mode) == 0 }
}

/// Shortcut configuration for a KVM microVM.
#[derive(Debug, Clone)]
pub struct KvmBasicConfig {
    pub vcpu_count: u32,
    pub smt: Option<bool>,
    pub mem_size_mib: u64,
    pub add_root_device: bool,
    pub boot_args: Option<String>,
    pub use_initrd: bool,
    pub track_dirty_pages: bool,
    pub huge_pages: HugePagesConfig,
    pub rootfs_io_engine: Option<String>,
    pub cpu_template: Option<CpuTemplate>,
    pub enable_entropy_device: bool,
}

impl Default for KvmBasicConfig {
    fn default() -> Self {
        Self {
            vcpu_count: 2,
            smt: None,
            mem_size_mib: 256,
            add_root_device: true,
            boot_args: None,
            use_initrd: false,
            track_dirty_pages: false,
            huge_pages: HugePagesConfig::None,
            rootfs_io_engine: None,
            cpu_template: None,
            enable_entropy_device: false,
        }
    }
}

/// The default guest kernel command line used by the suite.
pub const DEFAULT_BOOT_ARGS: &str =
    "reboot=k panic=1 nomodule swiotlb=noforce console=ttyS0 cryptomgr.notests";

/// Configures a microVM for KVM: CPU/memory, kernel image, root filesystem.
///
/// Does not start the microVM.
pub fn kvm_basic_config(vm: &mut MicroVm, config: KvmBasicConfig) -> Result<()> {
    vm.api()?.machine_config.put(json_body(vec![
        ("vcpu_count", Some(json!(config.vcpu_count))),
        ("smt", config.smt.map(|smt| json!(smt))),
        ("mem_size_mib", Some(json!(config.mem_size_mib))),
        ("track_dirty_pages", Some(json!(config.track_dirty_pages))),
        ("huge_pages", Some(json!(config.huge_pages.api_value()))),
    ]))?;

    vm.huge_pages = config.huge_pages;
    vm.vcpus_count = config.vcpu_count;
    vm.mem_size_bytes = config.mem_size_mib * (1 << 20);

    if let Some(template) = vm.custom_cpu_template.clone() {
        vm.set_cpu_template(Some(template))?;
    }
    if let Some(template) = config.cpu_template {
        vm.set_cpu_template(Some(template))?;
    }

    vm.boot_args = Some(match &config.boot_args {
        Some(boot_args) => boot_args.clone(),
        None => {
            let mut boot_args = DEFAULT_BOOT_ARGS.to_string();
            if !vm.pci_enabled {
                boot_args.push_str(" pci=off");
            }
            boot_args
        }
    });

    let kernel_file = vm
        .kernel_file()
        .ok_or_else(|| anyhow::anyhow!("microVM has no guest kernel configured"))?;
    let jailed_kernel = vm.create_jailed_resource(&kernel_file)?;

    let initrd = if config.use_initrd {
        match &vm.initrd_file.clone() {
            Some(initrd_file) => Some(vm.create_jailed_resource(initrd_file)?),
            None => None,
        }
    } else {
        None
    };

    vm.api()?.boot.put(json_body(vec![
        (
            "kernel_image_path",
            Some(json!(jailed_kernel.to_string_lossy())),
        ),
        (
            "boot_args",
            Some(json!(vm.boot_args.clone().unwrap_or_default())),
        ),
        (
            "initrd_path",
            initrd.map(|path| json!(path.to_string_lossy())),
        ),
    ]))?;

    if config.add_root_device {
        if let Some(rootfs_file) = vm.rootfs_file.clone() {
            let mut drive = DriveConfig::rootfs(rootfs_file);
            drive.io_engine = config.rootfs_io_engine.clone();
            vm.add_drive(drive)?;
        }
    }

    if config.enable_entropy_device {
        vm.enable_entropy_device()?;
    }
    Ok(())
}

/// Ensures `/dev/kvm` is usable, returning the probe details on failure.
pub fn require_kvm() -> Result<()> {
    let details = kvm_probe_details();
    if !has_kvm() {
        bail!("KVM is not available: {details:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_details_are_complete() {
        let details = kvm_probe_details();
        for key in ["device", "exists", "readable", "writable"] {
            assert!(details.contains_key(key), "missing {key}");
        }
        assert_eq!(details["device"], "/dev/kvm");
    }

    #[test]
    fn default_boot_args_match_python() {
        assert_eq!(
            DEFAULT_BOOT_ARGS,
            "reboot=k panic=1 nomodule swiotlb=noforce console=ttyS0 cryptomgr.notests"
        );
    }

    #[test]
    fn default_config_matches_python_defaults() {
        let config = KvmBasicConfig::default();
        assert_eq!(config.vcpu_count, 2);
        assert_eq!(config.mem_size_mib, 256);
        assert!(config.add_root_device);
        assert!(!config.use_initrd);
        assert!(!config.track_dirty_pages);
        assert_eq!(config.huge_pages, HugePagesConfig::None);
        assert!(config.smt.is_none());
    }
}
