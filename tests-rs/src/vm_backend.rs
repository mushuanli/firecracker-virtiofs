// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend dimension for microVM configuration, ported from
//! `tests/framework/vm_backend.py`.
//!
//! A backend supplies the backend-specific parts of configuring and starting a
//! microVM; [`crate::microvm::MicroVm`] owns the lifecycle shared by every
//! backend.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::artifacts::GuestKernel;
use crate::kvm;

/// Backend values and lifecycle behaviour for the `vm_backend` dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VmBackend {
    Kvm,
}

impl VmBackend {
    /// The stable value used in ids and reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            VmBackend::Kvm => "kvm",
        }
    }

    /// Whether this host can run the backend.
    pub fn available(&self) -> bool {
        match self {
            VmBackend::Kvm => kvm::has_kvm(),
        }
    }

    /// Host probe details for diagnostics.
    pub fn probe_details(&self) -> BTreeMap<String, String> {
        match self {
            VmBackend::Kvm => kvm::kvm_probe_details(),
        }
    }

    /// The concrete boot image required by the backend.
    pub fn kernel_image_for(&self, guest_kernel: &GuestKernel) -> PathBuf {
        match self {
            VmBackend::Kvm => guest_kernel.vmlinux.clone(),
        }
    }

    /// Performs backend-specific preparation before starting a microVM.
    pub fn prepare_start(&self) -> Result<()> {
        match self {
            VmBackend::Kvm => Ok(()),
        }
    }
}

impl std::fmt::Display for VmBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The KVM backend value (`VM_BACKEND_KVM`).
pub const VM_BACKEND_KVM: VmBackend = VmBackend::Kvm;

/// All backend values (`VM_BACKENDS_ALL`).
pub const VM_BACKENDS_ALL: [VmBackend; 1] = [VmBackend::Kvm];

/// The backends this host can run.
pub fn available_vm_backends() -> Vec<VmBackend> {
    VM_BACKENDS_ALL
        .into_iter()
        .filter(VmBackend::available)
        .collect()
}

/// Human-readable backend probe lines, equivalent to `vm_backend_probe_report`.
pub fn vm_backend_probe_report() -> Vec<String> {
    let available = available_vm_backends();
    let joined = if available.is_empty() {
        "none".to_string()
    } else {
        available
            .iter()
            .map(|backend| backend.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut lines = vec![format!("VM Backends Available: {joined}")];
    for backend in VM_BACKENDS_ALL {
        let mut details = BTreeMap::new();
        details.insert(
            "available".to_string(),
            if available.contains(&backend) {
                "yes".to_string()
            } else {
                "no".to_string()
            },
        );
        details.extend(backend.probe_details());
        let formatted = details
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("VM Backend {backend}: {formatted}"));
    }
    lines
}

/// Returns the backend for a dimension value.
pub fn get_vm_backend(backend: &str) -> Result<VmBackend> {
    match backend {
        "kvm" => Ok(VmBackend::Kvm),
        other => bail!("Unknown VM backend: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_values_roundtrip() {
        assert_eq!(get_vm_backend("kvm").unwrap(), VmBackend::Kvm);
        assert!(get_vm_backend("hvf").is_err());
        assert_eq!(VmBackend::Kvm.to_string(), "kvm");
    }

    #[test]
    fn probe_report_mentions_every_backend() {
        let lines = vm_backend_probe_report();
        assert!(lines[0].starts_with("VM Backends Available: "));
        assert_eq!(lines.len(), 2);
        assert!(lines[1].starts_with("VM Backend kvm: "));
        assert!(lines[1].contains("available="));
        assert!(lines[1].contains("device=/dev/kvm"));
    }

    #[test]
    fn kernel_image_is_the_vmlinux() {
        let kernel = GuestKernel {
            version: "6.1.168".into(),
            acpi: true,
            vmlinux: PathBuf::from("/artifacts/vmlinux-6.1.168"),
            efi_image: Some(PathBuf::from("/artifacts/bzImage-6.1.168")),
            debug: false,
            bzimage: Some(PathBuf::from("/artifacts/bzImage-6.1.168")),
        };
        assert_eq!(
            VmBackend::Kvm.kernel_image_for(&kernel),
            PathBuf::from("/artifacts/vmlinux-6.1.168")
        );
    }
}
