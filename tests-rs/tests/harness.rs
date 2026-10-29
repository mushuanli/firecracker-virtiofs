// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end harness tests, replacing the boot paths of the python
//! `tests/integration_tests/**` suite.
//!
//! Every test here needs a real Firecracker build, KVM, guest artifacts and
//! root. They are `#[ignore]`d so `cargo test` stays green on a build host;
//! run them explicitly with:
//!
//! ```text
//! cargo test --test harness -- --ignored --test-threads=1
//! ```

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;

use fc_harness::artifacts::{self, GuestKernel};
use fc_harness::defs;
use fc_harness::kvm::KvmBasicConfig;
use fc_harness::microvm::{MicroVmFactory, RestoreOptions, SpawnConfig};
use fc_harness::properties::global_props;
use fc_harness::vm_backend::{get_vm_backend, VmBackend, VM_BACKEND_KVM};

/// Locates a bootable kernel + rootfs pair, or `None` when artifacts are absent.
fn artifacts_available() -> Option<(GuestKernel, PathBuf)> {
    let dir = defs::artifact_dir_owned();
    let kernels = artifacts::kernels("vmlinux-*", &dir).ok()?;
    let rootfs = artifacts::disks("*.ext4", &dir).ok()?;
    let kernel = GuestKernel::from_vmlinux(kernels.last()?).ok()?;
    Some((kernel, rootfs.into_iter().next()?))
}

/// Whether this host can run the suite at all.
fn prerequisites_met() -> bool {
    let binary_dir = defs::default_binary_dir();
    binary_dir.join(defs::FC_BINARY_NAME).exists()
        && binary_dir.join("jailer").exists()
        && VmBackend::Kvm.available()
        && artifacts_available().is_some()
}

fn factory() -> Result<MicroVmFactory> {
    MicroVmFactory::new(defs::default_binary_dir(), VM_BACKEND_KVM)
}

#[test]
fn vm_backend_dimension_resolves() -> Result<()> {
    assert_eq!(get_vm_backend("kvm")?, VM_BACKEND_KVM);
    // The probe report must never panic, even without /dev/kvm.
    let report = fc_harness::vm_backend::vm_backend_probe_report();
    assert!(report[0].starts_with("VM Backends Available:"));
    assert!(global_props().host_linux_version_tpl().0 > 0);
    Ok(())
}

#[test]
#[ignore = "requires firecracker binaries, KVM, root and guest artifacts"]
fn boot_run_command_and_kill() -> Result<()> {
    if !prerequisites_met() {
        eprintln!("skipping: build binaries / KVM / artifacts not available");
        return Ok(());
    }
    let (kernel, rootfs) = artifacts_available().expect("checked by prerequisites_met");
    let mut factory = factory()?;
    let vm = factory.build(Some(kernel), Some(rootfs), None)?;
    vm.spawn(SpawnConfig::default())?;
    vm.add_net_iface(None, true)?;
    vm.basic_config(KvmBasicConfig::default())?;
    vm.start()?;

    assert_eq!(vm.state()?, "Running");
    let stdout = vm
        .ssh_iface(0)?
        .check_output("cat /etc/issue", Duration::from_secs(100))?
        .stdout;
    assert!(!stdout.trim().is_empty(), "guest /etc/issue is empty");

    vm.kill_with(true)?;
    factory.kill();
    Ok(())
}

#[test]
#[ignore = "requires firecracker binaries, KVM, root and guest artifacts"]
fn full_snapshot_restore_roundtrip() -> Result<()> {
    if !prerequisites_met() {
        eprintln!("skipping: build binaries / KVM / artifacts not available");
        return Ok(());
    }
    let (kernel, rootfs) = artifacts_available().expect("checked by prerequisites_met");
    let mut factory = factory()?;

    let vm = factory.build(Some(kernel), Some(rootfs), None)?;
    vm.spawn(SpawnConfig::default())?;
    vm.add_net_iface(None, true)?;
    vm.basic_config(KvmBasicConfig {
        track_dirty_pages: true,
        ..KvmBasicConfig::default()
    })?;
    vm.start()?;

    let dir = std::env::temp_dir().join(format!("fc-snap-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let snapshot = vm.snapshot_full()?;
    snapshot.save_to(&dir)?;
    vm.kill_with(true)?;

    let mut restore_options = RestoreOptions::default();
    restore_options.resume = true;
    let restored = factory.build_from_snapshot(&snapshot, restore_options)?;
    assert_eq!(restored.state()?, "Running");
    let stdout = restored
        .ssh_iface(0)?
        .check_output("echo restored", Duration::from_secs(100))?
        .stdout;
    assert_eq!(stdout.trim(), "restored");

    factory.kill();
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

#[test]
#[ignore = "requires firecracker binaries, KVM, root and guest artifacts"]
fn api_reports_a_version() -> Result<()> {
    if !prerequisites_met() {
        eprintln!("skipping: build binaries / KVM / artifacts not available");
        return Ok(());
    }
    let (kernel, rootfs) = artifacts_available().expect("checked by prerequisites_met");
    let mut factory = factory()?;
    let vm = factory.build(Some(kernel), Some(rootfs), None)?;
    vm.spawn(SpawnConfig::default())?;

    let version = vm.api()?.firecracker_version()?;
    assert!(
        version.starts_with("1.") || version.starts_with("0."),
        "unexpected version {version}"
    );
    vm.kill_with(true)?;
    factory.kill();
    Ok(())
}
