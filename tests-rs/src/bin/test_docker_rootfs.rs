// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Boot every squashfs rootfs in the current directory, ported from
//! `tools/test-popular-containers/test-docker-rootfs.py`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use fc_harness::artifacts::GuestKernel;
use fc_harness::defs;
use fc_harness::kvm::KvmBasicConfig;
use fc_harness::microvm::{MicroVmFactory, SpawnConfig};
use fc_harness::vm_backend::VM_BACKEND_KVM;

#[derive(Parser, Debug)]
#[command(
    name = "fc-test-docker-rootfs",
    about = "Test all the squashfs rootfs in the current directory"
)]
struct Args {
    /// Directory holding the `*.squashfs` rootfs images (default: cwd).
    #[arg(long, default_value = ".")]
    rootfs_dir: PathBuf,
    /// Directory holding the firecracker binaries.
    #[arg(long = "binary-dir")]
    binary_dir: Option<PathBuf>,
    /// Guest kernel to boot (default: the newest supported artifact).
    #[arg(long)]
    kernel: Option<PathBuf>,
    /// Command to run in each guest.
    #[arg(long, default_value = "cat /etc/issue")]
    guest_cmd: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let kernel_path = match args.kernel.clone() {
        Some(kernel) => kernel,
        None => {
            let artifact_dir = defs::artifact_dir_owned();
            let kernels = fc_harness::artifacts::kernels("vmlinux-*", &artifact_dir)?;
            kernels.last().cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "no guest kernel artifacts found in {}",
                    artifact_dir.display()
                )
            })?
        }
    };
    let kernel = GuestKernel::from_vmlinux(&kernel_path)?;

    let binary_dir = args
        .binary_dir
        .clone()
        .unwrap_or_else(defs::default_binary_dir);
    let mut factory = MicroVmFactory::new(&binary_dir, VM_BACKEND_KVM)?;

    let mut rootfs_images = collect_squashfs(&args.rootfs_dir)?;
    if rootfs_images.is_empty() {
        anyhow::bail!(
            "no *.squashfs images found in {}",
            args.rootfs_dir.display()
        );
    }
    rootfs_images.sort();

    let mut failures = 0usize;
    for rootfs in rootfs_images {
        println!(">>>> Testing {}", rootfs.display());
        let result = run_one(&mut factory, &kernel, &rootfs, &args.guest_cmd);
        match result {
            Ok((status, stdout, stderr)) => {
                println!("{status} {stdout}{stderr}");
            }
            Err(err) => {
                failures += 1;
                eprintln!("{}: {err:#}", rootfs.display());
            }
        }
    }
    factory.kill();
    if failures > 0 {
        anyhow::bail!("{failures} rootfs image(s) failed");
    }
    Ok(())
}

fn run_one(
    factory: &mut MicroVmFactory,
    kernel: &GuestKernel,
    rootfs: &PathBuf,
    guest_cmd: &str,
) -> Result<(i32, String, String)> {
    let vm = factory.build(Some(kernel.clone()), Some(rootfs.clone()), None)?;
    vm.spawn(SpawnConfig::default())?;
    vm.add_net_iface(None, true)?;
    vm.basic_config(KvmBasicConfig::default())?;
    vm.start()?;
    let output = vm
        .ssh_iface(0)?
        .run(guest_cmd, Duration::from_secs(100))
        .context("running the guest command")?;
    vm.kill_with(true)?;
    Ok((output.returncode, output.stdout, output.stderr))
}

/// Lists `*.squashfs` files inside `dir`.
pub fn collect_squashfs(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut images = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .flatten()
    {
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .map(|ext| ext.eq_ignore_ascii_case("squashfs"))
                .unwrap_or(false)
        {
            images.push(path);
        }
    }
    Ok(images)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_only_squashfs_images() {
        let dir = std::env::temp_dir().join(format!("fc-squash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["a.squashfs", "b.SQUASHFS", "c.ext4", "notes.txt"] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        std::fs::create_dir_all(dir.join("nested.squashfs")).unwrap();

        let found = collect_squashfs(&dir).unwrap();
        let names: Vec<String> = found
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a.squashfs".to_string()));
        assert!(names.contains(&"b.SQUASHFS".to_string()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_directory_is_an_error() {
        assert!(collect_squashfs(std::path::Path::new("/definitely/not/here")).is_err());
    }
}
