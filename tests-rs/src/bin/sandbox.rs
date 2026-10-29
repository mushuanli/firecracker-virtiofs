// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Run Firecracker in an interactive sandbox, ported from `tools/sandbox.py`.
//!
//! The python script dropped into an IPython REPL; this port replaces the REPL
//! with a small command loop (`ssh`, `console`, `log`, `metrics`, `snapshot`,
//! `help`, `quit`) so the same sandbox is available without a python runtime.
//! Everything up to `vm.start()` is a 1:1 port.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::Value;

use fc_harness::artifacts::{self, GuestKernel};
use fc_harness::defs;
use fc_harness::kvm::KvmBasicConfig;
use fc_harness::microvm::{MicroVm, MicroVmFactory, SnapshotConfig};
use fc_harness::microvm_helpers::MicrovmHelpers;
use fc_harness::snapshot::SnapshotType;
use fc_harness::vm_backend::VM_BACKEND_KVM;
use fc_harness::CpuTemplate;

#[derive(Parser, Debug)]
#[command(
    name = "fc-sandbox",
    about = "Run Firecracker in an interactive sandbox"
)]
struct Args {
    /// Kernel to use.
    #[arg(long)]
    kernel: Option<PathBuf>,
    /// Rootfs to use.
    #[arg(long)]
    rootfs: Option<PathBuf>,
    /// Number of vCPUs.
    #[arg(long, default_value_t = 2)]
    vcpus: u32,
    /// Guest memory size, e.g. 128MB.
    #[arg(long = "guest-mem-size", default_value = "128MB", value_parser = parse_byte_size_arg)]
    guest_mem_size: u64,
    /// Rootfs size after resize, e.g. 1GB.
    #[arg(long = "rootfs-size", default_value = "1GB", value_parser = parse_byte_size_arg)]
    rootfs_size: u64,
    /// Path to the firecracker binaries.
    #[arg(long = "binary-dir")]
    binary_dir: Option<PathBuf>,
    /// CPU template JSON document to apply.
    #[arg(long = "cpu-template-path")]
    cpu_template_path: Option<PathBuf>,
    /// Kernel boot arguments (space separated).
    #[arg(long = "boot-args", num_args = 1..)]
    boot_args: Vec<String>,
    /// Use the debug kernel.
    #[arg(long)]
    debug: bool,
    /// Enable the Firecracker GDB socket.
    #[arg(long)]
    gdb: bool,
}

fn parse_byte_size_arg(value: &str) -> Result<u64, String> {
    defs::parse_byte_size(value).ok_or_else(|| format!("invalid byte size: {value}"))
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Rewrite host paths under HOST_FC_ROOT_DIR to their in-container form.
    let kernel_arg = translate_host_path(args.kernel.as_deref())?;
    let rootfs_arg = translate_host_path(args.rootfs.as_deref())?;
    let binary_dir_arg = translate_host_path(args.binary_dir.as_deref())?;
    let cpu_template_arg = translate_host_path(args.cpu_template_path.as_deref())?;

    let artifact_dir = defs::artifact_dir_owned();
    let kernel_candidates = artifacts::kernels("vmlinux-*", &artifact_dir)?;
    let rootfs_candidates = artifacts::disks("*.ext4", &artifact_dir)?;

    let kernel_path = kernel_arg
        .or_else(|| kernel_candidates.last().cloned())
        .ok_or_else(|| anyhow::anyhow!("No kernel found and --kernel was not provided."))?;
    let rootfs_path = rootfs_arg
        .or_else(|| pick_default_rootfs(&rootfs_candidates))
        .ok_or_else(|| anyhow::anyhow!("No rootfs found and --rootfs was not provided."))?;

    let binary_dir = match binary_dir_arg {
        Some(dir) => dir,
        None => defs::default_binary_dir(),
    };

    let cpu_template = match cpu_template_arg {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let document: Value = serde_json::from_str(&text)
                .with_context(|| format!("parsing {}", path.display()))?;
            let name = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_else(|| "custom".to_string());
            Some(CpuTemplate::Custom {
                name,
                template: document,
            })
        }
        None => None,
    };

    let kernel = if args.debug || args.gdb {
        GuestKernel::from_vmlinux(
            &kernel_path
                .parent()
                .unwrap_or(Path::new("."))
                .join("debug")
                .join(
                    kernel_path
                        .file_name()
                        .ok_or_else(|| anyhow::anyhow!("kernel path has no file name"))?,
                ),
        )?
    } else {
        GuestKernel::from_vmlinux(&kernel_path)?
    };
    println!("uvm with kernel {} ...", kernel.vmlinux.display());

    let mut factory = MicroVmFactory::new(&binary_dir, VM_BACKEND_KVM)?;
    let vm = factory.build(Some(kernel), Some(rootfs_path.clone()), None)?;
    let rootfs_file = vm
        .rootfs_file
        .clone()
        .ok_or_else(|| anyhow::anyhow!("microVM has no rootfs"))?;
    MicrovmHelpers::enable_console(vm)?;
    MicrovmHelpers::resize_disk(&rootfs_file, args.rootfs_size)?;

    let mut spawn_config = fc_harness::microvm::SpawnConfig::default();
    spawn_config.log_show_level = true;
    spawn_config.validate_api = false;
    vm.spawn(spawn_config)?;
    MicrovmHelpers::print_log(vm);

    vm.add_net_iface(None, true)?;
    vm.basic_config(KvmBasicConfig {
        vcpu_count: args.vcpus,
        mem_size_mib: args.guest_mem_size / (1 << 20),
        boot_args: if args.boot_args.is_empty() {
            None
        } else {
            Some(args.boot_args.join(" "))
        },
        ..KvmBasicConfig::default()
    })?;

    if let Some(template) = cpu_template {
        vm.custom_cpu_template = Some(template.clone());
        vm.set_cpu_template(Some(template.clone()))?;
        println!("cpu template: {template:?}");
    }

    if args.gdb {
        vm.enable_gdb()?;
        MicrovmHelpers::tmux_gdb(vm)?;
    }

    vm.start()?;
    let _ = vm.get_metrics()?;

    println!(
        "\nSandbox ready (microVM {}).\n  ssh: {}\n  console: {}\nType `help` for commands.",
        vm.id(),
        MicrovmHelpers::how_to_ssh(vm)?,
        MicrovmHelpers::how_to_console(vm)
    );
    repl(vm)?;

    factory.kill();
    Ok(())
}

/// Picks the sandbox default rootfs: AL2023, then Ubuntu, then the newest.
pub fn pick_default_rootfs(candidates: &[PathBuf]) -> Option<PathBuf> {
    if candidates.is_empty() {
        return None;
    }
    for prefix in ["amazonlinux-", "ubuntu-"] {
        let matches: Vec<&PathBuf> = candidates
            .iter()
            .filter(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().starts_with(prefix))
                    .unwrap_or(false)
            })
            .collect();
        if let Some(last) = matches.last() {
            return Some((*last).clone());
        }
    }
    candidates.last().cloned()
}

/// Rewrites a host path under `HOST_FC_ROOT_DIR` to its sandbox equivalent.
pub fn translate_host_path(path: Option<&Path>) -> Result<Option<PathBuf>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let host_root = match std::env::var("HOST_FC_ROOT_DIR") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => return Ok(Some(path.to_path_buf())),
    };
    let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if let Ok(relative) = resolved.strip_prefix(&host_root) {
        return Ok(Some(defs::workspace_dir().join(relative)));
    }
    if resolved.exists() {
        return Ok(Some(resolved));
    }
    bail!(
        "{} not found in container and not under host workspace {}.",
        resolved.display(),
        host_root.display()
    )
}

fn repl(vm: &mut MicroVm) -> Result<()> {
    loop {
        print!("sandbox> ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            return Ok(());
        }
        let line = line.trim();
        match line {
            "" => continue,
            "quit" | "exit" => return Ok(()),
            "help" => println!(
                "commands:\n  ssh [cmd]       print the ssh command line, or run `cmd` over ssh\n  console         print the screen console command\n  log             print the firecracker log\n  metrics         print the last firecracker metrics datapoint\n  snapshot [full|diff]  take a snapshot\n  state           print the instance state\n  quit            exit (the microVM is killed)"
            ),
            "ssh" => println!("{}", MicrovmHelpers::how_to_ssh(vm)?),
            "console" => println!("{}", MicrovmHelpers::how_to_console(vm)),
            "log" => println!("{}", vm.log_data()),
            "metrics" => {
                let metrics = vm.get_metrics()?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(metrics.last().unwrap_or(&Value::Null))?
                );
            }
            "state" => println!("{}", vm.state()?),
            other => {
                if let Some(kind) = other.strip_prefix("ssh ") {
                    let out = vm
                        .ssh_iface(0)?
                        .run(kind, std::time::Duration::from_secs(100))?;
                    print!("{}{}", out.stdout, out.stderr);
                } else if let Some(kind) = other.strip_prefix("snapshot") {
                    let snapshot_type = match kind.trim() {
                        "diff" => SnapshotType::Diff,
                        _ => SnapshotType::Full,
                    };
                    let snapshot = vm.make_snapshot(SnapshotConfig::new(snapshot_type))?;
                    println!("snapshot: {snapshot:?}");
                } else {
                    println!("unknown command: {other} (try `help`)");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rootfs_prefers_al2023() {
        let candidates = vec![
            PathBuf::from("/a/ubuntu-24.04.ext4"),
            PathBuf::from("/a/amazonlinux-2023.ext4"),
            PathBuf::from("/a/alpine.ext4"),
        ];
        assert_eq!(
            pick_default_rootfs(&candidates).unwrap(),
            PathBuf::from("/a/amazonlinux-2023.ext4")
        );
    }

    #[test]
    fn default_rootfs_falls_back_to_ubuntu_then_last() {
        // python returns the last `amazonlinux-*` match before ever looking at
        // the `ubuntu-*` prefix, so the AL2023 image wins here.
        let candidates = vec![
            PathBuf::from("/a/amazonlinux-old.ext4"),
            PathBuf::from("/a/ubuntu-22.04.ext4"),
        ];
        assert_eq!(
            pick_default_rootfs(&candidates).unwrap(),
            PathBuf::from("/a/amazonlinux-old.ext4")
        );
        let candidates = vec![
            PathBuf::from("/a/alpine.ext4"),
            PathBuf::from("/a/ubuntu-22.04.ext4"),
        ];
        assert_eq!(
            pick_default_rootfs(&candidates).unwrap(),
            PathBuf::from("/a/ubuntu-22.04.ext4")
        );
        let candidates = vec![PathBuf::from("/a/alpine.ext4")];
        assert_eq!(
            pick_default_rootfs(&candidates).unwrap(),
            PathBuf::from("/a/alpine.ext4")
        );
        assert!(pick_default_rootfs(&[]).is_none());
    }

    #[test]
    fn translate_without_host_root_is_identity() {
        std::env::remove_var("HOST_FC_ROOT_DIR");
        let path = PathBuf::from("/tmp/some-kernel");
        assert_eq!(translate_host_path(Some(&path)).unwrap(), Some(path));
        assert_eq!(translate_host_path(None).unwrap(), None);
    }

    #[test]
    fn byte_size_parser_accepts_sandbox_defaults() {
        assert_eq!(parse_byte_size_arg("128MB").unwrap(), 128 << 20);
        assert_eq!(parse_byte_size_arg("1GB").unwrap(), 1 << 30);
        assert!(parse_byte_size_arg("128").is_err());
    }
}
