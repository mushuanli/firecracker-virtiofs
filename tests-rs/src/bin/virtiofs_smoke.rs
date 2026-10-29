// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Root-only, real KVM/Debian virtio-fs smoke test, ported from
//! `tools/virtiofs/smoke.py`.
//!
//! Does not mount a guest filesystem on the host. The supplied rootfs is
//! copied. Runs the device directly; production jailer/supervisor acceptance is
//! separate.

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::{json, Value};

use fc_harness::http_api::Api;
use fc_harness::utils;

#[derive(Parser, Debug)]
#[command(
    name = "fc-virtiofs-smoke",
    about = "Root-only virtio-fs smoke test against a disposable Debian 13 rootfs"
)]
struct Args {
    /// Path to the firecracker binary.
    #[arg(long)]
    firecracker: PathBuf,
    /// Path to the guest vmlinux.
    #[arg(long)]
    kernel: PathBuf,
    /// Path to the disposable Debian 13 rootfs (copied, never modified).
    #[arg(long)]
    rootfs: PathBuf,
    /// Path to virtiofsd.
    #[arg(long)]
    virtiofsd: PathBuf,
    /// Output directory for the disposable artifacts.
    #[arg(long)]
    output: PathBuf,
}

/// The guest-side validation script, depending on the share being read-only.
pub fn guest_script(readonly: bool) -> String {
    let operation = if readonly {
        r#"
if touch /share/forbidden; then echo READONLY_BYPASS; exit 1; fi
if rm /share/from-host; then echo READONLY_UNLINK_BYPASS; exit 1; fi
if mv /share/from-host /share/renamed; then echo READONLY_RENAME_BYPASS; exit 1; fi
"#
    } else {
        r#"
mkdir /share/session
printf guest-session > /share/session/record
mv /share/session/record /share/session/renamed
printf rename-probe > /share/movable
if mv /share/movable /share/escape-dir/stolen; then echo RENAME_ESCAPE; exit 1; fi
[ -f /share/movable ]
ln -s ../from-host /share/session/link
[ "$(cat /share/session/link)" = host-data ]
"#
    };

    format!(
        r#"#!/bin/bash
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev || true
. /etc/os-release
[ "$VERSION_ID" = 13 ]
mkdir -p /share
mount -t virtiofs -o rw,nodev,nosuid workspace /share
[ "$(cat /share/from-host)" = host-data ]
if cat /share/absolute-escape; then echo ABSOLUTE_ESCAPE; exit 1; fi
if cat /share/relative-escape; then echo RELATIVE_ESCAPE; exit 1; fi
{operation}
sync
echo VIRTIOFS_GUEST_PASS
while :; do sleep 60; done
"#
    )
}

fn main() -> Result<()> {
    let args = Args::parse();
    if unsafe { libc::geteuid() } != 0 {
        bail!("Requires root for daemon namespaces and KVM");
    }
    let root = args
        .output
        .canonicalize()
        .unwrap_or_else(|_| args.output.clone());
    std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
    set_mode(&root, 0o700)?;

    for readonly in [false, true] {
        let case = run_case(&args, &root, readonly)?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "case": case,
                "guest": "Debian 13",
                "result": "passed",
                "snapshot": "rejected",
                "daemon_disconnect": "vmm_stopped",
            }))?
        );
        let _ = std::io::stdout().flush();
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Runs one read-only / read-write case, returning the case name on success.
fn run_case(args: &Args, root: &Path, readonly: bool) -> Result<String> {
    let case_name = if readonly { "readonly" } else { "readwrite" };
    let case = root.join(case_name);
    std::fs::create_dir_all(&case)?;
    let share = case.join("share");
    std::fs::create_dir_all(&share)?;
    std::fs::write(share.join("from-host"), "host-data")?;

    let secret = case.join("outside-secret");
    std::fs::write(&secret, "host-private")?;
    std::os::unix::fs::symlink(&secret, share.join("absolute-escape"))?;
    std::os::unix::fs::symlink("../outside-secret", share.join("relative-escape"))?;
    let outside_dir = case.join("outside-dir");
    std::fs::create_dir_all(&outside_dir)?;
    std::os::unix::fs::symlink(&outside_dir, share.join("escape-dir"))?;

    let disk = case.join("root.ext4");
    utils::check_output_args(&[
        "cp".to_string(),
        "--reflink=auto".to_string(),
        args.rootfs.to_string_lossy().into_owned(),
        disk.to_string_lossy().into_owned(),
    ])?;

    let script = case.join("guest.sh");
    std::fs::write(&script, guest_script(readonly))?;
    let debugfs_cmd = format!("write {} /virtiofs-test.sh", script.display());
    utils::check_output_args(&[
        "debugfs".to_string(),
        "-w".to_string(),
        "-R".to_string(),
        debugfs_cmd,
        disk.to_string_lossy().into_owned(),
    ])?;

    let api_socket = case.join("api.sock");
    let backend_socket = case.join("fs.sock");
    let log_path = case.join("guest.log");
    let mut daemon: Option<Child> = None;
    let mut vmm: Option<Child> = None;

    let result = (|| -> Result<String> {
        let daemon_log = std::fs::File::create(case.join("daemon.log"))?;
        let mut command = Command::new(&args.virtiofsd);
        command.args([
            "--socket-path",
            &backend_socket.to_string_lossy(),
            "--shared-dir",
            &share.to_string_lossy(),
            "--sandbox",
            "namespace",
            "--seccomp",
            "kill",
            "--cache",
            "never",
            "--inode-file-handles=never",
        ]);
        if readonly {
            command.arg("--readonly");
        }
        daemon = Some(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::from(daemon_log.try_clone()?))
                .stderr(Stdio::from(daemon_log))
                .process_group(0)
                .spawn()
                .context("spawning virtiofsd")?,
        );
        wait_for(
            || Ok(backend_socket.exists()),
            daemon.as_mut().expect("daemon spawned"),
            60,
        )?;

        let guest_log = std::fs::File::create(&log_path)?;
        vmm = Some(
            Command::new(&args.firecracker)
                .args(["--api-sock", &api_socket.to_string_lossy()])
                .stdin(Stdio::piped())
                .stdout(Stdio::from(guest_log.try_clone()?))
                .stderr(Stdio::from(guest_log))
                .process_group(0)
                .spawn()
                .context("spawning firecracker")?,
        );
        wait_for(
            || Ok(api_socket.exists()),
            vmm.as_mut().expect("vmm spawned"),
            60,
        )?;

        let api = Api::new(&api_socket, false);
        request(
            &api,
            "PUT",
            "/machine-config",
            json!({"vcpu_count": 2, "mem_size_mib": 512}),
            204,
        )?;
        request(
            &api,
            "PUT",
            "/boot-source",
            json!({
                "kernel_image_path": args.kernel.to_string_lossy(),
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off acpi=off root=/dev/vda rw init=/bin/bash",
            }),
            204,
        )?;
        request(
            &api,
            "PUT",
            "/drives/root",
            json!({
                "drive_id": "root",
                "path_on_host": disk.to_string_lossy(),
                "is_root_device": true,
                "is_read_only": false,
            }),
            204,
        )?;
        let fs = json!({
            "fs_id": "project",
            "tag": "workspace",
            "socket": backend_socket.to_string_lossy(),
        });
        request(&api, "PUT", "/fs/project", fs.clone(), 204)?;
        request(
            &api,
            "PUT",
            "/actions",
            json!({"action_type": "InstanceStart"}),
            204,
        )?;

        wait_for(
            || {
                let log = read_lossy(&log_path);
                Ok(log.contains("bash") && log.contains("# "))
            },
            vmm.as_mut().expect("vmm spawned"),
            60,
        )?;
        if let Some(stdin) = vmm.as_mut().and_then(|child| child.stdin.as_mut()) {
            stdin.write_all(b"exec /bin/bash /virtiofs-test.sh\n")?;
            stdin.flush()?;
        }
        wait_for(
            || Ok(read_lossy(&log_path).contains("VIRTIOFS_GUEST_PASS")),
            vmm.as_mut().expect("vmm spawned"),
            120,
        )?;

        request(&api, "PUT", "/fs/project", fs, 400)?;
        request(&api, "PATCH", "/vm", json!({"state": "Paused"}), 204)?;
        let body = request(
            &api,
            "PUT",
            "/snapshot/create",
            json!({
                "snapshot_type": "Full",
                "snapshot_path": case.join("snapshot").to_string_lossy(),
                "mem_file_path": case.join("memory").to_string_lossy(),
            }),
            400,
        )?;
        let body = body.unwrap_or_default();
        if !body.contains("virtio-fs") {
            bail!("snapshot rejection did not mention virtio-fs: {body}");
        }
        if case.join("snapshot").exists() {
            bail!("snapshot file was created despite the rejection");
        }
        request(&api, "PATCH", "/vm", json!({"state": "Resumed"}), 204)?;

        if std::fs::read_to_string(&secret)? != "host-private" {
            bail!("the host secret was modified through the share");
        }
        if std::fs::read_dir(&outside_dir)?.next().is_some() {
            bail!("guest wrote into the outside directory through a symlink");
        }
        if readonly {
            if share.join("forbidden").exists() {
                bail!("read-only share accepted a new file");
            }
            if std::fs::read_to_string(share.join("from-host"))? != "host-data" {
                bail!("read-only share lost its host file");
            }
        } else if std::fs::read_to_string(share.join("session/renamed"))? != "guest-session" {
            bail!("read-write share lost the guest rename");
        }

        stop(daemon.take())?;
        let status = vmm
            .as_mut()
            .expect("vmm spawned")
            .wait()
            .context("waiting for firecracker")?;
        if status.code() != Some(1) {
            bail!("backend failure must produce a nonzero VMM exit, got {status:?}");
        }
        if !read_lossy(&log_path).contains("category=disconnected") {
            bail!("guest log does not mention category=disconnected");
        }
        Ok(case_name.to_string())
    })();

    stop(vmm.take())?;
    stop(daemon.take())?;
    let _ = std::fs::remove_file(&disk);
    result
}

fn read_lossy(path: &Path) -> String {
    std::fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

/// Sends a request and asserts the expected status code.
fn request(
    api: &Api,
    method: &str,
    path: &str,
    body: Value,
    expected: u16,
) -> Result<Option<String>> {
    let response = api.describe.request(method, path, Some(body))?;
    if response.status != expected {
        bail!(
            "{path}: expected {expected}, got {} ({})",
            response.status,
            response.body
        );
    }
    Ok(Some(response.body))
}

fn wait_for<F>(mut predicate: F, process: &mut Child, timeout_secs: u64) -> Result<()>
where
    F: FnMut() -> Result<bool>,
{
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        if predicate()? {
            return Ok(());
        }
        if let Some(status) = process.try_wait()? {
            bail!("Process exited: {status:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("guest/backend readiness timed out")
}

fn stop(process: Option<Child>) -> Result<()> {
    let Some(mut process) = process else {
        return Ok(());
    };
    // SAFETY: the child was spawned with its own process group.
    unsafe { libc::killpg(process.id() as i32, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if process.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            // SAFETY: same process group as above.
            unsafe { libc::killpg(process.id() as i32, libc::SIGKILL) };
            let _ = process.wait();
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_script_checks_write_bypasses() {
        let script = guest_script(true);
        assert!(script.contains("READONLY_BYPASS"));
        assert!(script.contains("READONLY_UNLINK_BYPASS"));
        assert!(script.contains("READONLY_RENAME_BYPASS"));
        assert!(!script.contains("mkdir /share/session"));
        assert!(script.contains("VIRTIOFS_GUEST_PASS"));
    }

    #[test]
    fn readwrite_script_checks_rename_escape() {
        let script = guest_script(false);
        assert!(script.contains("RENAME_ESCAPE"));
        assert!(script.contains("mkdir /share/session"));
        assert!(script.contains("ABSOLUTE_ESCAPE"));
        assert!(script.contains("RELATIVE_ESCAPE"));
        assert!(script.contains(r#"[ "$VERSION_ID" = 13 ]"#));
    }
}
