// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helper functions for interactive microVM debugging, ported from
//! `tests/framework/microvm_helpers.py`.
//!
//! python's `MicrovmHelpers` holds a `vm` reference; Rust cannot store a
//! self-reference on `MicroVm`, so every helper takes the microVM explicitly.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{bail, Context, Result};

use crate::microvm::MicroVm;
use crate::utils;

/// Marker type carried by [`MicroVm`] so call sites read like the python API
/// (`vm.helpers.how_to_ssh()` becomes `MicrovmHelpers::how_to_ssh(&vm)`).
#[derive(Debug, Default, Clone, Copy)]
pub struct MicrovmHelpers;

/// Installs packages in the devctr via apt.
pub fn docker_apt_install(packages: &[&str]) -> Result<()> {
    let lists = Path::new("/var/lib/apt/lists");
    let empty = std::fs::read_dir(lists)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(true);
    if empty {
        utils::check_output_args(&["apt", "update"])?;
    }
    let mut args = vec!["apt".to_string(), "install".to_string(), "-y".to_string()];
    args.extend(packages.iter().map(|p| p.to_string()));
    utils::check_output_args(&args)?;
    Ok(())
}

/// Information about the container this harness runs in.
#[derive(Debug, Clone, Copy, Default)]
pub struct DockerInfo;

impl DockerInfo {
    /// This container's IP address on `eth0`.
    pub fn ip(&self) -> Result<String> {
        let out = utils::check_output("ip -j address show eth0 |jq -r '.[].addr_info[].local'")?;
        Ok(out.stdout.trim().to_string())
    }

    /// This container's id (hostname).
    pub fn id(&self) -> Result<String> {
        let out = utils::check_output("hostname")?;
        Ok(out.stdout.trim().to_string())
    }

    /// Whether we are running inside a Docker container.
    pub fn in_docker(&self) -> bool {
        Path::new("/.dockerenv").exists()
    }
}

/// Number of subnets already handed out by [`MicrovmHelpers::enable_ip_forwarding`].
static SHARED_SUBNET_CTR: AtomicU32 = AtomicU32::new(0);

impl MicrovmHelpers {
    /// Prints Firecracker's log.
    pub fn print_log(vm: &MicroVm) {
        println!("{}", vm.log_data());
    }

    /// Resizes a filesystem (the filesystem must be unmounted).
    pub fn resize_disk(disk: &Path, size: u64) -> Result<()> {
        std::fs::OpenOptions::new()
            .write(true)
            .open(disk)
            .with_context(|| format!("opening {}", disk.display()))?
            .set_len(size)?;
        utils::check_output_args(&[
            "resize2fs".to_string(),
            "-f".to_string(),
            disk.to_string_lossy().into_owned(),
        ])?;
        Ok(())
    }

    /// Attaches gdbserver to the Firecracker process.
    pub fn gdbserver(vm: &MicroVm, port: u16) -> Result<()> {
        let pid = vm
            .firecracker_pid()
            .ok_or_else(|| anyhow::anyhow!("microVM is not running"))?;
        let comm = format!("localhost:{port}");
        std::process::Command::new("gdbserver")
            .args(["--attach", &comm, &pid.to_string()])
            .spawn()
            .context("spawning gdbserver")?;
        println!(
            "Connect gdb with:\n\tgdb --ex 'target remote {}:{port}'",
            DockerInfo.ip()?
        );
        Ok(())
    }

    /// Attaches lldb-server to the Firecracker process.
    pub fn lldbserver(vm: &MicroVm, port: u16) -> Result<()> {
        docker_apt_install(&["lldb"])?;
        std::process::Command::new("lldb-server")
            .args(["p", "--listen", &format!("*:{port}"), "--server"])
            .spawn()
            .context("spawning lldb-server")?;
        let pid = vm.firecracker_pid().unwrap_or_default();
        println!(
            "Connect lldb with\n\tlldb -o 'platform select remote-linux' -o 'platform connect connect://{}:{port}' -o 'attach {pid}'",
            DockerInfo.ip()?
        );
        Ok(())
    }

    /// Opens a window in the local tmux.
    pub fn tmux_neww(cmd: &str) -> Result<()> {
        utils::check_output_args(&["tmux", "neww", cmd])?;
        Ok(())
    }

    /// Command line that SSHes into the microVM.
    pub fn how_to_ssh(vm: &MicroVm) -> Result<String> {
        let iface = vm
            .iface
            .iter()
            .find(|(dev_name, _)| dev_name == "eth0")
            .map(|(_, iface)| iface)
            .ok_or_else(|| anyhow::anyhow!("microVM has no eth0 interface"))?;
        let ssh_key = vm
            .ssh_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("microVM has no ssh key"))?;
        Ok(format!(
            "{} ssh -o StrictHostKeyChecking=no -o KexAlgorithms=ecdh-sha2-nistp521 \
-o HostKeyAlgorithms=rsa-sha2-512 -c aes256-ctr -i {} root@{}",
            vm.netns.cmd_prefix(),
            ssh_key.display(),
            iface.guest_ip
        ))
    }

    /// Opens a tmux window with an SSH session to the VM.
    pub fn tmux_ssh(vm: &MicroVm, cmd: &str) -> Result<()> {
        let suffix = if cmd.is_empty() {
            String::new()
        } else {
            format!(" {cmd}")
        };
        Self::tmux_neww(&format!("{}{suffix}", Self::how_to_ssh(vm)?))
    }

    /// Attaches a console before the machine boots.
    pub fn enable_console(vm: &mut MicroVm) -> Result<()> {
        if vm.api.is_some() {
            bail!(".spawn already called, too late to enable the console");
        }
        let boot_args = vm.boot_args.get_or_insert_with(String::new);
        boot_args.push_str("console=ttyS0 reboot=k panic=1 swiotlb=noforce");
        vm.jailer.daemonize = false;
        vm.jailer.new_pid_ns = false;
        Ok(())
    }

    /// Command that connects to the VM console.
    pub fn how_to_console(vm: &MicroVm) -> String {
        format!("screen -dR {}", vm.screen_session())
    }

    /// Opens a tmux window with the console.
    pub fn tmux_console(vm: &MicroVm) -> Result<()> {
        Self::tmux_neww(&Self::how_to_console(vm))
    }

    /// How to get into this container from outside.
    pub fn how_to_docker() -> Result<String> {
        Ok(format!("docker exec -it {}", DockerInfo.id()?))
    }

    /// Enables IP forwarding inside the guest.
    pub fn enable_ip_forwarding(
        vm: &mut MicroVm,
        iface_dev: &str,
        ingress_ipv4: Option<Ipv4Addr>,
    ) -> Result<()> {
        let index = SHARED_SUBNET_CTR.fetch_add(1, Ordering::SeqCst);
        let netns = vm.netns.id().to_string();
        let veth_host = format!("vethhost{index}");
        let veth_guest = format!("vethguest{index}");

        // 10.255.0.0/16 chopped into /30s; consume `index` subnets so each
        // call gets a unique pair.
        let subnet_base = 0x0aff_0000u32 + index * 4;
        let veth_host_ip = Ipv4Addr::from(subnet_base + 1);
        let veth_guest_ip = Ipv4Addr::from(subnet_base + 2);

        let iface = vm
            .iface
            .iter()
            .find(|(dev_name, _)| dev_name == iface_dev)
            .map(|(_, iface)| iface.clone())
            .ok_or_else(|| anyhow::anyhow!("microVM has no {iface_dev} interface"))?;
        let tap_host_ip = iface.host_ip.clone();
        let tap_net = iface.network()?;

        let upstream_dev = utils::check_output("ip -j route list default |jq -r '.[0].dev'")?
            .stdout
            .trim()
            .to_string();

        let run = |cmd: &str| -> Result<()> {
            utils::check_output(cmd)?;
            Ok(())
        };
        let run_in_netns = |cmd: &str| run(&format!("ip netns exec {netns} {cmd}"));

        run(&format!(
            "ip link add name {veth_host} type veth peer name {veth_guest} netns {netns}"
        ))?;
        run(&format!("ip addr add {veth_host_ip}/30 dev {veth_host}"))?;
        run_in_netns(&format!("ip addr add {veth_guest_ip}/30 dev {veth_guest}"))?;
        run(&format!("ip link set {veth_host} up"))?;
        run_in_netns(&format!("ip link set {veth_guest} up"))?;

        run("iptables -P FORWARD ACCEPT")?;
        run(&format!(
            "iptables -t nat -A POSTROUTING -s {veth_host_ip}/30 -o {upstream_dev} -j MASQUERADE"
        ))?;
        run_in_netns(&format!("ip route add default via {veth_host_ip}"))?;
        run_in_netns(&format!(
            "iptables -t nat -A POSTROUTING -s {tap_net} -o {veth_guest} -j MASQUERADE"
        ))?;

        // Configure the guest.
        vm.ssh_iface(0)?.run(
            &format!("ip route add default via {tap_host_ip}"),
            std::time::Duration::from_secs(100),
        )?;
        let nameserver = utils::check_output(r"grep -oP 'nameserver\s+\K.+' /etc/resolv.conf")?
            .stdout
            .trim()
            .to_string();
        vm.ssh_iface(0)?.run(
            &format!("echo nameserver {nameserver} >/etc/resolv.conf"),
            std::time::Duration::from_secs(100),
        )?;

        let Some(ingress_ipv4) = ingress_ipv4 else {
            return Ok(());
        };
        let guest_ip = iface.guest_ip.clone();
        run_in_netns(&format!(
            "iptables -t nat -A PREROUTING -i {veth_guest} -d {ingress_ipv4} -j DNAT --to {guest_ip}"
        ))?;
        run(&format!("ip route add {ingress_ipv4} via {veth_guest_ip}"))?;
        Ok(())
    }

    /// Runs `trace-cmd` in the guest, streaming the trace data to the host.
    pub fn trace_cmd_guest(
        vm: &mut MicroVm,
        functions: &[&str],
        cmd: &str,
        port: u16,
    ) -> Result<Vec<PathBuf>> {
        docker_apt_install(&["trace-cmd"])?;
        println!("host> trace-cmd listen");
        std::process::Command::new("ip")
            .args([
                "netns",
                "exec",
                vm.netns.id(),
                "trace-cmd",
                "listen",
                "-p",
                &port.to_string(),
            ])
            .spawn()
            .context("starting trace-cmd listener")?;

        println!("guest> trace-cmd record");
        let host_ip = vm
            .iface
            .iter()
            .find(|(dev_name, _)| dev_name == "eth0")
            .map(|(_, iface)| iface.host_ip.clone())
            .ok_or_else(|| anyhow::anyhow!("microVM has no eth0 interface"))?;
        vm.ssh_iface(0)?.run(
            &format!(
                "trace-cmd record -N {host_ip}:{port} -p function {} {cmd}",
                functions.join(" ")
            ),
            std::time::Duration::from_secs(100),
        )?;

        let mut files: Vec<PathBuf> = std::fs::read_dir(".")?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .map(|name| {
                        let name = name.to_string_lossy();
                        name.starts_with("trace.") && name.ends_with(".dat")
                    })
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        Ok(files)
    }

    /// Runs GDB against the Firecracker gdb socket in a new tmux window.
    pub fn tmux_gdb(vm: &MicroVm) -> Result<()> {
        let gdb_socket = vm
            .gdb_socket
            .clone()
            .ok_or_else(|| anyhow::anyhow!("gdb socket is not enabled"))?;
        let chroot_gdb_socket = vm.jailer.chroot_path().join(gdb_socket);
        let script_path = std::env::temp_dir().join(format!("fc_gdb_{}.gdb", utils::random_str(8)));
        std::fs::write(
            &script_path,
            format!(
                "target remote {}\ndirectory resources/linux\nhbreak start_kernel\ncontinue\n",
                chroot_gdb_socket.display()
            ),
        )?;
        let kernel = vm
            .guest_kernel
            .as_ref()
            .map(|kernel| kernel.vmlinux.clone())
            .ok_or_else(|| anyhow::anyhow!("microVM has no guest kernel"))?;
        Self::tmux_neww(&format!(
            "\n            until [ -S {socket} ]; do\n                echo 'waiting for {socket}';\n                sleep 1;\n            done;\n            gdb {kernel} -x {script}\n            ",
            socket = chroot_gdb_socket.display(),
            kernel = kernel.display(),
            script = script_path.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_info_detects_container_marker() {
        // The marker may or may not exist; the call must not panic.
        let info = DockerInfo;
        let _ = info.in_docker();
    }

    #[test]
    fn subnet_counter_is_monotonic() {
        let before = SHARED_SUBNET_CTR.load(Ordering::SeqCst);
        SHARED_SUBNET_CTR.fetch_add(1, Ordering::SeqCst);
        assert_eq!(SHARED_SUBNET_CTR.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn how_to_console_uses_screen_session() {
        let vm = unreachable_vm();
        assert_eq!(MicrovmHelpers::how_to_console(&vm), "screen -dR unit-test");
    }

    /// Builds a `MicroVm` without touching the filesystem or a netns.
    fn unreachable_vm() -> MicroVm {
        // `MicroVm::new` validates binary paths, so build the struct directly
        // through the public constructor with existing paths.
        MicroVm::new(
            "unit-test",
            "/bin/true",
            "/bin/true",
            crate::network::NetNs::new("unit-test"),
            crate::vm_backend::VmBackend::Kvm,
        )
        .expect("creating an inert microVM")
    }
}
