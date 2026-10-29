// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host networking helpers, ported from `tests/host_tools/network.py`.
//!
//! `SSHConnection` keeps the same ControlMaster-based design: one persistent
//! connection is established on construction and every later command reuses
//! it through `ControlPath`.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::utils::{self, CommandReturn};

/// Multiplexed SSH connection to a guest, mirroring `SSHConnection`.
#[derive(Debug)]
pub struct SshConnection {
    netns: Option<String>,
    ssh_key: PathBuf,
    control_path: PathBuf,
    host: String,
    user: String,
    options: Vec<String>,
    closed: bool,
}

impl SshConnection {
    /// Instantiates the client and establishes the ControlPersist master.
    pub fn new(
        netns: Option<String>,
        ssh_key: impl Into<PathBuf>,
        control_path: impl Into<PathBuf>,
        host: impl Into<String>,
        user: impl Into<String>,
    ) -> Result<Self> {
        let ssh_key = ssh_key.into();
        let control_path = control_path.into();
        if !ssh_key.exists() {
            bail!("ssh key {} does not exist", ssh_key.display());
        }
        let mut perms = std::fs::metadata(&ssh_key)?.permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o400);
        std::fs::set_permissions(&ssh_key, perms)?;
        if std::fs::metadata(&ssh_key)?.permissions().mode() & 0o777 != 0o400 {
            bail!("ssh key {} must be mode 0400", ssh_key.display());
        }

        let mut connection = Self {
            netns,
            ssh_key,
            control_path,
            host: host.into(),
            user: user.into(),
            options: Vec::new(),
            closed: false,
        };
        connection.options = vec![
            "-o".to_string(),
            format!("ControlPath={}", connection.control_path.display()),
        ];
        connection.init_connection()?;
        Ok(connection)
    }

    fn user_host(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    fn remote_path(&self, path: &str) -> String {
        format!("{}:{path}", self.user_host())
    }

    fn scp(&self, source: &str, dest: &str, options: &[String]) -> Result<()> {
        let mut args = vec!["scp".to_string()];
        args.extend(options.iter().cloned());
        args.push(source.to_string());
        args.push(dest.to_string());
        let result = self.exec(&args, Duration::from_secs(100))?;
        if !result.success() {
            bail!("scp failed: {}", result.describe(&args.join(" ")));
        }
        Ok(())
    }

    /// Copies a local file (or tree) into the guest.
    pub fn scp_put(&self, local_path: &Path, remote_path: &str, recursive: bool) -> Result<()> {
        let mut options = self.options.clone();
        if recursive {
            options.push("-r".to_string());
        }
        self.scp(
            &local_path.to_string_lossy(),
            &self.remote_path(remote_path),
            &options,
        )
    }

    /// Copies a guest file (or tree) to the host.
    pub fn scp_get(&self, remote_path: &str, local_path: &Path, recursive: bool) -> Result<()> {
        let mut options = self.options.clone();
        if recursive {
            options.push("-r".to_string());
        }
        self.scp(
            &self.remote_path(remote_path),
            &local_path.to_string_lossy(),
            &options,
        )
    }

    /// Establishes the persistent background connection, retrying while the
    /// guest is still booting.
    fn init_connection(&mut self) -> Result<()> {
        let establish = vec![
            "ssh".to_string(),
            "-i".to_string(),
            self.ssh_key.to_string_lossy().into_owned(),
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "-o".to_string(),
            "ConnectTimeout=2".to_string(),
            "-o".to_string(),
            "ControlMaster=auto".to_string(),
            "-o".to_string(),
            "ControlPersist=yes".to_string(),
            "-o".to_string(),
            "KexAlgorithms=ecdh-sha2-nistp521".to_string(),
            "-o".to_string(),
            "HostKeyAlgorithms=rsa-sha2-512".to_string(),
            "-o".to_string(),
            "PubkeyAcceptedAlgorithms=rsa-sha2-512".to_string(),
            "-c".to_string(),
            "aes256-ctr".to_string(),
            self.options[0].clone(),
            self.options[1].clone(),
            self.user_host(),
            "true".to_string(),
        ];

        utils::retry_attempts(20, Duration::from_secs(1), || {
            if self.control_path.exists() {
                bail!(
                    "control path {} already exists",
                    self.control_path.display()
                );
            }
            let result = self.exec(&establish, Duration::from_secs(100));
            match result {
                Ok(out) if out.success() => Ok(()),
                Ok(out) => {
                    if self.control_path.exists() {
                        let _ = self.close(false);
                    }
                    Err(anyhow!("ssh master setup failed: {}", out.describe("ssh")))
                }
                Err(err) => {
                    if self.control_path.exists() {
                        let _ = self.close(false);
                    }
                    Err(err)
                }
            }
        })
    }

    /// Returns the ControlMaster pid when the persisted connection is alive.
    pub fn check_liveness(&self, strict: bool) -> Result<Option<i32>> {
        let check = vec![
            "ssh".to_string(),
            "-O".to_string(),
            "check".to_string(),
            self.options[0].clone(),
            self.options[1].clone(),
            self.user_host(),
        ];
        let result = self.exec(&check, Duration::from_secs(100));
        if !strict && result.is_err() {
            return Ok(None);
        }
        let result = result?;
        if !result.success() {
            if strict {
                bail!("ssh control master not alive: {}", result.stderr);
            }
            return Ok(None);
        }
        let regex = regex::Regex::new(r"Master running \(pid=(\d+)\)").expect("static regex");
        let caps = regex.captures(&result.stderr).ok_or_else(|| {
            anyhow!(
                "SSH ControlMaster connection not alive anymore: {}",
                result.stderr
            )
        })?;
        Ok(Some(caps[1].parse()?))
    }

    /// Closes the ControlPersist connection.
    pub fn close(&mut self, strict: bool) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let Some(master_pid) = self.check_liveness(strict)? else {
            return Ok(());
        };
        let stop = vec![
            "ssh".to_string(),
            "-O".to_string(),
            "stop".to_string(),
            self.options[0].clone(),
            self.options[1].clone(),
            self.user_host(),
        ];
        let result = self.exec(&stop, Duration::from_secs(100))?;
        if !result.stderr.contains("Stop listening request sent") {
            bail!("unexpected ssh -O stop output: {}", result.stderr);
        }
        if utils::wait_process_termination(master_pid, Duration::from_secs(5)).is_err() {
            // For some reason it will not exit, force it.
            // SAFETY: `kill` on a pid we obtained from `ssh -O check`.
            unsafe { libc::kill(master_pid, libc::SIGKILL) };
        }
        Ok(())
    }

    /// Runs a command string inside the guest.
    pub fn run(&self, cmd_string: &str, timeout: Duration) -> Result<CommandReturn> {
        self.run_opts(cmd_string, timeout, false, false)
    }

    /// Runs a command string and fails on a non-zero exit code.
    pub fn check_output(&self, cmd_string: &str, timeout: Duration) -> Result<CommandReturn> {
        self.run_opts(cmd_string, timeout, true, false)
    }

    /// Runs a command with explicit `check` / `debug` knobs.
    pub fn run_opts(
        &self,
        cmd_string: &str,
        timeout: Duration,
        check: bool,
        debug: bool,
    ) -> Result<CommandReturn> {
        self.check_liveness(true)?;
        let mut command = vec!["ssh".to_string()];
        if debug {
            command.push("-vvv".to_string());
        }
        command.extend(self.options.iter().cloned());
        command.push(self.user_host());
        command.push(cmd_string.to_string());

        let result = self.exec(&command, timeout)?;
        if check && !result.success() {
            bail!("{}", result.describe(cmd_string));
        }
        Ok(result)
    }

    fn exec(&self, cmd: &[String], timeout: Duration) -> Result<CommandReturn> {
        let mut full = Vec::with_capacity(cmd.len() + 3);
        if let Some(netns) = &self.netns {
            full.extend([
                "ip".to_string(),
                "netns".to_string(),
                "exec".to_string(),
                netns.clone(),
            ]);
        }
        full.extend(cmd.iter().cloned());
        utils::run_cmd_args_timeout(&full, Some(timeout))
    }
}

impl Drop for SshConnection {
    fn drop(&mut self) {
        if !self.closed && self.control_path.exists() {
            let _ = self.close(false);
        }
    }
}

/// Builds a locally-administered MAC address from an IPv4 address.
pub fn mac_from_ip(ip_address: &str) -> Result<String> {
    let mut parts = vec!["06".to_string(), "00".to_string()];
    for octet in ip_address.split('.') {
        let value: u8 = octet
            .parse()
            .with_context(|| format!("invalid IPv4 octet in {ip_address}"))?;
        parts.push(format!("{value:02x}"));
    }
    Ok(parts.join(":"))
}

/// Returns the guest interface name owning `guest_ip`.
pub fn get_guest_net_if_name(ssh: &SshConnection, guest_ip: &str) -> Result<Option<String>> {
    let cmd = format!("ip a s | grep '{guest_ip}' | tr -s ' ' | cut -d' ' -f6");
    let name = ssh
        .run(&cmd, Duration::from_secs(100))?
        .stdout
        .trim()
        .to_string();
    Ok(if name.is_empty() { None } else { Some(name) })
}

/// Random lowercase alphanumeric string of length `k`.
pub fn random_str(k: usize) -> String {
    const SYMBOLS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e3779b97f4a7c15)
        | 1;
    (0..k)
        .map(|_| {
            // xorshift64*: good enough for tap/netns suffixes.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let value = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
            SYMBOLS[(value >> 33) as usize % SYMBOLS.len()] as char
        })
        .collect()
}

/// A tap device living inside a network namespace.
#[derive(Debug, Clone)]
pub struct Tap {
    name: String,
    netns: NetNs,
}

impl Tap {
    /// Creates the tap device directly inside the netns to avoid conflicts.
    pub fn new(name: impl Into<String>, netns: NetNs, ip: Option<&str>) -> Result<Self> {
        let name = name.into();
        netns.check_output(&format!("ip tuntap add mode tap name {name}"))?;
        if let Some(ip) = ip {
            netns.check_output(&format!("ifconfig {name} {ip} up"))?;
        }
        Ok(Self { name, netns })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn netns(&self) -> &NetNs {
        &self.netns
    }

    /// Sets the length of the tap's TX queue.
    pub fn set_tx_queue_len(&self, tx_queue_len: u32) -> Result<()> {
        self.netns.check_output(&format!(
            "ip link set {} txqueuelen {tx_queue_len}",
            self.name
        ))?;
        Ok(())
    }
}

impl std::fmt::Display for Tap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<Tap name={} netns={}>", self.name, self.netns.id)
    }
}

/// Network interface configuration for a guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetIfaceConfig {
    pub host_ip: String,
    pub guest_ip: String,
    pub tap_name: String,
    pub dev_name: String,
    pub netmask_len: u8,
}

impl NetIfaceConfig {
    /// Defines the network interface with id `i`.
    pub fn with_id(i: usize, netmask_len: u8) -> Self {
        Self {
            host_ip: format!("192.168.{i}.1"),
            guest_ip: format!("192.168.{i}.2"),
            tap_name: format!("tap{i}"),
            dev_name: format!("eth{i}"),
            netmask_len,
        }
    }

    /// Guest MAC address derived from the guest IP.
    pub fn guest_mac(&self) -> String {
        mac_from_ip(&self.guest_ip).expect("guest_ip is generated from a valid octet")
    }

    /// The guest network in CIDR notation (`192.168.0.0/30`).
    pub fn network(&self) -> Result<String> {
        let host: Ipv4Addr = self.host_ip.parse().context("invalid host_ip")?;
        let mask = if self.netmask_len >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - self.netmask_len)
        };
        let network = Ipv4Addr::from(u32::from(host) & mask);
        Ok(format!("{network}/{}", self.netmask_len))
    }

    /// Serialises to the JSON shape used by `snapshot.json`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "host_ip": self.host_ip,
            "guest_ip": self.guest_ip,
            "tap_name": self.tap_name,
            "dev_name": self.dev_name,
            "netmask_len": self.netmask_len,
        })
    }

    /// Restores a configuration from `snapshot.json`.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        Ok(Self {
            host_ip: value["host_ip"]
                .as_str()
                .ok_or_else(|| anyhow!("missing host_ip"))?
                .to_string(),
            guest_ip: value["guest_ip"]
                .as_str()
                .ok_or_else(|| anyhow!("missing guest_ip"))?
                .to_string(),
            tap_name: value["tap_name"]
                .as_str()
                .ok_or_else(|| anyhow!("missing tap_name"))?
                .to_string(),
            dev_name: value["dev_name"]
                .as_str()
                .ok_or_else(|| anyhow!("missing dev_name"))?
                .to_string(),
            netmask_len: value["netmask_len"]
                .as_u64()
                .ok_or_else(|| anyhow!("missing netmask_len"))? as u8,
        })
    }
}

/// A host network namespace used by the jailed Firecracker process.
#[derive(Debug, Clone)]
pub struct NetNs {
    id: String,
    taps: std::sync::Arc<Mutex<BTreeMap<String, Tap>>>,
}

impl PartialEq for NetNs {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for NetNs {}

impl NetNs {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            taps: std::sync::Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Host path of the netns file.
    pub fn path(&self) -> PathBuf {
        Path::new("/var/run/netns").join(&self.id)
    }

    /// Prefix used to run commands inside the namespace.
    pub fn cmd_prefix(&self) -> String {
        format!("ip netns exec {}", self.id)
    }

    /// Runs a command inside the namespace.
    pub fn check_output(&self, cmd: &str) -> Result<utils::CommandReturn> {
        utils::check_output(&format!("{} {cmd}", self.cmd_prefix()))
    }

    /// Creates the namespace if missing.
    pub fn setup(&self) -> Result<()> {
        if !self.path().exists() {
            utils::check_output(&format!("ip netns add {}", self.id))?;
        }
        Ok(())
    }

    /// Deletes the namespace.
    pub fn cleanup(&self) -> Result<()> {
        if self.path().exists() {
            utils::check_output(&format!("ip netns del {}", self.id))?;
        }
        Ok(())
    }

    /// Adds (or reuses) a tap device inside the namespace.
    pub fn add_tap(&self, name: &str, ip: &str) -> Result<Tap> {
        let mut taps = self.taps.lock().expect("taps mutex poisoned");
        if let Some(tap) = taps.get(name) {
            return Ok(tap.clone());
        }
        let tap = Tap::new(name, self.clone(), Some(ip))?;
        taps.insert(name.to_string(), tap.clone());
        Ok(tap)
    }

    /// Whether any tap still has carrier signal.
    pub fn is_used(&self) -> Result<bool> {
        let taps: Vec<String> = self
            .taps
            .lock()
            .expect("taps mutex poisoned")
            .keys()
            .cloned()
            .collect();
        for tap in taps {
            let stdout = self
                .check_output(&format!("cat /sys/class/net/{tap}/carrier"))?
                .stdout;
            if stdout.trim() != "0" {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Number of taps currently tracked.
    pub fn tap_count(&self) -> usize {
        self.taps.lock().expect("taps mutex poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_from_ip_matches_python_doctest() {
        assert_eq!(mac_from_ip("192.168.241.2").unwrap(), "06:00:c0:a8:f1:02");
    }

    #[test]
    fn net_iface_config_network_cidr() {
        let iface = NetIfaceConfig::with_id(0, 30);
        assert_eq!(iface.guest_mac(), "06:00:c0:a8:00:02");
        assert_eq!(iface.network().unwrap(), "192.168.0.0/30");
        let iface = NetIfaceConfig::with_id(3, 24);
        assert_eq!(iface.network().unwrap(), "192.168.3.0/24");
    }

    #[test]
    fn net_iface_config_json_roundtrip() {
        let iface = NetIfaceConfig::with_id(1, 30);
        let json = iface.to_json();
        assert_eq!(NetIfaceConfig::from_json(&json).unwrap(), iface);
    }

    #[test]
    fn random_str_has_requested_length() {
        let s = random_str(16);
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
