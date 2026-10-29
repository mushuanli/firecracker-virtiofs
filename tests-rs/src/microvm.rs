// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Classes for working with microVMs, ported from
//! `tests/framework/microvm.py`.
//!
//! [`MicroVm`] creates, drives and destroys microVMs; [`MicroVmFactory`] builds
//! them from artifacts; [`Serial`] talks to the guest serial console through
//! the `screen` wrapper.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::artifacts::GuestKernel;
use crate::defs;
use crate::drive::VhostUserBlkBackend;
use crate::guest::GuestDistro;
use crate::host::fcmetrics::{FCMetricsMonitor, MetricsVm};
use crate::host::memory::{MemoryMonitor, MemoryMonitoredVm};
use crate::http_api::{json_body, Api};
use crate::hugepages::HugePagesConfig;
use crate::jailer::JailerContext;
use crate::kvm;
use crate::microvm_helpers::MicrovmHelpers;
use crate::network::{NetIfaceConfig, NetNs, SshConnection};
use crate::properties::global_props;
use crate::snapshot::{Snapshot, SnapshotType};
use crate::utils;
use crate::vm_backend::VmBackend;

/// A guest CPU template.
///
/// Re-exported from [`crate::cpu_templates`] so the harness has exactly one
/// template type, mirroring python's `str | dict | None` union.
pub use crate::cpu_templates::CpuTemplate;

/// Background monitor attached to a microVM (memory / FC metrics).
pub trait MicroVmMonitor: Send {
    /// Stops the monitor thread.
    fn stop(&mut self);
    /// Raises if the collected samples violate the monitor's thresholds.
    fn check(&mut self) -> Result<()>;
}

/// A userfaultfd handler process bound to a snapshot's memory file.
pub trait MemBackendHandler {
    /// Path of the unix socket the VM's UFFD backend connects to.
    fn socket_path(&self) -> &Path;
    /// Handler logs, for diagnostics on failure.
    fn log_data(&self) -> String;
    /// Whether the handler is still running.
    fn is_running(&mut self) -> bool;
    /// Kills the handler.
    fn kill(&mut self);
}

/// Options controlling [`MicroVm::restore_from_snapshot`].
pub struct RestoreOptions {
    pub resume: bool,
    pub rename_interfaces: Option<BTreeMap<String, String>>,
    pub vsock_override: Option<String>,
    pub clock_realtime: bool,
    pub huge_pages: Option<HugePagesConfig>,
    pub uffd: Option<Box<dyn MemBackendHandler>>,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            resume: false,
            rename_interfaces: None,
            vsock_override: None,
            clock_realtime: false,
            huge_pages: None,
            uffd: None,
        }
    }
}

/// A Firecracker microVM.
pub struct MicroVm {
    microvm_id: String,
    fc_binary_path: PathBuf,
    jailer_binary_path: PathBuf,
    pub backend: VmBackend,
    pub jailer: JailerContext,
    pub netns: NetNs,
    pub pci_enabled: bool,
    pub guest_kernel: Option<GuestKernel>,
    pub boot_image: Option<PathBuf>,
    pub rootfs_file: Option<PathBuf>,
    pub distro: Option<GuestDistro>,
    pub ssh_key: Option<PathBuf>,
    pub initrd_file: Option<PathBuf>,
    pub boot_args: Option<String>,
    pub api: Option<Api>,
    pub log_file: Option<PathBuf>,
    pub serial_out_path: Option<PathBuf>,
    pub metrics_file: Option<PathBuf>,
    spawned: bool,
    killed: bool,
    /// Network interfaces keyed by guest device name, insertion-ordered.
    pub iface: Vec<(String, NetIfaceConfig)>,
    pub disks: BTreeMap<String, PathBuf>,
    pub disks_vhost_user: BTreeMap<String, Box<dyn VhostUserBlkBackend>>,
    pub huge_pages: HugePagesConfig,
    pub vcpus_count: u32,
    pub mem_size_bytes: u64,
    pub cpu_template_name: String,
    pub custom_cpu_template: Option<CpuTemplate>,
    pre_cmd: Vec<String>,
    pub metadata_file: Option<PathBuf>,
    screen_pid: Option<i32>,
    time_api_requests: bool,
    firecracker_pid: Option<i32>,
    ssh_connections: Vec<SshConnection>,
    monitors: Vec<Box<dyn MicroVmMonitor>>,
    /// Typed handle to the RSS monitor, so snapshot/restore can retune its
    /// threshold the way python's `MemoryMonitor` does.
    memory_monitor: Option<std::sync::Arc<MemoryMonitor>>,
    uffd_handler: Option<Box<dyn MemBackendHandler>>,
    pub gdb_socket: Option<String>,
    pub helpers: MicrovmHelpers,
}

impl std::fmt::Debug for MicroVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<Microvm id={}>", self.microvm_id)
    }
}

impl MicroVm {
    /// Sets up microVM attributes, paths and data structures.
    pub fn new(
        microvm_id: impl Into<String>,
        fc_binary_path: impl Into<PathBuf>,
        jailer_binary_path: impl Into<PathBuf>,
        netns: NetNs,
        backend: VmBackend,
    ) -> Result<Self> {
        let microvm_id = microvm_id.into();
        let fc_binary_path = fc_binary_path.into();
        let jailer_binary_path = jailer_binary_path.into();
        if !fc_binary_path.exists() {
            bail!("missing firecracker binary at {}", fc_binary_path.display());
        }
        if !jailer_binary_path.exists() {
            bail!("missing jailer binary at {}", jailer_binary_path.display());
        }

        let mut jailer = JailerContext::new(microvm_id.clone(), fc_binary_path.clone());
        jailer.netns = Some(netns.clone());

        // Copy /etc/localtime into the jailer root.
        let vm = Self {
            microvm_id,
            fc_binary_path,
            jailer_binary_path,
            backend,
            jailer,
            netns,
            pci_enabled: false,
            guest_kernel: None,
            boot_image: None,
            rootfs_file: None,
            distro: None,
            ssh_key: None,
            initrd_file: None,
            boot_args: None,
            api: None,
            log_file: None,
            serial_out_path: None,
            metrics_file: None,
            spawned: false,
            killed: false,
            iface: Vec::new(),
            disks: BTreeMap::new(),
            disks_vhost_user: BTreeMap::new(),
            huge_pages: HugePagesConfig::None,
            vcpus_count: 0,
            mem_size_bytes: 0,
            cpu_template_name: "None".to_string(),
            custom_cpu_template: None,
            pre_cmd: Vec::new(),
            metadata_file: None,
            screen_pid: None,
            time_api_requests: true,
            firecracker_pid: None,
            ssh_connections: Vec::new(),
            monitors: Vec::new(),
            memory_monitor: None,
            uffd_handler: None,
            gdb_socket: None,
            helpers: MicrovmHelpers::default(),
        };
        let _ = vm.helpers; // helpers borrow the vm lazily through its methods
        Ok(vm)
    }

    /// Path of the Firecracker binary backing this microVM.
    pub fn fc_binary_path(&self) -> &Path {
        &self.fc_binary_path
    }

    /// Path of the jailer binary backing this microVM.
    pub fn jailer_binary_path(&self) -> &Path {
        &self.jailer_binary_path
    }

    /// Unique identifier of this microVM.
    pub fn id(&self) -> &str {
        &self.microvm_id
    }

    /// Path of the microVM root on disk.
    pub fn path(&self) -> PathBuf {
        self.jailer.chroot_base_with_id()
    }

    /// Path of the microVM chroot.
    pub fn chroot(&self) -> PathBuf {
        self.jailer.chroot_path()
    }

    /// The API client, when the VM has been spawned.
    pub fn api(&self) -> Result<&Api> {
        self.api
            .as_ref()
            .ok_or_else(|| anyhow!("microVM {} is not spawned", self.microvm_id))
    }

    /// Firecracker process id, read from the jailer pid file.
    pub fn firecracker_pid(&self) -> Option<i32> {
        self.firecracker_pid
    }

    /// Screen session name.
    pub fn screen_session(&self) -> &str {
        &self.microvm_id
    }

    /// Screen log path.
    pub fn screen_log(&self) -> PathBuf {
        PathBuf::from(format!("/tmp/screen-{}.log", self.microvm_id))
    }

    /// Enables the PCI transport for this microVM.
    pub fn set_pci(&mut self, pci: bool) {
        self.pci_enabled = pci;
        if pci {
            self.jailer.set_extra_arg("enable-pci", None::<String>);
        }
    }

    /// Firecracker log contents.
    pub fn log_data(&self) -> String {
        self.log_file
            .as_ref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .unwrap_or_default()
    }

    /// Current instance state reported by `GET /`.
    pub fn state(&self) -> Result<String> {
        let body = self.api()?.describe.get()?.json()?;
        body.get("state")
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("GET / returned {}", body))
    }

    /// CloudWatch dimensions describing this microVM.
    pub fn dimensions(&self) -> Value {
        let props = global_props();
        json!({
            "instance": props.instance,
            "cpu_model": props.cpu_model,
            "host_kernel": format!("linux-{}", props.host_linux_version),
            "guest_kernel": self.guest_kernel.as_ref().map(|k| k.metric_id()).unwrap_or_default(),
            "rootfs": self.rootfs_file.as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            "vcpus": self.vcpus_count.to_string(),
            "guest_memory": format!("{}MB", self.mem_size_bytes / (1024 * 1024)),
            "pci": self.pci_enabled.to_string(),
        })
    }

    /// Concrete boot image this VM boots.
    pub fn kernel_file(&self) -> Option<PathBuf> {
        if let Some(image) = &self.boot_image {
            return Some(image.clone());
        }
        self.guest_kernel
            .as_ref()
            .map(|kernel| self.backend.kernel_image_for(kernel))
    }

    /// Logical guest kernel version as a tuple.
    pub fn guest_kernel_version(&self) -> Option<Vec<u32>> {
        self.guest_kernel
            .as_ref()
            .map(|kernel| kernel.version_tuple())
    }

    /// Inserts every JSON object written by Firecracker into the metrics file.
    pub fn get_metrics(&self) -> Result<Vec<Value>> {
        let path = self
            .metrics_file
            .as_ref()
            .ok_or_else(|| anyhow!("no metrics file configured"))?;
        let contents = std::fs::read_to_string(path).unwrap_or_default();
        let mut metrics = Vec::new();
        for line in contents.lines() {
            if !line.ends_with('}') {
                // Partial write: skip it like the python harness does.
                continue;
            }
            match serde_json::from_str(line) {
                Ok(value) => metrics.push(value),
                Err(_) => continue,
            }
        }
        Ok(metrics)
    }

    /// Flushes the microVM metrics and returns the latest datapoint.
    pub fn flush_metrics(&self) -> Result<Value> {
        self.api()?
            .actions
            .put(json!({"action_type": "FlushMetrics"}))?;
        self.get_metrics()?
            .pop()
            .ok_or_else(|| anyhow!("metrics file is empty after flush"))
    }

    /// Creates a hard link to a resource inside this microVM's jail.
    pub fn create_jailed_resource(&self, path: &Path) -> Result<PathBuf> {
        self.jailer.jailed_path(path, true, ".")
    }

    /// Returns the path a resource has inside this microVM's jail.
    pub fn get_jailed_resource(&self, path: &Path) -> Result<PathBuf> {
        self.jailer.jailed_path(path, false, ".")
    }

    /// Prepends commands to the command line used to launch the microVM.
    pub fn add_pre_cmd(&mut self, pre_cmd: &[&str]) {
        let mut combined: Vec<String> = pre_cmd.iter().map(|c| c.to_string()).collect();
        combined.extend(self.pre_cmd.iter().cloned());
        self.pre_cmd = combined;
    }

    /// Adds a background monitor; monitors are stopped by [`MicroVm::kill`].
    pub fn add_monitor(&mut self, monitor: Box<dyn MicroVmMonitor>) {
        self.monitors.push(monitor);
    }

    /// Pins the VMM thread to `cpu_id`.
    pub fn pin_vmm(&self, cpu_id: usize) -> Result<bool> {
        let Some(pid) = self.firecracker_pid else {
            return Ok(false);
        };
        for (thread_name, tids) in utils::get_threads(pid) {
            if thread_name.starts_with("firecracker") {
                for tid in tids {
                    utils::set_cpu_affinity(tid, &[cpu_id])?;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Pins a vCPU thread to `cpu_id`.
    pub fn pin_vcpu(&self, vcpu_id: usize, cpu_id: usize) -> Result<bool> {
        let Some(pid) = self.firecracker_pid else {
            return Ok(false);
        };
        let threads = utils::get_threads(pid);
        let tids = threads
            .get(&format!("fc_vcpu {vcpu_id}"))
            .ok_or_else(|| anyhow!("fc_vcpu {vcpu_id} thread not found"))?;
        for tid in tids {
            utils::set_cpu_affinity(*tid, &[cpu_id])?;
        }
        Ok(true)
    }

    /// Pins the API server thread to `cpu_id`.
    pub fn pin_api(&self, cpu_id: usize) -> Result<bool> {
        let Some(pid) = self.firecracker_pid else {
            return Ok(false);
        };
        let threads = utils::get_threads(pid);
        let tids = threads
            .get("fc_api")
            .ok_or_else(|| anyhow!("fc_api thread not found"))?;
        for tid in tids {
            utils::set_cpu_affinity(*tid, &[cpu_id])?;
        }
        Ok(true)
    }

    /// Pins every microVM thread to consecutive physical cores.
    pub fn pin_threads(&self, first_cpu: usize) -> Result<usize> {
        for vcpu in 0..self.vcpus_count as usize {
            let pcpu = first_cpu + vcpu;
            if !self.pin_vcpu(vcpu, pcpu)? {
                bail!("Failed to pin fc_vcpu {vcpu} thread to core {pcpu}.");
            }
        }
        if !self.pin_vmm(first_cpu + self.vcpus_count as usize)? {
            bail!("Failed to pin firecracker thread.");
        }
        if !self.pin_api(first_cpu + self.vcpus_count as usize + 1)? {
            bail!("Failed to pin fc_api thread.");
        }
        Ok(first_cpu + self.vcpus_count as usize + 2)
    }

    /// Starts a microVM as a daemon or in a screen session.
    pub fn spawn(&mut self, config: SpawnConfig) -> Result<()> {
        let log_level = normalize_log_level(&config.log_level);
        self.jailer.setup()?;

        self.api = Some(Api::new(self.jailer.api_socket_path(), config.validate_api));

        if let Some(log_file) = &config.log_file {
            let path = self.path().join(log_file);
            touch(&path)?;
            let jailed = self.create_jailed_resource(&path)?;
            self.log_file = Some(path);
            self.jailer
                .set_extra_arg("log-path", Some(jailed.to_string_lossy().into_owned()));
            self.jailer.set_extra_arg("level", Some(log_level.clone()));
            if config.log_show_level {
                self.jailer.set_extra_arg("show-level", None::<String>);
            }
            if config.log_show_origin {
                self.jailer.set_extra_arg("show-log-origin", None::<String>);
            }
        }

        if let Some(serial_out_path) = &config.serial_out_path {
            let path = self.path().join(serial_out_path);
            touch(&path)?;
            let _ = self.create_jailed_resource(&path)?;
            self.serial_out_path = Some(path);
        }

        if let Some(metrics_path) = &config.metrics_path {
            let path = self.path().join(metrics_path);
            touch(&path)?;
            let _ = self.create_jailed_resource(&path)?;
            let metrics_name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            self.metrics_file = Some(path);
            self.jailer
                .set_extra_arg("metrics-path", Some(metrics_name));
        } else if config.emit_metrics {
            bail!("emit_metrics requires a metrics path");
        }

        if let Some(metadata_file) = &self.metadata_file {
            if metadata_file.exists() {
                let _ = self.create_jailed_resource(metadata_file)?;
            }
            self.jailer.set_extra_arg(
                "metadata",
                Some(
                    metadata_file
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                ),
            );
        }

        if log_level != "Debug" {
            // Checking the timings requires DEBUG level log messages.
            self.time_api_requests = false;
        }

        let mut cmd: Vec<String> = self.pre_cmd.clone();
        cmd.push(self.jailer_binary_path.to_string_lossy().into_owned());
        cmd.extend(self.jailer.construct_param_list());

        if self.jailer.daemonize {
            utils::check_output_args(&cmd)?;
        } else {
            let screen_log = self.screen_log();
            let session = self.microvm_id.clone();
            let binary = cmd[0].clone();
            let params = cmd[1..].to_vec();
            let screen_pid =
                utils::start_screen_process(&screen_log, &session, Path::new(&binary), &params)?;
            self.screen_pid = Some(screen_pid);
        }

        // With `--new-pid-ns` Firecracker detaches from screen and the screen
        // process exits; do not try to kill it to avoid a race.
        if self.jailer.new_pid_ns {
            self.screen_pid = None;
        }

        self.spawned = true;
        self.killed = false;
        self.firecracker_pid = self.read_pid_file()?;

        if config.emit_metrics {
            self.attach_fc_metrics_monitor(Duration::from_secs(60))?;
        }

        if config.expect_failure {
            return Ok(());
        }

        if self.jailer.has_extra_arg("config-file") && !self.iface.is_empty() {
            if config.serial_out_path.is_some() {
                bail!("config-file based spawn must not set serial_out_path");
            }
            self.wait_for_ssh_up()?;
        } else if !self.jailer.has_extra_arg("no-api") {
            let api = self.api()?;
            api.wait_for_socket(Duration::from_secs(3))?;
            if let Some(serial_out_path) = &self.serial_out_path {
                let name = serial_out_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                self.api()?.serial.put(json!({ "serial_out_path": name }))?;
            }
        } else if self.log_file.is_some()
            && matches!(log_level.as_str(), "Trace" | "Debug" | "Info")
        {
            self.check_log_message("Running Firecracker")?;
        }

        Ok(())
    }

    fn read_pid_file(&self) -> Result<Option<i32>> {
        let pid_file = self.jailer.pid_file();
        if !pid_file.exists() {
            return Ok(None);
        }
        let contents = utils::retry_attempts(5, Duration::from_millis(100), || {
            let contents = std::fs::read_to_string(&pid_file)?;
            contents
                .trim()
                .parse::<i32>()
                .with_context(|| format!("malformed pid file {}", pid_file.display()))
        })?;
        Ok(Some(contents))
    }

    /// Waits until `message` appears in the Firecracker log.
    pub fn check_log_message(&self, message: &str) -> Result<()> {
        utils::retry_for(Duration::from_secs(1), Duration::from_millis(10), || {
            let log = self.log_data();
            if log.contains(message) {
                Ok(())
            } else {
                bail!("Message (\"{message}\") not found in log data")
            }
        })
    }

    /// Waits until any message in `messages` appears in the log.
    pub fn check_any_log_message(&self, messages: &[&str]) -> Result<()> {
        utils::retry_attempts(5, Duration::from_millis(200), || {
            let log = self.log_data();
            if messages.iter().any(|message| log.contains(message)) {
                Ok(())
            } else {
                bail!("{messages:?} were not found in this log: {log}")
            }
        })
    }

    /// Reads the exit code out of the Firecracker log.
    pub fn get_exit_code(&self) -> Result<i32> {
        let regex =
            regex::Regex::new(r"Firecracker exiting (with error|successfully). exit_code=(\d+)")
                .expect("static regex");
        utils::retry_attempts(5, Duration::from_millis(200), || {
            let log = self.log_data();
            let caps = regex
                .captures(&log)
                .ok_or_else(|| anyhow!("unable to find exit code from the log"))?;
            caps[2].parse::<i32>().context("parsing exit code")
        })
    }

    /// Sends a string to the Firecracker serial console via screen.
    pub fn serial_input(&self, input_string: &str) -> Result<utils::CommandReturn> {
        utils::check_output(&format!(
            "screen -S {} -p 0 -X stuff \"{input_string}\"",
            self.microvm_id
        ))
    }

    /// Configures the microVM, delegating to the configured backend.
    pub fn basic_config(&mut self, config: kvm::KvmBasicConfig) -> Result<()> {
        match self.backend {
            VmBackend::Kvm => kvm::kvm_basic_config(self, config),
        }
    }

    /// Sets the guest CPU template.
    pub fn set_cpu_template(&mut self, template: Option<CpuTemplate>) -> Result<()> {
        let template = template.unwrap_or(CpuTemplate::None);
        self.cpu_template_name = crate::cpu_templates::get_cpu_template_name(&template, false);
        match template {
            CpuTemplate::None => {}
            CpuTemplate::Static(name) => {
                self.api()?
                    .machine_config
                    .patch(json!({ "cpu_template": name }))?;
            }
            CpuTemplate::Custom { template, .. } => {
                // python does `api.cpu_config.put(**cpu_template["template"])`,
                // so the request body is the inner `template` document.
                let body = template.get("template").cloned().unwrap_or(template);
                self.api()?.cpu_config.put(body)?;
            }
        }
        Ok(())
    }

    /// Adds a block device.
    pub fn add_drive(&mut self, drive: DriveConfig) -> Result<()> {
        let jailed = self.create_jailed_resource(&drive.path_on_host)?;
        let body = json_body(vec![
            ("drive_id", Some(json!(drive.drive_id))),
            ("path_on_host", Some(json!(jailed.to_string_lossy()))),
            ("is_root_device", Some(json!(drive.is_root_device))),
            ("is_read_only", Some(json!(drive.is_read_only))),
            ("partuuid", drive.partuuid.map(|v| json!(v))),
            ("cache_type", drive.cache_type.map(|v| json!(v))),
            ("io_engine", drive.io_engine.map(|v| json!(v))),
            ("topology", drive.topology.clone()),
            ("blk_size", drive.blk_size.clone()),
            ("discard", drive.discard.map(|v| json!(v))),
        ]);
        self.api()?.drive.put(body)?;
        self.disks.insert(drive.drive_id, drive.path_on_host);
        Ok(())
    }

    /// Adds a vhost-user block device.
    pub fn add_vhost_user_drive(&mut self, drive: VhostUserDriveConfig) -> Result<()> {
        if let Some(mut previous) = self.disks_vhost_user.remove(&drive.drive_id) {
            previous.kill()?;
        }
        let mut backend = drive.backend;
        let socket_path = backend.spawn(self.jailer.uid, self.jailer.gid)?;
        let body = json_body(vec![
            ("drive_id", Some(json!(drive.drive_id))),
            ("socket", Some(json!(socket_path))),
            ("partuuid", drive.partuuid.map(|v| json!(v))),
            ("is_root_device", Some(json!(drive.is_root_device))),
            ("cache_type", drive.cache_type.map(|v| json!(v))),
        ]);
        self.api()?.drive.put(body)?;
        self.disks_vhost_user.insert(drive.drive_id, backend);
        Ok(())
    }

    /// Modifies an existing block device.
    pub fn patch_drive(&mut self, drive_id: &str, file: Option<&Path>) -> Result<()> {
        match file {
            Some(file) => {
                let jailed = self.create_jailed_resource(file)?;
                self.api()?.drive.patch(json!({
                    "drive_id": drive_id,
                    "path_on_host": jailed.to_string_lossy(),
                }))?;
                self.disks.insert(drive_id.to_string(), file.to_path_buf());
            }
            None => {
                self.api()?.drive.patch(json!({ "drive_id": drive_id }))?;
            }
        }
        Ok(())
    }

    /// Adds a network interface.
    pub fn add_net_iface(
        &mut self,
        iface: Option<NetIfaceConfig>,
        call_api: bool,
    ) -> Result<NetIfaceConfig> {
        let iface = iface.unwrap_or_else(|| NetIfaceConfig::with_id(self.iface.len(), 30));
        let ip = format!("{}/{}", iface.host_ip, iface.netmask_len);
        self.netns.add_tap(&iface.tap_name, &ip)?;
        self.iface.push((iface.dev_name.clone(), iface.clone()));

        if call_api {
            self.api()?.network.put(json!({
                "iface_id": iface.dev_name,
                "host_dev_name": iface.tap_name,
                "guest_mac": iface.guest_mac(),
            }))?;
        }
        Ok(iface)
    }

    /// Adds a pmem device.
    pub fn add_pmem(&mut self, pmem: PmemConfig) -> Result<()> {
        let jailed = self.create_jailed_resource(&pmem.path_on_host)?;
        self.api()?.pmem.put(json!({
            "id": pmem.pmem_id,
            "path_on_host": jailed.to_string_lossy(),
            "root_device": pmem.root_device,
            "read_only": pmem.read_only,
        }))?;
        self.disks.insert(pmem.pmem_id, pmem.path_on_host);
        Ok(())
    }

    /// Prepares and starts the microVM.
    pub fn start(&mut self) -> Result<()> {
        let state = self.state()?;
        if state != "Not started" {
            bail!("cannot start microVM in state {state}");
        }
        self.backend.prepare_start()?;
        self.api()?
            .actions
            .put(json!({"action_type": "InstanceStart"}))?;

        let state = self.state()?;
        if state != "Running" {
            bail!("microVM did not start, state is {state}");
        }
        if !self.iface.is_empty() {
            self.wait_for_ssh_up()?;
        }
        Ok(())
    }

    /// Pauses the microVM.
    pub fn pause(&self) -> Result<()> {
        self.api()?.vm.patch(json!({ "state": "Paused" }))?;
        Ok(())
    }

    /// Resumes the microVM.
    pub fn resume(&self) -> Result<()> {
        self.api()?.vm.patch(json!({ "state": "Resumed" }))?;
        Ok(())
    }

    /// Creates a snapshot of this microVM, pausing it first.
    pub fn make_snapshot(&mut self, config: SnapshotConfig) -> Result<Snapshot> {
        self.pause()?;
        if let Some(monitor) = &self.memory_monitor {
            monitor.set_threshold_for_snapshot();
        }
        for monitor in &mut self.monitors {
            let _ = monitor;
        }
        let body = json_body(vec![
            ("mem_file_path", Some(json!(config.mem_path))),
            ("snapshot_path", Some(json!(config.vmstate_path))),
            (
                "snapshot_type",
                Some(json!(config.snapshot_type.api_type())),
            ),
            (
                "sync_snapshot_files",
                config.sync_snapshot_files.map(|v| json!(v)),
            ),
        ]);
        self.api()?.snapshot_create.put(body)?;

        let root = self.chroot();
        let mut meta = BTreeMap::new();
        if let Some(kernel) = &self.guest_kernel {
            meta.insert(
                "kernel_file".to_string(),
                kernel.vmlinux.to_string_lossy().into_owned(),
            );
        }
        if let Some(rootfs) = &self.rootfs_file {
            meta.insert(
                "rootfs_file".to_string(),
                rootfs.to_string_lossy().into_owned(),
            );
        }
        meta.insert("vcpus_count".to_string(), self.vcpus_count.to_string());

        Ok(Snapshot {
            vmstate: root.join(&config.vmstate_path),
            mem: root.join(&config.mem_path),
            net_ifaces: self.iface.iter().map(|(_, iface)| iface.clone()).collect(),
            disks: self.disks.clone(),
            ssh_key: self.ssh_key.clone().unwrap_or_default(),
            snapshot_type: config.snapshot_type,
            meta,
        })
    }

    /// Makes a Diff snapshot.
    pub fn snapshot_diff(&mut self) -> Result<Snapshot> {
        self.make_snapshot(SnapshotConfig::new(SnapshotType::Diff))
    }

    /// Makes a Full snapshot.
    pub fn snapshot_full(&mut self) -> Result<Snapshot> {
        self.make_snapshot(SnapshotConfig::new(SnapshotType::Full))
    }

    /// Restores a snapshot into this microVM.
    pub fn restore_from_snapshot(
        &mut self,
        snapshot: &Snapshot,
        options: RestoreOptions,
    ) -> Result<Snapshot> {
        let mut options = options;
        let jailed_snapshot = snapshot.copy_to_chroot(&self.chroot())?;

        if let Some(handler) = options.uffd.take() {
            self.uffd_handler = Some(handler);
        }
        let uffd_socket = self
            .uffd_handler
            .as_ref()
            .map(|handler| handler.socket_path().to_path_buf());

        let jailed_mem = Path::new("/").join(
            jailed_snapshot
                .mem
                .file_name()
                .ok_or_else(|| anyhow!("snapshot mem has no file name"))?,
        );
        let jailed_vmstate = Path::new("/").join(
            jailed_snapshot
                .vmstate
                .file_name()
                .ok_or_else(|| anyhow!("snapshot vmstate has no file name"))?,
        );

        if jailed_snapshot.disks.is_empty() {
            bail!("Snapshot requires at least one disk.");
        }
        for disk in jailed_snapshot.disks.values() {
            self.create_jailed_resource(disk)?;
        }
        self.disks = jailed_snapshot.disks.clone();
        self.ssh_key = Some(jailed_snapshot.ssh_key.clone());

        let ifaces = jailed_snapshot.net_ifaces.clone();
        for iface in ifaces {
            self.add_net_iface(Some(iface), false)?;
        }

        let mem_backend = match uffd_socket {
            Some(socket) => json!({
                "backend_type": "Uffd",
                "backend_path": socket.to_string_lossy(),
            }),
            None => json!({
                "backend_type": "File",
                "backend_path": jailed_mem.to_string_lossy(),
            }),
        };

        if let Some(kernel_file) = jailed_snapshot.meta.get("kernel_file") {
            self.guest_kernel = Some(GuestKernel::from_vmlinux(Path::new(kernel_file)).with_context(
                || {
                    format!(
                        "snapshot {} records guest kernel {kernel_file:?}, which is not a recognised artifact",
                        snapshot.vmstate.parent().map(|p| p.display().to_string()).unwrap_or_default()
                    )
                },
            )?);
        }
        if let Some(rootfs_file) = jailed_snapshot.meta.get("rootfs_file") {
            let path = PathBuf::from(rootfs_file);
            self.distro = GuestDistro::from_rootfs(&path);
            self.rootfs_file = Some(path);
        }
        if let Some(vcpus) = jailed_snapshot.meta.get("vcpus_count") {
            if let Ok(count) = vcpus.parse::<u32>() {
                self.vcpus_count = count;
            }
        }

        let mut optional = serde_json::Map::new();
        if let Some(rename) = &options.rename_interfaces {
            let overrides: Vec<Value> = rename
                .iter()
                .map(|(iface_id, host_dev_name)| {
                    json!({"iface_id": iface_id, "host_dev_name": host_dev_name})
                })
                .collect();
            optional.insert("network_overrides".into(), json!(overrides));
        }
        if let Some(vsock) = &options.vsock_override {
            optional.insert("vsock_override".into(), json!({"uds_path": vsock}));
        }
        if options.clock_realtime {
            optional.insert("clock_realtime".into(), json!(true));
        }
        if let Some(huge_pages) = options.huge_pages {
            optional.insert("huge_pages".into(), json!(huge_pages.api_value()));
        }

        let mut body = json!({
            "mem_backend": mem_backend,
            "snapshot_path": jailed_vmstate.to_string_lossy(),
            "enable_diff_snapshots": jailed_snapshot.snapshot_type.needs_dirty_page_tracking(),
            "resume_vm": options.resume,
        });
        if let Value::Object(map) = &mut body {
            for (key, value) in optional {
                map.insert(key, value);
            }
        }
        self.api()?.snapshot_load.put(body)?;

        if let Some(huge_pages) = options.huge_pages {
            self.huge_pages = huge_pages;
        }

        if let Ok(machine_config) = self.api()?.machine_config.get() {
            if let Ok(config) = machine_config.json() {
                if let Some(mem_size_mib) = config.get("mem_size_mib").and_then(|v| v.as_u64()) {
                    self.mem_size_bytes = mem_size_mib * (1 << 20);
                }
            }
        }

        if let Some(monitor) = &self.memory_monitor {
            monitor.set_threshold_for_restored_vm();
        }

        if !jailed_snapshot.net_ifaces.is_empty() && options.resume {
            self.wait_for_ssh_up()?;
        }
        Ok(jailed_snapshot)
    }

    /// Restores a snapshot from a directory written by
    /// [`Snapshot::save_to`].
    pub fn restore_from_path(
        &mut self,
        snap_dir: &Path,
        options: RestoreOptions,
    ) -> Result<Snapshot> {
        let snapshot = Snapshot::load_from(snap_dir)?;
        self.restore_from_snapshot(&snapshot, options)
    }

    /// Enables the entropy device.
    pub fn enable_entropy_device(&self) -> Result<()> {
        self.api()?.entropy.put(json!({}))?;
        Ok(())
    }

    /// Returns a cached SSH connection on the given interface index.
    pub fn ssh_iface(&mut self, iface_idx: usize) -> Result<&SshConnection> {
        if self.ssh_connections.len() > iface_idx {
            return Ok(&self.ssh_connections[iface_idx]);
        }
        while self.ssh_connections.len() <= iface_idx {
            let guest_ip = self
                .iface
                .get(self.ssh_connections.len())
                .map(|(_, iface)| iface.guest_ip.clone())
                .ok_or_else(|| anyhow!("no network interface at index {iface_idx}"))?;
            let ssh_key = self
                .ssh_key
                .clone()
                .ok_or_else(|| anyhow!("microVM has no ssh key"))?;
            let control_path = self
                .chroot()
                .join(format!("ssh-{}.sock", self.ssh_connections.len()));
            let connection = SshConnection::new(
                Some(self.netns.id().to_string()),
                ssh_key,
                control_path,
                guest_ip,
                "root",
            )?;
            self.ssh_connections.push(connection);
        }
        Ok(&self.ssh_connections[iface_idx])
    }

    /// Waits for the guest to come up and answer over SSH.
    pub fn wait_for_ssh_up(&mut self) -> Result<()> {
        let _ = self.ssh_iface(0)?;
        Ok(())
    }

    /// Backtraces of all Firecracker threads.
    pub fn thread_backtraces(&self) -> String {
        let Some(pid) = self.firecracker_pid else {
            return String::new();
        };
        let mut backtraces = Vec::new();
        for (thread_name, tids) in utils::get_threads(pid) {
            for tid in tids {
                if let Ok(stack) = std::fs::read_to_string(format!("/proc/{tid}/stack")) {
                    backtraces.push(format!("{thread_name} (pid={tid}):\n{stack}"));
                }
            }
        }
        backtraces.join("\n")
    }

    /// Dumps debug information about this microVM.
    pub fn dump_debug_information(&self, what: &str) -> String {
        let mut out = format!("{what}\nFirecracker logs:\n{}", self.log_data());
        if let Some(handler) = &self.uffd_handler {
            out.push_str(&format!("\nUffd logs:\n{}", handler.log_data()));
        }
        if !self.killed {
            out.push_str(&format!(
                "\nThread backtraces:\n{}",
                self.thread_backtraces()
            ));
        }
        eprintln!("{out}");
        out
    }

    /// Enables GDB debugging on the microVM.
    pub fn enable_gdb(&mut self) -> Result<()> {
        self.gdb_socket = Some("gdb.socket".to_string());
        self.api()?
            .machine_config
            .patch(json!({"gdb_socket_path": "gdb.socket"}))?;
        Ok(())
    }

    /// Sends a hot(un)plug request and waits for completion.
    ///
    /// Returns `(api_latency, total_latency)`.
    pub fn hotplug_memory(
        &self,
        requested_size_mib: i64,
        timeout: Duration,
        poll: Duration,
    ) -> Result<(Duration, Duration)> {
        let started = Instant::now();
        self.api()?
            .memory_hotplug
            .patch(json!({"requested_size_mib": requested_size_mib}))?;
        let api_end = started.elapsed();

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let body = self.api()?.memory_hotplug.get()?.json()?;
            if body.get("plugged_size_mib").and_then(|v| v.as_i64()) == Some(requested_size_mib) {
                return Ok((api_end, started.elapsed()));
            }
            std::thread::sleep(poll);
        }
        bail!("Hotplug did not complete within {timeout:?}");
    }

    /// Attaches the RSS monitor (python `Microvm(monitor_memory=True)`).
    ///
    /// Samples the Firecracker process RSS in the background and fails teardown
    /// through [`MicroVmMonitor::check`] if a threshold is exceeded.
    pub fn attach_memory_monitor(&mut self) -> Result<()> {
        let view: std::sync::Arc<dyn MemoryMonitoredVm> = std::sync::Arc::new(VmStatsView {
            pid: self.firecracker_pid,
            mem_size_bytes: Some(self.mem_size_bytes),
        });
        let monitor = std::sync::Arc::new(MemoryMonitor::with_defaults(view));
        monitor.start()?;
        self.memory_monitor = Some(std::sync::Arc::clone(&monitor));
        self.monitors.push(Box::new(MemoryMonitorAdapter(monitor)));
        Ok(())
    }

    /// Attaches the Firecracker metrics monitor (`spawn(emit_metrics=True)`).
    pub fn attach_fc_metrics_monitor(&mut self, timer: Duration) -> Result<()> {
        let api = self.api()?.clone();
        let metrics_file = self
            .metrics_file
            .clone()
            .ok_or_else(|| anyhow!("metrics file not configured"))?;
        let props = global_props();
        let dimensions = BTreeMap::from([
            ("instance".to_string(), props.instance.clone()),
            (
                "host_kernel".to_string(),
                format!("linux-{}", props.host_linux_version),
            ),
            (
                "guest_kernel".to_string(),
                self.guest_kernel
                    .as_ref()
                    .map(|kernel| kernel.metric_id())
                    .unwrap_or_default(),
            ),
        ]);
        let view: std::sync::Arc<dyn MetricsVm> = std::sync::Arc::new(ApiMetricsView {
            api,
            metrics_file,
            dimensions,
        });
        let monitor = std::sync::Arc::new(FCMetricsMonitor::new(view, timer));
        monitor.start()?;
        self.monitors
            .push(Box::new(FcMetricsMonitorAdapter(monitor)));
        Ok(())
    }

    /// Marks this microVM as killed, so teardown does not kill it again.
    pub fn mark_killed(&mut self, timeout: Duration) -> Result<()> {
        if let Some(pid) = self.firecracker_pid {
            utils::wait_process_termination(pid, timeout)?;
        }
        self.killed = true;
        Ok(())
    }

    /// All clean up associated with this microVM.
    pub fn kill(&mut self) {
        self.kill_with(true).ok();
    }

    /// Kills the microVM, optionally tolerating an already dead process.
    pub fn kill_with(&mut self, might_be_dead: bool) -> Result<()> {
        if self.killed {
            return Ok(());
        }

        for monitor in &mut self.monitors {
            monitor.stop();
        }

        for connection in &mut self.ssh_connections {
            let _ = connection.close(!might_be_dead);
        }
        self.ssh_connections.clear();

        // Stop vhost-user backends first: stopping Firecracker first races the
        // backend's own exit path.
        let mut backends = std::mem::take(&mut self.disks_vhost_user);
        for backend in backends.values_mut() {
            let _ = backend.kill();
        }

        let log_data = self.log_data();
        if log_data.contains("Shutting down VM after intercepting signal") && !might_be_dead {
            bail!("microVM shut down after intercepting a signal:\n{log_data}");
        }

        for pid in [self.firecracker_pid, self.screen_pid]
            .into_iter()
            .flatten()
        {
            // SAFETY: killing a pid we spawned; ESRCH is handled below.
            let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    continue;
                }
                if !might_be_dead {
                    self.dump_debug_information(&format!(
                        "Failed to kill Firecracker Process {pid}: {err}"
                    ));
                    return Err(err.into());
                }
                continue;
            }
            if let Err(err) = utils::wait_process_termination(pid, Duration::from_secs(10)) {
                utils::dump_proc_state(pid);
                return Err(err);
            }
        }

        if self.spawned {
            // Guard against a wrong PID: retry briefly while /proc settles.
            utils::retry_for(Duration::from_secs(1), Duration::from_millis(10), || {
                let stdout = utils::check_output("ps ax --no-headers -o pid,cmd -ww")?.stdout;
                let offenders: Vec<&str> = stdout
                    .lines()
                    .filter(|line| {
                        let lower = line.to_lowercase();
                        lower.contains(&self.jailer.jailer_id.to_lowercase())
                            && lower.contains("firecracker")
                    })
                    .collect();
                if offenders.is_empty() {
                    Ok(())
                } else {
                    bail!(
                        "processes still use the dead Firecracker's jailer_id:\n{}",
                        offenders.join("\n")
                    )
                }
            })?;
        }

        if let Some(handler) = &mut self.uffd_handler {
            if handler.is_running() {
                handler.kill();
            }
        }

        self.spawned = false;
        self.killed = true;

        if self.time_api_requests {
            self.validate_api_response_times()?;
        }
        for monitor in &mut self.monitors {
            monitor.check()?;
        }
        Ok(())
    }

    /// Asserts every API call logged by Firecracker stayed under
    /// [`defs::MAX_API_CALL_DURATION_MS`].
    pub fn validate_api_response_times(&self) -> Result<()> {
        let request_regex = regex::Regex::new(
            r#"] The API server received a (?P<method>\w+) request on "(?P<url>(/(\w|-)*)+)"( with body (?P<body>.*))?\."#,
        )
        .expect("static regex");
        let duration_regex =
            regex::Regex::new(r"] Total previous API call duration: (?P<execution_time>\d+) us.$")
                .expect("static regex");

        let log = self.log_data();
        let mut current: Option<(String, String, String)> = None;
        for line in log.split('\n') {
            if let Some(caps) = request_regex.captures(line) {
                if let Some((method, url, body)) = &current {
                    bail!(
                        "API call duration log entry for {method} {url} with body {body} is missing!"
                    );
                }
                current = Some((
                    caps.name("method")
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                    caps.name("url")
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                    caps.name("body")
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                ));
            }

            if let Some(caps) = duration_regex.captures(line) {
                let Some((method, url, body)) = current.take() else {
                    bail!("Got API call duration log entry before request entry");
                };
                if url != "/snapshot/create" && url != "/snapshot/load" {
                    let execution_us: f64 = caps["execution_time"].parse().unwrap_or(0.0);
                    let exec_time_ms = execution_us / 1000.0;
                    if exec_time_ms > defs::MAX_API_CALL_DURATION_MS as f64 {
                        bail!(
                            "{method} {url} API call exceeded maximum duration: {exec_time_ms} ms. Body: {body}"
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// Snapshot of the two values the RSS monitor needs.
///
/// Decouples [`MemoryMonitor`] from `MicroVm`'s mutable borrow: the monitor
/// keeps the pid and the guest memory size, exactly the numbers python's
/// `MemoryMonitor` reads off the live `Microvm` object.
#[derive(Debug, Clone, Copy)]
pub struct VmStatsView {
    pub pid: Option<i32>,
    pub mem_size_bytes: Option<u64>,
}

impl MemoryMonitoredVm for VmStatsView {
    fn firecracker_pid(&self) -> Option<i32> {
        self.pid
    }

    fn mem_size_bytes(&self) -> Option<u64> {
        self.mem_size_bytes
    }
}

/// Metrics-file and API view backing [`FCMetricsMonitor`].
#[derive(Debug)]
pub struct ApiMetricsView {
    api: Api,
    metrics_file: PathBuf,
    dimensions: BTreeMap<String, String>,
}

impl ApiMetricsView {
    /// Every JSON object written so far, skipping partially written lines.
    fn read_metrics(&self) -> Result<Vec<Value>> {
        let contents = std::fs::read_to_string(&self.metrics_file).unwrap_or_default();
        Ok(contents
            .lines()
            .filter(|line| line.ends_with('}'))
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect())
    }
}

impl MetricsVm for ApiMetricsView {
    fn all_metrics(&self) -> Result<Vec<Value>> {
        self.read_metrics()
    }

    fn flush_metrics(&self) -> Result<Value> {
        self.request_metrics_flush()?;
        self.read_metrics()?
            .pop()
            .ok_or_else(|| anyhow!("metrics file is empty after flush"))
    }

    fn request_metrics_flush(&self) -> Result<()> {
        self.api
            .actions
            .put(json!({"action_type": "FlushMetrics"}))?;
        Ok(())
    }

    fn metric_dimensions(&self) -> BTreeMap<String, String> {
        self.dimensions.clone()
    }
}

/// Adapter letting [`MemoryMonitor`] run as a [`MicroVmMonitor`].
struct MemoryMonitorAdapter(std::sync::Arc<MemoryMonitor>);

impl MicroVmMonitor for MemoryMonitorAdapter {
    fn stop(&mut self) {
        let _ = self.0.stop();
    }

    fn check(&mut self) -> Result<()> {
        self.0.check_samples()
    }
}

/// Adapter letting [`FCMetricsMonitor`] run as a [`MicroVmMonitor`].
struct FcMetricsMonitorAdapter(std::sync::Arc<FCMetricsMonitor>);

impl MicroVmMonitor for FcMetricsMonitorAdapter {
    fn stop(&mut self) {
        let _ = self.0.stop();
    }

    fn check(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Options for [`MicroVm::spawn`].
#[derive(Debug, Clone)]
pub struct SpawnConfig {
    pub log_file: Option<String>,
    pub serial_out_path: Option<String>,
    pub log_level: String,
    pub log_show_level: bool,
    pub log_show_origin: bool,
    pub metrics_path: Option<String>,
    pub emit_metrics: bool,
    pub validate_api: bool,
    pub expect_failure: bool,
}

impl Default for SpawnConfig {
    fn default() -> Self {
        Self {
            log_file: Some("fc.log".to_string()),
            serial_out_path: Some("serial.log".to_string()),
            log_level: "Debug".to_string(),
            log_show_level: false,
            log_show_origin: false,
            metrics_path: Some("fc.ndjson".to_string()),
            emit_metrics: false,
            validate_api: true,
            expect_failure: false,
        }
    }
}

/// Block device configuration for [`MicroVm::add_drive`].
#[derive(Debug, Clone)]
pub struct DriveConfig {
    pub drive_id: String,
    pub path_on_host: PathBuf,
    pub is_root_device: bool,
    pub is_read_only: bool,
    pub partuuid: Option<String>,
    pub cache_type: Option<String>,
    pub io_engine: Option<String>,
    pub topology: Option<Value>,
    pub blk_size: Option<Value>,
    pub discard: Option<String>,
}

impl DriveConfig {
    /// A rootfs drive with the harness defaults.
    pub fn rootfs(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let is_read_only = path
            .extension()
            .map(|ext| ext == "squashfs")
            .unwrap_or(false);
        Self {
            drive_id: "rootfs".to_string(),
            path_on_host: path,
            is_root_device: true,
            is_read_only,
            partuuid: None,
            cache_type: None,
            io_engine: None,
            topology: None,
            blk_size: None,
            discard: None,
        }
    }
}

/// vhost-user drive configuration for [`MicroVm::add_vhost_user_drive`].
pub struct VhostUserDriveConfig {
    pub drive_id: String,
    pub backend: Box<dyn VhostUserBlkBackend>,
    pub partuuid: Option<String>,
    pub is_root_device: bool,
    pub cache_type: Option<String>,
}

/// pmem device configuration for [`MicroVm::add_pmem`].
#[derive(Debug, Clone)]
pub struct PmemConfig {
    pub pmem_id: String,
    pub path_on_host: PathBuf,
    pub root_device: bool,
    pub read_only: bool,
}

/// Snapshot request configuration for [`MicroVm::make_snapshot`].
#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    pub snapshot_type: SnapshotType,
    pub mem_path: String,
    pub vmstate_path: String,
    pub sync_snapshot_files: Option<bool>,
}

impl SnapshotConfig {
    /// Defaults for the given snapshot type (`mem` / `vmstate` paths).
    pub fn new(snapshot_type: SnapshotType) -> Self {
        Self {
            snapshot_type,
            mem_path: "mem".to_string(),
            vmstate_path: "vmstate".to_string(),
            sync_snapshot_files: None,
        }
    }
}

fn touch(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("touching {}", path.display()))?;
    Ok(())
}

fn normalize_log_level(level: &str) -> String {
    let mut chars = level.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase(),
        None => "Debug".to_string(),
    }
}

/// MicroVM factory, mirroring `MicroVMFactory`.
#[derive(Debug)]
pub struct MicroVmFactory {
    pub binary_path: PathBuf,
    pub backend: VmBackend,
    pub vms: Vec<MicroVm>,
    netns_prefix: String,
}

impl MicroVmFactory {
    /// Creates a factory that builds VMs from `binary_path`.
    pub fn new(binary_path: impl Into<PathBuf>, backend: VmBackend) -> Result<Self> {
        let binary_path = binary_path.into();
        let factory = Self {
            binary_path,
            backend,
            vms: Vec::new(),
            netns_prefix: "fc".to_string(),
        };
        if !factory.fc_binary_path().exists() {
            bail!(
                "missing firecracker binary at {}",
                factory.fc_binary_path().display()
            );
        }
        if !factory.jailer_binary_path().exists() {
            bail!(
                "missing jailer binary at {}",
                factory.jailer_binary_path().display()
            );
        }
        Ok(factory)
    }

    /// Path to the firecracker binary.
    pub fn fc_binary_path(&self) -> PathBuf {
        self.binary_path.join(defs::FC_BINARY_NAME)
    }

    /// Path to the jailer binary.
    pub fn jailer_binary_path(&self) -> PathBuf {
        self.binary_path.join("jailer")
    }

    /// Builds a microVM, optionally attaching a kernel and rootfs.
    pub fn build(
        &mut self,
        kernel: Option<GuestKernel>,
        rootfs: Option<PathBuf>,
        microvm_id: Option<String>,
    ) -> Result<&mut MicroVm> {
        let microvm_id = microvm_id
            .unwrap_or_else(|| format!("{}-{}", self.netns_prefix, utils::random_str(12)));
        let netns = NetNs::new(microvm_id.clone());
        let mut vm = MicroVm::new(
            microvm_id.clone(),
            self.fc_binary_path(),
            self.jailer_binary_path(),
            netns,
            self.backend,
        )?;
        vm.netns.setup()?;

        if let Some(kernel) = kernel {
            // Resolve eagerly so an impossible kernel/backend combination
            // surfaces at build time.
            let _ = self.backend.kernel_image_for(&kernel);
            vm.guest_kernel = Some(kernel);
        }

        if let Some(rootfs) = rootfs {
            let ssh_key = rootfs.with_extension("id_rsa");
            let rootfs_path = if rootfs.extension().map(|e| e == "squashfs").unwrap_or(false) {
                rootfs.clone()
            } else {
                let dst = vm.path().join(
                    rootfs
                        .file_name()
                        .ok_or_else(|| anyhow!("rootfs has no file name"))?,
                );
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::copy(&rootfs, &dst).with_context(|| {
                    format!("copying rootfs {} -> {}", rootfs.display(), dst.display())
                })?;
                dst
            };
            vm.distro = GuestDistro::from_rootfs(&rootfs_path);
            vm.rootfs_file = Some(rootfs_path);
            vm.ssh_key = Some(ssh_key);
        }

        self.vms.push(vm);
        Ok(self.vms.last_mut().expect("just pushed"))
    }

    /// Builds, spawns, restores and resumes a microVM from a snapshot.
    pub fn build_from_snapshot(
        &mut self,
        snapshot: &Snapshot,
        options: RestoreOptions,
    ) -> Result<&mut MicroVm> {
        let vm = self.build(None, None, None)?;
        vm.spawn(SpawnConfig::default())?;
        let mut options = options;
        options.resume = true;
        vm.restore_from_snapshot(snapshot, options)?;
        Ok(vm)
    }

    /// Builds, spawns, configures, starts a microVM and waits for SSH.
    pub fn build_booted(
        &mut self,
        kernel: Option<GuestKernel>,
        rootfs: Option<PathBuf>,
        pci: bool,
        config: kvm::KvmBasicConfig,
    ) -> Result<&mut MicroVm> {
        let vm = self.build(kernel, rootfs, None)?;
        vm.set_pci(pci);
        vm.spawn(SpawnConfig::default())?;
        vm.basic_config(config)?;
        vm.add_net_iface(None, true)?;
        vm.start()?;
        Ok(vm)
    }

    /// Builds a booted microVM, snapshots it, kills it and restores a copy.
    pub fn build_restored(
        &mut self,
        kernel: Option<GuestKernel>,
        rootfs: Option<PathBuf>,
        pci: bool,
        config: kvm::KvmBasicConfig,
    ) -> Result<&mut MicroVm> {
        let booted = self.build_booted(kernel, rootfs, pci, config)?;
        let cpu_template_name = booted.cpu_template_name.clone();
        let snapshot = booted.snapshot_full()?;
        booted.kill_with(true)?;
        let restored = self.build_from_snapshot(&snapshot, RestoreOptions::default())?;
        restored.cpu_template_name = cpu_template_name;
        Ok(self.vms.last_mut().expect("restored vm exists"))
    }

    /// Kills and cleans up every microVM built by this factory.
    pub fn kill(&mut self) {
        for vm in &mut self.vms {
            vm.kill();
            let _ = vm.jailer.cleanup();
            let chroot = vm.jailer.chroot_base_with_id();
            if !vm.jailer.jailer_id.is_empty() && chroot.exists() {
                let _ = std::fs::remove_dir_all(&chroot);
            }
            let _ = vm.netns.cleanup();
        }
        self.vms.clear();
    }
}

impl Drop for MicroVmFactory {
    fn drop(&mut self) {
        // Best effort: never leak jails or netns on panic.
        if !self.vms.is_empty() {
            self.kill();
        }
    }
}

/// Serial console communication with a microVM.
pub struct Serial<'a> {
    vm: &'a MicroVm,
    file: Option<std::fs::File>,
    rx_timeout: Duration,
}

impl<'a> Serial<'a> {
    /// Creates a serial console handle; call [`Serial::open`] before use.
    pub fn new(vm: &'a MicroVm) -> Self {
        Self {
            vm,
            file: None,
            rx_timeout: Duration::from_secs(60),
        }
    }

    /// Opens the screen log file for reading.
    pub fn open(&mut self) -> Result<()> {
        if self.file.is_some() {
            return Ok(());
        }
        let log = self.vm.screen_log();
        utils::retry_attempts(5, Duration::from_millis(200), || {
            if log.exists() {
                Ok(())
            } else {
                bail!("screen log {} not created yet", log.display())
            }
        })?;
        self.file = Some(std::fs::File::open(&log)?);
        Ok(())
    }

    /// Sends a string terminated by `end` (default `"\n"`).
    pub fn tx(&self, input_string: &str, end: &str) -> Result<()> {
        self.vm.serial_input(&format!("{input_string}{end}"))?;
        Ok(())
    }

    /// Reads a single character, returning `""` on timeout.
    pub fn rx_char(&mut self) -> Result<String> {
        let Some(file) = &mut self.file else {
            bail!("serial not opened");
        };
        use std::os::unix::io::AsRawFd;
        let mut pollfd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pollfd` is a valid, initialised pollfd array of length 1.
        let rc = unsafe { libc::poll(&mut pollfd, 1, 100) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("polling serial log");
        }
        if rc == 0 {
            return Ok(String::new());
        }
        if pollfd.revents & libc::POLLHUP != 0 {
            bail!("The console vanished before test completed.");
        }
        let mut buf = [0u8; 1];
        let read = file.read(&mut buf)?;
        if read == 0 {
            return Ok(String::new());
        }
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    /// Reads a string delimited by `token` (default `"\n"`).
    pub fn rx(&mut self, token: &str) -> Result<String> {
        let started = Instant::now();
        let mut out = String::new();
        loop {
            out.push_str(&self.rx_char()?);
            if out.ends_with(token) {
                return Ok(out);
            }
            if started.elapsed() >= self.rx_timeout {
                bail!("serial read timed out after {:?}", self.rx_timeout);
            }
        }
    }

    /// Reads and discards output until the console is idle.
    pub fn drain_until_idle(&mut self, idle: Duration) -> Result<()> {
        let started = Instant::now();
        let mut last_activity = Instant::now();
        loop {
            let now = Instant::now();
            if now - started >= self.rx_timeout {
                return Ok(());
            }
            if !self.rx_char()?.is_empty() {
                last_activity = now;
            } else if now - last_activity >= idle {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_is_capitalised() {
        assert_eq!(normalize_log_level("debug"), "Debug");
        assert_eq!(normalize_log_level("ERROR"), "Error");
        assert_eq!(normalize_log_level(""), "Debug");
    }

    #[test]
    fn snapshot_config_defaults() {
        let config = SnapshotConfig::new(SnapshotType::Diff);
        assert_eq!(config.mem_path, "mem");
        assert_eq!(config.vmstate_path, "vmstate");
        assert!(config.sync_snapshot_files.is_none());
    }

    #[test]
    fn rootfs_drive_detects_squashfs() {
        let drive = DriveConfig::rootfs("/artifacts/rootfs.squashfs");
        assert!(drive.is_read_only);
        assert!(drive.is_root_device);
        let drive = DriveConfig::rootfs("/artifacts/rootfs.ext4");
        assert!(!drive.is_read_only);
    }

    #[test]
    fn api_timing_validation_accepts_short_calls() {
        let dir = std::env::temp_dir().join(format!("fc-api-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("fc.log");
        std::fs::write(
            &log_path,
            "\n".to_string()
                + r#"] The API server received a Put request on "/boot-source" with body "{}"."#
                + "\n] Total previous API call duration: 100 us.\n",
        )
        .unwrap();

        let mut vm = fake_vm();
        vm.log_file = Some(log_path);
        vm.validate_api_response_times().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn api_timing_validation_rejects_slow_calls() {
        let dir = std::env::temp_dir().join(format!("fc-api-slow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("fc.log");
        std::fs::write(
            &log_path,
            r#"] The API server received a Put request on "/boot-source" with body "{}"."#
                .to_string()
                + "\n] Total previous API call duration: 800000 us.\n",
        )
        .unwrap();

        let mut vm = fake_vm();
        vm.log_file = Some(log_path);
        let err = vm.validate_api_response_times().unwrap_err().to_string();
        assert!(err.contains("exceeded maximum duration"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn snapshot_endpoints_are_exempt_from_timing() {
        let dir = std::env::temp_dir().join(format!("fc-api-snap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("fc.log");
        std::fs::write(
            &log_path,
            r#"] The API server received a Put request on "/snapshot/create" with body "{}"."#
                .to_string()
                + "\n] Total previous API call duration: 999999 us.\n",
        )
        .unwrap();
        let mut vm = fake_vm();
        vm.log_file = Some(log_path);
        vm.validate_api_response_times().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    fn fake_vm() -> MicroVm {
        MicroVm {
            microvm_id: "test".into(),
            fc_binary_path: PathBuf::from("/bin/true"),
            jailer_binary_path: PathBuf::from("/bin/true"),
            backend: VmBackend::Kvm,
            jailer: JailerContext::new("test", "/bin/true"),
            netns: NetNs::new("test"),
            pci_enabled: false,
            guest_kernel: None,
            boot_image: None,
            rootfs_file: None,
            distro: None,
            ssh_key: None,
            initrd_file: None,
            boot_args: None,
            api: None,
            log_file: None,
            serial_out_path: None,
            metrics_file: None,
            spawned: false,
            killed: false,
            iface: Vec::new(),
            disks: BTreeMap::new(),
            disks_vhost_user: BTreeMap::new(),
            huge_pages: HugePagesConfig::None,
            vcpus_count: 2,
            mem_size_bytes: 256 << 20,
            cpu_template_name: "None".into(),
            custom_cpu_template: None,
            pre_cmd: Vec::new(),
            metadata_file: None,
            screen_pid: None,
            time_api_requests: true,
            firecracker_pid: None,
            ssh_connections: Vec::new(),
            monitors: Vec::new(),
            memory_monitor: None,
            uffd_handler: None,
            gdb_socket: None,
            helpers: MicrovmHelpers::default(),
        }
    }
}
