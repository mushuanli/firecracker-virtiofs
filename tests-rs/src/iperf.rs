// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! iperf3 based throughput test helpers, ported from
//! `tests/framework/utils_iperf.py`.
//!
//! Mapping from python: `IPerf3Test(microvm, ...)` becomes
//! [`IPerf3Test`], which takes the pieces it reads off the microVM explicitly
//! (the SSH connection, the optional netns, the Firecracker pid and the vCPU
//! count) so it does not depend on the microVM ownership model. The command
//! builders live on [`IPerf3Config`] so they can be unit tested without a guest.
//!
//! `emit_iperf3_metrics(metrics, data, omit)` becomes
//! [`emit_iperf3_metrics`], which returns the `(name, value, unit)` tuples the
//! caller feeds into its metrics sink instead of writing to a `metrics` object.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::network::{NetNs, SshConnection};
use crate::utils::{check_output, cpu_map, host_cpus, track_cpu_utilization, CmdBuilder};

/// Default iperf3 binary name on the host and in the guest.
pub const DEFAULT_IPERF: &str = "iperf3";

/// Sentinel meaning "do not pass `--len`" (`payload_length="DEFAULT"`).
pub const DEFAULT_PAYLOAD_LENGTH: &str = "DEFAULT";

/// Upper bound added to the requested runtime when waiting for an iperf3 run.
pub const IPERF_TIMEOUT_MARGIN: Duration = Duration::from_secs(60);

/// Time the iperf3 servers get to start before the clients are launched.
pub const SERVER_STARTUP_DELAY: Duration = Duration::from_secs(2);

/// `--len` value passed to the guest iperf3 client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadLength {
    /// Do not pass `--len` at all (`payload_length="DEFAULT"`).
    Default,
    /// Explicit payload length, e.g. `128K`.
    Custom(String),
}

impl PayloadLength {
    /// The `--len` argument, or `None` when the default payload is used.
    pub fn as_arg(&self) -> Option<&str> {
        match self {
            PayloadLength::Default => None,
            PayloadLength::Custom(value) => Some(value),
        }
    }
}

impl Default for PayloadLength {
    fn default() -> Self {
        PayloadLength::Default
    }
}

impl From<&str> for PayloadLength {
    fn from(value: &str) -> Self {
        if value == DEFAULT_PAYLOAD_LENGTH {
            PayloadLength::Default
        } else {
            PayloadLength::Custom(value.to_string())
        }
    }
}

/// Direction of the measured flow (the python `mode` dictionary key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPerfMode {
    /// Guest to host traffic (`mode="g2h"`).
    GuestToHost,
    /// Host to guest traffic (`mode="h2g"`, iperf3 runs with `-R`).
    HostToGuest,
}

impl IPerfMode {
    /// The key used in the python result dictionary.
    pub const fn as_key(self) -> &'static str {
        match self {
            IPerfMode::GuestToHost => "g2h",
            IPerfMode::HostToGuest => "h2g",
        }
    }

    /// The iperf3 client flag selecting this direction (`-R` for `h2g`).
    pub const fn client_flag(self) -> &'static str {
        match self {
            IPerfMode::GuestToHost => "",
            IPerfMode::HostToGuest => "-R",
        }
    }
}

impl fmt::Display for IPerfMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_key())
    }
}

impl FromStr for IPerfMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "g2h" => Ok(IPerfMode::GuestToHost),
            "h2g" => Ok(IPerfMode::HostToGuest),
            other => Err(anyhow!("unknown iperf mode {other}")),
        }
    }
}

/// Configuration of one iperf3 throughput test (python `IPerf3Test.__init__`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPerf3Config {
    /// First TCP port used; client `i` uses `base_port + i`.
    pub base_port: u16,
    /// Measured runtime in seconds (`--time` / server lifetime is 1 run).
    pub runtime: u64,
    /// Warm-up seconds omitted from the metrics (`--omit`).
    pub omit: u64,
    /// Direction of the measured flow.
    pub mode: IPerfMode,
    /// Number of concurrent client/server pairs.
    pub num_clients: usize,
    /// The `--client` value handed to the guest iperf3.
    pub connect_to: String,
    /// Host iperf3 binary.
    pub iperf: String,
    /// Guest iperf3 binary.
    pub guest_iperf: String,
    /// `--len` value for the guest client.
    pub payload_length: PayloadLength,
}

impl IPerf3Config {
    /// Builds a configuration with the default binaries and payload length.
    pub fn new(
        base_port: u16,
        runtime: u64,
        omit: u64,
        mode: IPerfMode,
        num_clients: usize,
        connect_to: impl Into<String>,
    ) -> Self {
        Self {
            base_port,
            runtime,
            omit,
            mode,
            num_clients,
            connect_to: connect_to.into(),
            iperf: DEFAULT_IPERF.to_string(),
            guest_iperf: DEFAULT_IPERF.to_string(),
            payload_length: PayloadLength::Default,
        }
    }

    /// Command spawning the iperf3 server for `port_offset` on the host.
    pub fn host_command(&self, port_offset: usize) -> CmdBuilder {
        CmdBuilder::new(&self.iperf)
            .with_arg("-sD", "")
            .with_arg(
                "-p",
                (u32::from(self.base_port) + port_offset as u32).to_string(),
            )
            .with_arg("-1", "")
    }

    /// Command spawning the iperf3 client for `port_offset` inside the guest.
    pub fn guest_command(&self, port_offset: usize) -> CmdBuilder {
        let cmd = CmdBuilder::new(&self.guest_iperf)
            .with_arg("--time", self.runtime.to_string())
            .with_arg("--json", "")
            .with_arg("--omit", self.omit.to_string())
            .with_arg(
                "-p",
                (u32::from(self.base_port) + port_offset as u32).to_string(),
            )
            .with_arg("--client", self.connect_to.clone());

        match self.payload_length.as_arg() {
            Some(payload_length) => cmd.with_arg("--len", payload_length),
            None => cmd,
        }
    }

    /// Full guest client command for `client_idx`, pinned to `client_idx % vcpus`.
    pub fn client_command(&self, client_idx: usize, vcpus_count: usize) -> String {
        let affinity = if vcpus_count == 0 {
            0
        } else {
            client_idx % vcpus_count
        };
        self.guest_command(client_idx)
            .with_arg(self.mode.client_flag(), "")
            .with_arg("--affinity", affinity.to_string())
            .build()
    }
}

/// Results of one [`IPerf3Test::run_test`] run (python result dictionary).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IPerf3Result {
    /// CPU utilization samples per Firecracker thread name.
    pub cpu_load_raw: BTreeMap<String, Vec<f64>>,
    /// Guest to host iperf3 JSON documents, one per client.
    pub g2h: Vec<serde_json::Value>,
    /// Host to guest iperf3 JSON documents, one per client.
    pub h2g: Vec<serde_json::Value>,
}

/// One metric emitted by [`emit_iperf3_metrics`] (`metrics.put_metric`).
#[derive(Debug, Clone, PartialEq)]
pub struct Metric {
    /// Metric name, e.g. `throughput_guest_to_host`.
    pub name: String,
    /// Metric value.
    pub value: f64,
    /// CloudWatch-style unit, e.g. `Bits/Second`.
    pub unit: &'static str,
}

impl Metric {
    /// Creates a metric tuple.
    pub fn new(name: impl Into<String>, value: f64, unit: &'static str) -> Self {
        Self {
            name: name.into(),
            value,
            unit,
        }
    }
}

/// An iperf3 throughput test bound to a guest.
///
/// Python reads `microvm.netns`, `microvm.ssh`, `microvm.firecracker_pid` and
/// `microvm.vcpus_count` inside the class; the port takes those four values
/// explicitly, so a caller builds the test from the microVM accessors it has
/// (`IPerf3Test::new(ssh, vcpus_count, config)`, then `.with_netns(..)` and
/// `.with_firecracker_pid(..)`).
#[derive(Debug)]
pub struct IPerf3Test<'a> {
    ssh: &'a SshConnection,
    netns: Option<&'a NetNs>,
    firecracker_pid: Option<i32>,
    vcpus_count: usize,
    config: IPerf3Config,
}

impl<'a> IPerf3Test<'a> {
    /// Binds the configuration to a guest SSH connection and vCPU count.
    pub fn new(ssh: &'a SshConnection, vcpus_count: usize, config: IPerf3Config) -> Self {
        Self {
            ssh,
            netns: None,
            firecracker_pid: None,
            vcpus_count,
            config,
        }
    }

    /// Sets the netns the host-side servers are spawned in.
    pub fn with_netns(mut self, netns: &'a NetNs) -> Self {
        self.netns = Some(netns);
        self
    }

    /// Sets the Firecracker pid used for CPU utilization tracking.
    pub fn with_firecracker_pid(mut self, pid: i32) -> Self {
        self.firecracker_pid = Some(pid);
        self
    }

    /// The test configuration.
    pub fn config(&self) -> &IPerf3Config {
        &self.config
    }

    /// iperf3 flag for the configured direction (`-R` for host to guest).
    pub fn client_mode_to_iperf3_flag(&self) -> &'static str {
        self.config.mode.client_flag()
    }

    /// Command spawning the iperf3 server for `port_offset` on the host.
    pub fn host_command(&self, port_offset: usize) -> CmdBuilder {
        self.config.host_command(port_offset)
    }

    /// Command spawning the iperf3 client for `port_offset` inside the guest.
    pub fn guest_command(&self, port_offset: usize) -> CmdBuilder {
        self.config.guest_command(port_offset)
    }

    /// Runs a client inside the guest and returns its raw JSON stdout.
    pub fn spawn_iperf3_client(&self, client_idx: usize, client_mode_flag: &str) -> Result<String> {
        let affinity = if self.vcpus_count == 0 {
            0
        } else {
            client_idx % self.vcpus_count
        };
        let cmd = self
            .config
            .guest_command(client_idx)
            .with_arg(client_mode_flag, "")
            .with_arg("--affinity", affinity.to_string())
            .build();
        let timeout =
            Duration::from_secs(self.config.runtime + self.config.omit) + IPERF_TIMEOUT_MARGIN;
        Ok(self.ssh.check_output(&cmd, timeout)?.stdout)
    }

    /// Runs the whole test: servers on the host, clients in the guest, CPU tracking.
    ///
    /// Returns the aggregated result, mirroring the python dictionary with the
    /// `cpu_load_raw`, `g2h` and `h2g` keys.
    pub fn run_test(&self, mut first_free_cpu: usize) -> Result<IPerf3Result> {
        if first_free_cpu + self.config.num_clients > host_cpus().len() {
            bail!(
                "not enough host CPUs: requested {} starting at {}, host has {}",
                self.config.num_clients,
                first_free_cpu,
                host_cpus().len()
            );
        }
        if self.config.runtime < 3 {
            bail!("iperf runtime must be at least 3 seconds to sample CPU load");
        }

        for server_idx in 0..self.config.num_clients {
            let assigned_cpu = cpu_map(first_free_cpu)?;
            let cmd = self
                .host_command(server_idx)
                .with_arg("--affinity", assigned_cpu.to_string())
                .build();
            let cmd = match self.netns {
                Some(netns) => format!("{} {cmd}", netns.cmd_prefix()),
                None => cmd,
            };
            check_output(&cmd)?;
            first_free_cpu += 1;
        }

        // Wait for the iperf3 servers to start.
        thread::sleep(SERVER_STARTUP_DELAY);

        let pid = self
            .firecracker_pid
            .ok_or_else(|| anyhow!("firecracker pid is required to track CPU utilization"))?;
        // Ignore the final two data points as they are impacted by test teardown.
        let iterations = usize::try_from(self.config.runtime - 2)
            .context("iperf runtime does not fit in usize")?;
        let omit = Duration::from_secs(self.config.omit);
        let cpu_handle = thread::spawn(move || track_cpu_utilization(pid, iterations, omit));

        let flag = self.client_mode_to_iperf3_flag();
        let client_outputs: Result<Vec<String>> = thread::scope(|scope| {
            let handles = (0..self.config.num_clients)
                .map(|client_idx| scope.spawn(move || self.spawn_iperf3_client(client_idx, flag)))
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| match handle.join() {
                    Ok(result) => result,
                    Err(_) => Err(anyhow!("iperf3 client thread panicked")),
                })
                .collect()
        });
        let client_outputs = client_outputs?;

        let cpu_load_raw = cpu_handle
            .join()
            .map_err(|_| anyhow!("cpu utilization tracker thread panicked"))?;

        let mut result = IPerf3Result {
            cpu_load_raw,
            g2h: Vec::new(),
            h2g: Vec::new(),
        };
        for output in client_outputs {
            let document = parse_client_output(&output)?;
            match self.config.mode {
                IPerfMode::GuestToHost => result.g2h.push(document),
                IPerfMode::HostToGuest => result.h2g.push(document),
            }
        }

        Ok(result)
    }
}

/// Parses one iperf3 `--json` document (python `json.loads`).
pub fn parse_client_output(stdout: &str) -> Result<serde_json::Value> {
    serde_json::from_str(stdout).context("parsing iperf3 JSON output")
}

/// Converts a run into metrics (python `emit_iperf3_metrics`).
///
/// CPU utilization is emitted first, then one throughput metric per sampled
/// point in time for `g2h` and `h2g`. Per-point throughput is the sum over all
/// clients, and intervals are zip-truncated to the shortest series, exactly like
/// the python implementation.
pub fn emit_iperf3_metrics(result: &IPerf3Result, omit: usize) -> Result<Vec<Metric>> {
    let mut metrics = Vec::new();

    for (thread_name, values) in &result.cpu_load_raw {
        for value in values {
            metrics.push(Metric::new(
                format!("cpu_utilization_{thread_name}"),
                *value,
                "Percent",
            ));
        }
    }

    for (name, series) in [
        ("throughput_guest_to_host", &result.g2h),
        ("throughput_host_to_guest", &result.h2g),
    ] {
        for throughput in aggregate_throughput(series, omit)? {
            metrics.push(Metric::new(name, throughput, "Bits/Second"));
        }
    }

    Ok(metrics)
}

/// Sums `intervals[omit..].sum.bits_per_second` over every series, point by point.
fn aggregate_throughput(series: &[serde_json::Value], omit: usize) -> Result<Vec<f64>> {
    let intervals = series
        .iter()
        .map(|document| {
            document
                .get("intervals")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| anyhow!("iperf3 output has no `intervals` array"))
        })
        .collect::<Result<Vec<_>>>()?;

    let samples = intervals
        .iter()
        .map(|entries| entries.len().saturating_sub(omit))
        .min()
        .unwrap_or(0);

    let mut totals = Vec::with_capacity(samples);
    for sample in 0..samples {
        let mut total = 0.0;
        for entries in &intervals {
            let bits_per_second = entries
                .get(sample + omit)
                .and_then(|interval| interval.get("sum"))
                .and_then(|sum| sum.get("bits_per_second"))
                .and_then(serde_json::Value::as_f64)
                .ok_or_else(|| anyhow!("iperf3 interval is missing `sum.bits_per_second`"))?;
            total += bits_per_second;
        }
        totals.push(total);
    }

    Ok(totals)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> IPerf3Config {
        IPerf3Config::new(5000, 20, 5, IPerfMode::GuestToHost, 2, "192.168.0.1")
    }

    #[test]
    fn host_command_matches_python_output() {
        assert_eq!(config().host_command(1).build(), "iperf3 -sD  -p 5001 -1  ");
    }

    #[test]
    fn guest_command_matches_python_output() {
        assert_eq!(
            config().guest_command(0).build(),
            "iperf3 --time 20 --json  --omit 5 -p 5000 --client 192.168.0.1 "
        );
    }

    #[test]
    fn guest_command_includes_payload_length_when_not_default() {
        let mut config = config();
        assert!(!config.guest_command(0).build().contains("--len"));
        config.payload_length = PayloadLength::from("128K");
        assert!(config.guest_command(0).build().contains("--len 128K"));
        assert_eq!(PayloadLength::from("DEFAULT"), PayloadLength::Default);
        assert_eq!(PayloadLength::default(), PayloadLength::Default);
    }

    #[test]
    fn client_mode_maps_to_iperf3_flag() {
        assert_eq!(IPerfMode::GuestToHost.client_flag(), "");
        assert_eq!(IPerfMode::HostToGuest.client_flag(), "-R");
        assert_eq!(IPerfMode::GuestToHost.as_key(), "g2h");
        assert_eq!(IPerfMode::HostToGuest.as_key(), "h2g");
        assert_eq!(
            "h2g".parse::<IPerfMode>().expect("known mode"),
            IPerfMode::HostToGuest
        );
        assert!("sideways".parse::<IPerfMode>().is_err());
    }

    #[test]
    fn client_command_appends_flag_and_affinity() {
        let mut config = config();
        config.mode = IPerfMode::HostToGuest;
        assert_eq!(
            config.client_command(3, 2),
            "iperf3 --time 20 --json  --omit 5 -p 5003 --client 192.168.0.1 -R  --affinity 1 "
        );
        // A zero vCPU count must not divide by zero, it falls back to cpu 0.
        assert!(config.client_command(1, 0).ends_with("--affinity 0 "));
        config.mode = IPerfMode::GuestToHost;
        assert!(!config.client_command(0, 1).contains(" -R "));
    }

    fn interval(bits_per_second: u64) -> serde_json::Value {
        serde_json::json!({
            "sum": {"bits_per_second": bits_per_second},
            "streams": [],
        })
    }

    #[test]
    fn metrics_sum_throughput_per_point_in_time() {
        let result = IPerf3Result {
            cpu_load_raw: BTreeMap::from([("fc_vcpu 0".to_string(), vec![10.0, 20.0])]),
            g2h: vec![
                serde_json::json!({"intervals": [
                    interval(1), interval(2), interval(3), interval(4)
                ]}),
                serde_json::json!({"intervals": [
                    interval(10), interval(20), interval(30), interval(40)
                ]}),
            ],
            h2g: vec![serde_json::json!({"intervals": [
                interval(100), interval(200), interval(300), interval(400)
            ]})],
        };

        let metrics = emit_iperf3_metrics(&result, 2).expect("metrics");
        let rendered = metrics
            .iter()
            .map(|metric| (metric.name.as_str(), metric.value, metric.unit))
            .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            vec![
                ("cpu_utilization_fc_vcpu 0", 10.0, "Percent"),
                ("cpu_utilization_fc_vcpu 0", 20.0, "Percent"),
                ("throughput_guest_to_host", 33.0, "Bits/Second"),
                ("throughput_guest_to_host", 44.0, "Bits/Second"),
                ("throughput_host_to_guest", 300.0, "Bits/Second"),
                ("throughput_host_to_guest", 400.0, "Bits/Second"),
            ]
        );
    }

    #[test]
    fn metrics_zip_truncate_to_shortest_series() {
        let result = IPerf3Result {
            cpu_load_raw: BTreeMap::new(),
            g2h: vec![
                serde_json::json!({"intervals": [interval(1), interval(2), interval(3)]}),
                serde_json::json!({"intervals": [interval(10)]}),
            ],
            h2g: Vec::new(),
        };
        let metrics = emit_iperf3_metrics(&result, 0).expect("metrics");
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].value, 11.0);
    }

    #[test]
    fn metrics_reject_malformed_documents() {
        let result = IPerf3Result {
            cpu_load_raw: BTreeMap::new(),
            g2h: vec![serde_json::json!({"intervals": [{"sum": {}}]})],
            h2g: Vec::new(),
        };
        assert!(emit_iperf3_metrics(&result, 0).is_err());

        let result = IPerf3Result {
            cpu_load_raw: BTreeMap::new(),
            g2h: vec![serde_json::json!({"no_intervals": []})],
            h2g: Vec::new(),
        };
        assert!(emit_iperf3_metrics(&result, 0).is_err());
    }

    #[test]
    fn parses_client_output() {
        let document = parse_client_output(r#"{"end": {"sum_sent": {"bits_per_second": 1}}}"#)
            .expect("valid json");
        assert_eq!(document["end"]["sum_sent"]["bits_per_second"], 1);
        assert!(parse_client_output("not json").is_err());
    }
}
