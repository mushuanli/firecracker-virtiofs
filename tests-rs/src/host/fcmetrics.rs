// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Firecracker metrics validation and export, ported from `tests/host_tools/fcmetrics.py`.
//!
//! python validates with `jsonschema`; this port keeps the same schema construction
//! (`create_metrics_schema_objects`) but validates with a small in-tree checker, so no new
//! dependency is needed. CloudWatch EMF export goes through [`MetricsWrapper`], whose transport is
//! a no-op in this crate.
//!
//! `FCMetricsMonitor` is a **background monitor**: python subclasses `threading.Thread` and
//! registers itself in `vm.monitors`; this port owns a `std::thread`, an `Arc<AtomicBool>` stop
//! flag and a `JoinHandle`, and leaves registration to the caller.
//!
//! `jsonschema.assert` style checks become `anyhow::Result` errors, the `validate_missing_metrics`
//! regression pass is kept, and the metric discovery helpers walk the tree in-process
//! (`git -C <workspace_dir> ls-files` plus `walkdir`) instead of shelling out to `grep`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde_json::{json, Map, Value};
use walkdir::WalkDir;

use crate::defs;
use crate::host::metrics::MetricsWrapper;
use crate::utils;

/// Key carrying the UTC timestamp of a Firecracker metrics datapoint.
pub const UTC_TIMESTAMP_MS: &str = "utc_timestamp_ms";

/// Largest accepted distance between the reported timestamp and the current time, in ms.
pub const MAX_TIMESTAMP_SKEW_MS: i64 = 1000;

/// Failure counters that are triggered spuriously and therefore tolerated.
pub const IGNORED_FAILURE_METRICS: [&str; 3] = [
    // Triggered spuriously in vsock tests: iperf-vsock does not implement connection shutdown.
    "fc_metrics.vsock.rx_read_fails",
    "fc_metrics.vsock.tx_write_fails",
    "fc_metrics.vsock.tx_flush_fails",
];

/// Fields that are legitimately unused in production code.
pub const KNOWN_FALSE_POSITIVES: [&str; 5] = [
    "min_us",
    "max_us",
    "sum_us",
    "process_startup_time_us",
    "process_startup_time_cpu_us",
];

/// Metrics exported by a vhost-user device (`vhost_user_*`).
pub const VHOST_USER_METRICS: [&str; 5] = [
    "activate_fails",
    "cfg_fails",
    "init_time_us",
    "activate_time_us",
    "config_change_time_us",
];

/// What the Firecracker metrics monitor needs from a microVM.
pub trait MetricsVm: Send + Sync {
    /// Every metrics datapoint written so far, oldest first (python `get_all_metrics`).
    fn all_metrics(&self) -> Result<Vec<Value>>;
    /// Asks Firecracker to flush its metrics and returns the newest datapoint.
    fn flush_metrics(&self) -> Result<Value>;
    /// Sends `PUT /actions {"action_type": "FlushMetrics"}`.
    fn request_metrics_flush(&self) -> Result<()>;
    /// CloudWatch dimensions `instance`, `host_kernel` and `guest_kernel`.
    fn metric_dimensions(&self) -> BTreeMap<String, String>;
}

/// Returns the current UTC timestamp in milliseconds since the Unix epoch.
pub fn current_utc_timestamp_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_millis() as i64,
        Err(_) => 0,
    }
}

/// Returns the `LatencyAggregateMetrics` field list.
pub fn latency_agg_metrics_fields() -> Value {
    json!(["min_us", "max_us", "sum_us"])
}

/// Returns the block device metric fields (with their aggregate groups).
pub fn block_metrics() -> Value {
    json!([
        "activate_fails",
        "cfg_fails",
        "no_avail_buffer",
        "event_fails",
        "execute_fails",
        "invalid_reqs_count",
        "flush_count",
        "queue_event_count",
        "rate_limiter_event_count",
        "update_count",
        "update_fails",
        "read_bytes",
        "write_bytes",
        "read_count",
        "write_count",
        "rate_limiter_throttled_events",
        "io_engine_throttled_events",
        "remaining_reqs_count",
        { "read_agg": latency_agg_metrics_fields() },
        { "write_agg": latency_agg_metrics_fields() },
    ])
}

/// Returns the net device metric fields (with the tap write aggregate group).
pub fn net_metrics() -> Value {
    json!([
        "activate_fails",
        "cfg_fails",
        "no_rx_avail_buffer",
        "no_tx_avail_buffer",
        "event_fails",
        "rx_queue_event_count",
        "rx_event_rate_limiter_count",
        "rx_rate_limiter_throttled",
        "rx_tap_event_count",
        "rx_bytes_count",
        "rx_packets_count",
        "rx_fails",
        "rx_count",
        "tap_read_fails",
        "tap_write_fails",
        "tx_bytes_count",
        "tx_malformed_frames",
        "tx_fails",
        "tx_count",
        "tx_packets_count",
        "tx_queue_event_count",
        "tx_rate_limiter_event_count",
        "tx_rate_limiter_throttled",
        "tx_spoofed_mac_count",
        "tx_remaining_reqs_count",
        { "tap_write_agg": latency_agg_metrics_fields() },
    ])
}

/// Returns the expected Firecracker metrics tree for `arch` (`firecracker_metrics` in python).
pub fn firecracker_metrics_template(arch: &str) -> Value {
    let mut template = json!({
        "utc_timestamp_ms": "",
        "api_server": [
            "process_startup_time_us",
            "process_startup_time_cpu_us",
        ],
        "balloon": [
            "activate_fails",
            "inflate_count",
            "stats_updates_count",
            "stats_update_fails",
            "deflate_count",
            "event_fails",
            "free_page_report_count",
            "free_page_report_freed",
            "free_page_report_fails",
            "free_page_hint_count",
            "free_page_hint_freed",
            "free_page_hint_fails",
        ],
        "block": block_metrics(),
        "deprecated_api": [
            "deprecated_http_api_calls",
        ],
        "get_api_requests": [
            "instance_info_count",
            "machine_cfg_count",
            "mmds_count",
            "vmm_version_count",
            "hotplug_memory_count",
        ],
        "i8042": [
            "error_count",
            "missed_read_count",
            "missed_write_count",
            "read_count",
            "reset_count",
            "write_count",
        ],
        "latencies_us": [
            "full_create_snapshot",
            "diff_create_snapshot",
            "load_snapshot",
            "pause_vm",
            "resume_vm",
            "vmm_full_create_snapshot",
            "vmm_diff_create_snapshot",
            "vmm_load_snapshot",
            "vmm_pause_vm",
            "vmm_resume_vm",
        ],
        "logger": [
            "missed_metrics_count",
            "metrics_fails",
            "missed_log_count",
            "rate_limited_log_count",
        ],
        "mmds": [
            "rx_accepted",
            "rx_accepted_err",
            "rx_accepted_unusual",
            "rx_bad_eth",
            "rx_invalid_token",
            "rx_no_token",
            "rx_count",
            "tx_bytes",
            "tx_count",
            "tx_errors",
            "tx_frames",
            "connections_created",
            "connections_destroyed",
        ],
        "net": net_metrics(),
        "patch_api_requests": [
            "drive_count",
            "drive_fails",
            "network_count",
            "network_fails",
            "machine_cfg_count",
            "machine_cfg_fails",
            "mmds_count",
            "mmds_fails",
            "hotplug_memory_count",
            "hotplug_memory_fails",
            "pmem_count",
            "pmem_fails",
        ],
        "put_api_requests": [
            "actions_count",
            "actions_fails",
            "boot_source_count",
            "boot_source_fails",
            "drive_count",
            "drive_fails",
            "logger_count",
            "logger_fails",
            "machine_cfg_count",
            "machine_cfg_fails",
            "cpu_cfg_count",
            "cpu_cfg_fails",
            "metrics_count",
            "metrics_fails",
            "network_count",
            "network_fails",
            "mmds_count",
            "mmds_fails",
            "vsock_count",
            "vsock_fails",
            "pmem_count",
            "pmem_fails",
            "serial_count",
            "serial_fails",
            "hotplug_memory_count",
            "hotplug_memory_fails",
        ],
        "seccomp": [
            "num_faults",
        ],
        "vcpu": [
            "exit_io_in",
            "exit_io_out",
            "exit_mmio_read",
            "exit_mmio_write",
            "failures",
            "kvmclock_ctrl_fails",
            { "exit_io_in_agg": latency_agg_metrics_fields() },
            { "exit_io_out_agg": latency_agg_metrics_fields() },
            { "exit_mmio_read_agg": latency_agg_metrics_fields() },
            { "exit_mmio_write_agg": latency_agg_metrics_fields() },
        ],
        "vmm": [
            "panic_count",
        ],
        "uart": [
            "error_count",
            "flush_count",
            "missed_read_count",
            "missed_write_count",
            "read_count",
            "write_count",
            "rate_limiter_dropped_bytes",
        ],
        "signals": [
            "sigbus",
            "sigsegv",
            "sigxfsz",
            "sigxcpu",
            "sigpipe",
            "sighup",
            "sigill",
        ],
        "vsock": [
            "activate_fails",
            "cfg_fails",
            "rx_queue_event_fails",
            "tx_queue_event_fails",
            "ev_queue_event_fails",
            "muxer_event_fails",
            "conn_event_fails",
            "rx_queue_event_count",
            "tx_queue_event_count",
            "rx_bytes_count",
            "tx_bytes_count",
            "rx_packets_count",
            "tx_packets_count",
            "conns_added",
            "conns_killed",
            "conns_removed",
            "killq_resync",
            "tx_flush_fails",
            "tx_write_fails",
            "rx_read_fails",
        ],
        "entropy": [
            "activate_fails",
            "entropy_event_fails",
            "entropy_event_count",
            "entropy_bytes",
            "host_rng_fails",
            "entropy_rate_limiter_throttled",
            "rate_limiter_event_count",
        ],
        "interrupts": ["triggers", "config_updates"],
        "pmem": [
            "activate_fails",
            "cfg_fails",
            "event_fails",
            "queue_event_count",
            "rate_limiter_throttled_events",
            "rate_limiter_event_count",
        ],
        "memory_hotplug": [
            "activate_fails",
            "queue_event_fails",
            "queue_event_count",
            "plug_count",
            "plug_bytes",
            "plug_fails",
            { "plug_agg": latency_agg_metrics_fields() },
            "unplug_count",
            "unplug_bytes",
            "unplug_fails",
            "unplug_discard_fails",
            { "unplug_agg": latency_agg_metrics_fields() },
            "state_count",
            "state_fails",
            { "state_agg": latency_agg_metrics_fields() },
            "unplug_all_count",
            "unplug_all_fails",
            { "unplug_all_agg": latency_agg_metrics_fields() },
        ],
    });
    if arch == "aarch64" {
        template["rtc"] = json!(["error_count", "missed_read_count", "missed_write_count",]);
    }
    template
}

/// Builds a JSON-schema-like tree from a metrics template (`create_metrics_schema_objects`).
pub fn create_metrics_schema_objects(metrics: &Value) -> Result<Value> {
    match metrics {
        Value::Object(map) => {
            let mut required: Vec<Value> = Vec::new();
            let mut properties = Map::new();
            // python pops the timestamp before recursing; the placeholder value of the template is
            // never part of the schema.
            if map.contains_key(UTC_TIMESTAMP_MS) {
                properties.insert(UTC_TIMESTAMP_MS.to_string(), json!({"type": "number"}));
                required.push(json!(UTC_TIMESTAMP_MS));
            }
            for (name, value) in map {
                if name == UTC_TIMESTAMP_MS {
                    continue;
                }
                properties.insert(name.clone(), create_metrics_schema_objects(value)?);
                required.push(json!(name));
            }
            Ok(json!({
                "type": "object",
                "required": required,
                "properties": properties,
                "additionalProperties": false,
            }))
        }
        Value::Array(items) => {
            let mut required: Vec<Value> = Vec::new();
            let mut properties = Map::new();
            for item in items {
                match item {
                    Value::String(field) => {
                        properties.insert(field.clone(), json!({"type": "number"}));
                        required.push(json!(field));
                    }
                    Value::Object(map) => {
                        for (name, value) in map {
                            properties.insert(name.clone(), create_metrics_schema_objects(value)?);
                            required.push(json!(name));
                        }
                    }
                    // python silently ignores other list entries.
                    _ => {}
                }
            }
            Ok(json!({
                "type": "object",
                "required": required,
                "properties": properties,
                "additionalProperties": false,
            }))
        }
        _ => bail!("Invalid schema"),
    }
}

/// Returns every schema violation of `instance` against `schema`.
pub fn schema_errors(instance: &Value, schema: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    validate_schema_value(instance, schema, "", &mut errors);
    errors
}

fn validate_schema_value(instance: &Value, schema: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(schema_object) = schema.as_object() else {
        return;
    };
    if let Some(kind) = schema_object.get("type").and_then(Value::as_str) {
        let matches = match kind {
            "object" => instance.is_object(),
            "number" => instance.is_number(),
            "string" => instance.is_string(),
            _ => true,
        };
        if !matches {
            let subject = if path.is_empty() { "<root>" } else { path };
            errors.push(format!("'{subject}' is not of type '{kind}'"));
            return;
        }
    }
    let Value::Object(map) = instance else {
        return;
    };
    if let Some(required) = schema_object.get("required").and_then(Value::as_array) {
        for key in required.iter().filter_map(Value::as_str) {
            if !map.contains_key(key) {
                errors.push(format!("'{key}' is a required property"));
            }
        }
    }
    let properties = schema_object.get("properties").and_then(Value::as_object);
    let additional = schema_object.get("additionalProperties");
    for (key, value) in map {
        let child_path = join_metric_path(path, key);
        match properties.and_then(|properties| properties.get(key)) {
            Some(child_schema) => validate_schema_value(value, child_schema, &child_path, errors),
            None => match additional {
                Some(Value::Bool(false)) => {
                    errors.push(format!("additional property '{child_path}' is not allowed"));
                }
                Some(schema_value @ Value::Object(_)) => {
                    validate_schema_value(value, schema_value, &child_path, errors);
                }
                _ => {}
            },
        }
    }
}

fn join_metric_path(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

/// Validates a Firecracker metrics datapoint (`validate_fc_metrics`).
pub fn validate_fc_metrics(metrics: &mut Value) -> Result<()> {
    let reported = metrics
        .get(UTC_TIMESTAMP_MS)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("metrics are missing a numeric `{UTC_TIMESTAMP_MS}`"))?;
    let now_ms = current_utc_timestamp_ms();
    if (now_ms - reported).abs() >= MAX_TIMESTAMP_SKEW_MS {
        bail!("{UTC_TIMESTAMP_MS} {reported} is not a current UTC timestamp (expected ~{now_ms})");
    }

    let arch = defs::host_arch();
    let mut template = firecracker_metrics_template(arch);
    let mut vhost_user_devices: Vec<String> = Vec::new();
    if let Some(names) = metrics.as_object() {
        for metrics_name in names.keys() {
            if metrics_name.starts_with("vhost_user_") {
                template[metrics_name.as_str()] = json!(VHOST_USER_METRICS.to_vec());
                vhost_user_devices.push(metrics_name.clone());
            } else if metrics_name.starts_with("block_") {
                template[metrics_name.as_str()] = block_metrics();
            } else if metrics_name.starts_with("net_") {
                template[metrics_name.as_str()] = net_metrics();
            }
        }
    }
    let mut schema = create_metrics_schema_objects(&template)?;
    let schema_object = schema
        .as_object_mut()
        .ok_or_else(|| anyhow!("the metrics schema root is not an object"))?;
    let properties = schema_object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("the metrics schema has no properties"))?;
    // `id` and `properties` are optional non-metric fields (see `MetricsConfig.emit_id` and
    // `MetricsConfig.properties`): allow them when present, never require them.
    properties.insert("id".to_string(), json!({"type": "string"}));
    properties.insert(
        "properties".to_string(),
        json!({"type": "object", "additionalProperties": {"type": "string"}}),
    );

    let errors = schema_errors(metrics, &schema);
    if !errors.is_empty() {
        bail!(
            "Firecracker metrics do not match the expected schema: {}",
            errors.join("; ")
        );
    }

    validate_missing_metrics(metrics, &schema, arch, &vhost_user_devices)
}

/// Regression pass: removing a required field must make the schema complain.
fn validate_missing_metrics(
    metrics: &mut Value,
    schema: &Value,
    arch: &str,
    vhost_user_devices: &[String],
) -> Result<()> {
    expect_required_error(metrics, schema, "api_server", "process_startup_time_us")?;
    if arch == "aarch64" {
        expect_required_error(metrics, schema, "rtc", "error_count")?;
    }
    for vhost_user_device in vhost_user_devices {
        expect_required_error(metrics, schema, vhost_user_device, "activate_time_us")?;
    }
    Ok(())
}

/// Removes `container.field`, expects a `required property` error, then restores the field.
fn expect_required_error(
    metrics: &mut Value,
    schema: &Value,
    container: &str,
    field: &str,
) -> Result<()> {
    let removed = metrics
        .get_mut(container)
        .and_then(Value::as_object_mut)
        .and_then(|object| object.remove(field))
        .ok_or_else(|| anyhow!("metrics are missing `{container}.{field}`"))?;
    let errors = schema_errors(metrics, schema);
    if let Some(object) = metrics.get_mut(container).and_then(Value::as_object_mut) {
        object.insert(field.to_string(), removed);
    }
    let expected = format!("'{field}' is a required property");
    if !errors.iter().any(|error| error.contains(&expected)) {
        bail!("expected a schema error containing {expected:?}, got {errors:?}");
    }
    Ok(())
}

/// Validates the breaking-change and aggregation behaviour of one device's metrics
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcDeviceMetrics {
    /// Device metric group name, e.g. `block` or `net`.
    pub dev_name: String,
    /// Expected number of `<dev_name>_*` metric groups.
    pub num_dev: usize,
    /// Whether Firecracker emits an aggregated `<dev_name>` group.
    pub aggr_supported: bool,
}

impl FcDeviceMetrics {
    /// Creates a device metrics expectation.
    pub fn new(dev_name: impl Into<String>, num_dev: usize, aggr_supported: bool) -> Self {
        Self {
            dev_name: dev_name.into(),
            num_dev,
            aggr_supported,
        }
    }

    /// Flushes the VM metrics and validates both the schema and the per-device aggregation.
    pub fn validate(&self, vm: &dyn MetricsVm) -> Result<()> {
        let mut fc_metrics = vm.flush_metrics()?;
        validate_fc_metrics(&mut fc_metrics)?;
        self.validate_per_device_metrics(&fc_metrics)
    }

    /// Checks that `<dev_name>` is the aggregate of `<dev_name>_*` and that the device count
    pub fn validate_per_device_metrics(&self, fc_metrics: &Value) -> Result<()> {
        let (actual_num_devices, calculated) = self.aggregate_device_metrics(fc_metrics)?;
        if actual_num_devices != self.num_dev {
            bail!(
                "expected {} `{}_*` metric groups, found {actual_num_devices}",
                self.num_dev,
                self.dev_name
            );
        }
        if self.aggr_supported {
            let aggregate = fc_metrics
                .get(&self.dev_name)
                .ok_or_else(|| anyhow!("missing aggregate metric group `{}`", self.dev_name))?;
            if aggregate != &calculated {
                bail!(
                    "aggregate `{}` ({aggregate}) is not the sum of the per-device metrics ({calculated})",
                    self.dev_name
                );
            }
        }
        Ok(())
    }

    /// Sums every `<dev_name>_*` group and returns the device count alongside the totals.
    pub fn aggregate_device_metrics(&self, fc_metrics: &Value) -> Result<(usize, Value)> {
        let metrics = fc_metrics
            .as_object()
            .ok_or_else(|| anyhow!("firecracker metrics are not a JSON object"))?;
        let mut calculated = Map::new();
        let mut actual_num_devices = 0usize;
        let device_prefix = format!("{}_", self.dev_name);
        for (component_metric_names, component_metric_values) in metrics {
            if !(component_metric_names.starts_with(&self.dev_name)
                && component_metric_names.contains(&device_prefix))
            {
                continue;
            }
            actual_num_devices += 1;
            let Some(values) = component_metric_values.as_object() else {
                continue;
            };
            for (metrics_name, metric_value) in values {
                if metric_value.is_i64() || metric_value.is_u64() {
                    // python only accumulates `int` values, ignoring floats.
                    let current = calculated
                        .get(metrics_name)
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let addition = metric_value.as_i64().unwrap_or(0);
                    calculated.insert(metrics_name.clone(), json!(current + addition));
                } else if metric_value.is_object() {
                    // LatencyAggregateMetrics: only `sum_us` accumulates.
                    let entry = calculated
                        .entry(metrics_name.clone())
                        .or_insert_with(|| json!({"min_us": 0, "max_us": 0, "sum_us": 0}));
                    let previous = entry.get("sum_us").and_then(Value::as_i64).unwrap_or(0);
                    let addition = metric_value
                        .get("sum_us")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    entry["sum_us"] = json!(previous + addition);
                }
            }
        }
        Ok((actual_num_devices, Value::Object(calculated)))
    }
}

/// Returns the CloudWatch unit for a Firecracker metrics key (`get_emf_unit_for_fc_metrics`).
pub fn get_emf_unit_for_fc_metrics(full_key: &str) -> &'static str {
    for key in full_key.to_lowercase().split('.') {
        if key.ends_with("_bytes") || key.ends_with("_bytes_count") {
            return "Bytes";
        }
        if key.ends_with("_ms") {
            return "Milliseconds";
        }
        if key.ends_with("_us") {
            return "Microseconds";
        }
    }
    "Count"
}

/// Flattens a metrics tree into `prefix.child...` paths (`flatten_dict` in python).
pub fn flatten_dict(node: &Value, prefix: &str) -> BTreeMap<String, Value> {
    let mut result = BTreeMap::new();
    match node {
        Value::Object(map) => {
            for (name, child) in map {
                result.extend(flatten_dict(child, &join_metric_path(prefix, name)));
            }
        }
        other => {
            result.insert(prefix.to_string(), other.clone());
        }
    }
    result
}

/// Returns the flattened failure counters that are non-zero.
pub fn failing_metrics(flattened: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    let mut failures = BTreeMap::new();
    for (key, value) in flattened {
        if IGNORED_FAILURE_METRICS.contains(&key.as_str()) {
            continue;
        }
        let Some(leaf) = key.split('.').next_back() else {
            continue;
        };
        let is_failure = leaf.contains("err")
            || leaf.contains("fail")
            || leaf.contains("panic")
            || leaf.contains("num_faults");
        // python uses a truthiness test: only non-zero counters count as failures.
        let is_zero = match value {
            Value::Null => true,
            Value::Number(number) => number.as_f64().map(|value| value == 0.0).unwrap_or(false),
            Value::String(text) => text.is_empty(),
            Value::Bool(flag) => !flag,
            _ => false,
        };
        if !is_failure || is_zero {
            continue;
        }
        failures.insert(key.clone(), value.clone());
    }
    failures
}

/// Exports one metrics datapoint and asserts that no failure counter moved
pub fn flush_fc_metrics_to_cw(fc_metrics: &Value, metrics: &mut MetricsWrapper) -> Result<()> {
    let flattened_metrics = flatten_dict(fc_metrics, "fc_metrics");
    for (key, value) in &flattened_metrics {
        if key.contains(".utc_timestamp_ms.") {
            continue;
        }
        let Some(number) = value.as_f64() else {
            bail!("metric {key} is not numeric: {value}");
        };
        metrics.put_metric(key, number, get_emf_unit_for_fc_metrics(key));
    }
    metrics.flush();

    let failures = failing_metrics(&flattened_metrics);
    if !failures.is_empty() {
        bail!(
            "firecracker reported failure metrics: {}",
            serde_json::to_string_pretty(&failures)?
        );
    }
    Ok(())
}

/// Background monitor that exports Firecracker metrics every `timer` seconds
pub struct FCMetricsMonitor {
    vm: Arc<dyn MetricsVm>,
    timer: Duration,
    metrics_index: AtomicUsize,
    running: AtomicBool,
    metrics_logger: Mutex<MetricsWrapper>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl FCMetricsMonitor {
    /// python's default collection interval, matching Firecracker's own metrics dump cadence.
    pub const DEFAULT_TIMER_SECS: u64 = 60;

    /// Creates a monitor without starting it.
    pub fn new(vm: Arc<dyn MetricsVm>, timer: Duration) -> Self {
        Self {
            vm,
            timer,
            metrics_index: AtomicUsize::new(0),
            running: AtomicBool::new(false),
            metrics_logger: Mutex::new(MetricsWrapper::new()),
            handle: Mutex::new(None),
        }
    }

    /// Creates a monitor with python's 60 second interval.
    pub fn with_default_timer(vm: Arc<dyn MetricsVm>) -> Self {
        Self::new(vm, Duration::from_secs(Self::DEFAULT_TIMER_SECS))
    }

    /// Returns the collection interval.
    pub fn timer(&self) -> Duration {
        self.timer
    }

    /// Returns how many datapoints have been exported so far.
    pub fn metrics_index(&self) -> usize {
        self.metrics_index.load(Ordering::SeqCst)
    }

    /// Returns `true` while the background collection thread is alive.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Sets the CloudWatch dimensions and starts the background collection thread.
    pub fn start(self: &Arc<Self>) -> Result<()> {
        {
            let mut logger = self
                .metrics_logger
                .lock()
                .map_err(|_| anyhow!("metrics logger mutex is poisoned"))?;
            logger.set_dimensions(&self.vm.metric_dimensions());
        }
        let mut handle = self
            .handle
            .lock()
            .map_err(|_| anyhow!("metrics monitor handle mutex is poisoned"))?;
        if handle.as_ref().is_some_and(|handle| !handle.is_finished()) {
            return Err(anyhow!("metrics monitor is already running"));
        }
        // Arm the flag before spawning so an immediate `stop()` cannot race the
        // thread's own `running = true` store and leave it looping forever.
        self.running.store(true, Ordering::SeqCst);
        let monitor = Arc::clone(self);
        *handle = Some(thread::spawn(move || monitor.run()));
        Ok(())
    }

    /// Stops the monitor and exports the remaining datapoints (python `stop`).
    pub fn stop(&self) -> Result<()> {
        let handle = self
            .handle
            .lock()
            .map_err(|_| anyhow!("metrics monitor handle mutex is poisoned"))?
            .take();
        let Some(handle) = handle else {
            return Ok(());
        };
        self.running.store(false, Ordering::SeqCst);
        let _ = handle.join();
        if let Err(err) = self.vm.request_metrics_flush() {
            eprintln!("failed to flush Firecracker metrics: {err:#}");
        }
        self.flush_metrics().map(|_| ())
    }

    /// Exports every datapoint that has not been exported yet and returns how many were new.
    pub fn flush_metrics(&self) -> Result<usize> {
        let all_metrics = self.vm.all_metrics()?;
        let mut flushed = 0usize;
        for metrics in all_metrics.iter().skip(self.metrics_index()) {
            {
                let mut logger = self
                    .metrics_logger
                    .lock()
                    .map_err(|_| anyhow!("metrics logger mutex is poisoned"))?;
                flush_fc_metrics_to_cw(metrics, &mut logger)?;
            }
            self.metrics_index.fetch_add(1, Ordering::SeqCst);
            flushed += 1;
        }
        Ok(flushed)
    }

    /// Writes the collected metrics to `<dir>/metrics.json` (python `store_data`).
    pub fn store_data(&self, dir: &Path, nodeid: Option<&str>) -> Result<()> {
        let logger = self
            .metrics_logger
            .lock()
            .map_err(|_| anyhow!("metrics logger mutex is poisoned"))?;
        logger.store_data(dir, nodeid)
    }

    /// Body of the collection thread (python `FCMetricsMonitor.run`).
    fn run(self: Arc<Self>) {
        while self.running.load(Ordering::SeqCst) {
            if let Err(err) = self.flush_metrics() {
                // python would let the exception kill the daemon thread; keep it observable
                // without hiding the test failure that is usually the real cause.
                eprintln!("failed to export Firecracker metrics: {err:#}");
            }
            // Sleep in one second steps so `stop` does not have to wait a whole period.
            for _ in 0..self.timer.as_secs().max(1) {
                thread::sleep(Duration::from_secs(1));
                if !self.running.load(Ordering::SeqCst) {
                    break;
                }
            }
        }
    }
}

impl Drop for FCMetricsMonitor {
    /// Stops the collection thread when the monitor goes out of scope.
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Returns the repository files ending in `metrics.rs` (python `find_metrics_files`).
pub fn find_metrics_files() -> Result<Vec<PathBuf>> {
    let workspace = defs::workspace_dir();
    let result = utils::check_output(&format!("git -C {} ls-files", workspace.display()))
        .context("listing the repository files")?;
    Ok(result
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && line.ends_with("metrics.rs"))
        .map(PathBuf::from)
        .collect())
}

fn metrics_field_regex() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        // python greps with a lookbehind (`(?<=pub )`), which the `regex` crate does not support;
        // matching `pub ` explicitly and capturing the field keeps the same results.
        Regex::new(r"pub (\w+): (Shared(?:Inc|Store)Metric|LatencyAggregateMetrics)")
            .expect("static metrics field regex is valid")
    })
}

/// Extracts `(field, type)` pairs from one metrics definition file (`extract_fields`).
pub fn extract_fields(file_path: &Path) -> Result<Vec<(String, String)>> {
    let content = std::fs::read_to_string(file_path)
        .with_context(|| format!("reading {}", file_path.display()))?;
    Ok(extract_fields_from_content(&content))
}

/// Extracts `(field, type)` pairs from metrics definition source text.
pub fn extract_fields_from_content(content: &str) -> Vec<(String, String)> {
    metrics_field_regex()
        .captures_iter(content)
        .map(|captures| (captures[1].to_string(), captures[2].to_string()))
        .collect()
}

/// Returns `true` for test files and metrics definition files (`is_file_test_or_definition`).
pub fn is_file_test_or_definition(filepath: &str) -> bool {
    let path = filepath.to_lowercase();
    path.contains("/test/")
        || path.contains("/tests/")
        || path.ends_with("_test.rs")
        || path.contains("test_")
        || path.contains("tests.rs")
        || (path.contains("metrics.rs") && path.contains("vmm"))
}

/// Strips comments and string literals from a source line, or `None` for comment-only lines.
pub fn field_usage_code(code: &str) -> Option<String> {
    let code = code.trim_start();
    if code.starts_with("//") || code.starts_with("/*") || code.starts_with('*') {
        return None;
    }
    // python: re.sub(r"//.*", "", code) then re.sub(r'"[^"]*"', "", code).
    let code = match code.find("//") {
        Some(position) => &code[..position],
        None => code,
    };
    Some(strip_string_literals(code))
}

fn strip_string_literals(code: &str) -> String {
    let mut output = String::with_capacity(code.len());
    let mut rest = code;
    while let Some(position) = rest.find('"') {
        output.push_str(&rest[..position]);
        let after_quote = &rest[position + 1..];
        match after_quote.find('"') {
            Some(end) => rest = &after_quote[end + 1..],
            None => {
                // Unmatched quote: keep it, like the non-matching python regex.
                output.push('"');
                rest = after_quote;
            }
        }
    }
    output.push_str(rest);
    output
}

/// Marks every field name that `filepath`'s `code` line really uses.
pub fn mark_used_fields_in_line(
    filepath: &str,
    code: &str,
    field_names: &[String],
    used: &mut BTreeSet<String>,
) {
    if is_file_test_or_definition(filepath) {
        return;
    }
    let Some(code) = field_usage_code(code) else {
        return;
    };
    for field in field_names {
        if code.contains(field.as_str()) {
            used.insert(field.clone());
        }
    }
}

/// Collects field usages of one source tree into `used`.
pub fn scan_source_tree(
    root: &Path,
    field_names: &[String],
    used: &mut BTreeSet<String>,
) -> Result<()> {
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let display = entry.path().display().to_string();
        for line in content.lines() {
            mark_used_fields_in_line(&display, line, field_names, used);
        }
    }
    Ok(())
}

/// Finds metrics fields without production usage (`find_unused_metrics`).
pub fn find_unused_metrics() -> Result<BTreeMap<String, Vec<(String, String)>>> {
    let metrics_files = find_metrics_files()?;
    if metrics_files.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut all_fields: Vec<(String, String, String)> = Vec::new();
    for file_path in &metrics_files {
        for (field, ty) in extract_fields(file_path)? {
            all_fields.push((file_path.display().to_string(), field, ty));
        }
    }
    if all_fields.is_empty() {
        return Ok(BTreeMap::new());
    }

    let field_names: BTreeSet<String> = all_fields
        .iter()
        .filter(|(_, field, _)| !KNOWN_FALSE_POSITIVES.contains(&field.as_str()))
        .map(|(_, field, _)| field.clone())
        .collect();
    if field_names.is_empty() {
        return Ok(BTreeMap::new());
    }
    let field_names: Vec<String> = field_names.into_iter().collect();

    let mut used: BTreeSet<String> = BTreeSet::new();
    scan_source_tree(&defs::workspace_dir().join("src"), &field_names, &mut used)?;

    let mut unused: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (file_path, field, ty) in all_fields {
        if KNOWN_FALSE_POSITIVES.contains(&field.as_str()) {
            continue;
        }
        if !used.contains(&field) {
            unused.entry(file_path).or_default().push((field, ty));
        }
    }
    Ok(unused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_objects_require_every_field() {
        let template = json!({
            "utc_timestamp_ms": "",
            "block": ["read_count", "write_count", {"read_agg": ["min_us", "max_us", "sum_us"]}],
        });
        let schema = create_metrics_schema_objects(&template).expect("schema");

        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], json!(false));
        assert_eq!(schema["required"], json!(["utc_timestamp_ms", "block"]));
        assert_eq!(schema["properties"]["utc_timestamp_ms"]["type"], "number");
        assert_eq!(schema["properties"]["block"]["type"], "object");
        assert_eq!(
            schema["properties"]["block"]["properties"]["read_count"]["type"],
            "number"
        );
        assert_eq!(
            schema["properties"]["block"]["properties"]["read_agg"]["properties"]["sum_us"]["type"],
            "number"
        );
        assert_eq!(
            schema["properties"]["block"]["required"],
            json!(["read_count", "write_count", "read_agg"])
        );
        // Unknown nodes are rejected, like python's `Invalid schema`.
        assert!(create_metrics_schema_objects(&json!("nope")).is_err());
        assert!(create_metrics_schema_objects(&json!(42)).is_err());
    }

    #[test]
    fn schema_errors_find_missing_extra_and_mistyped_fields() {
        let schema = json!({
            "type": "object",
            "required": ["read_count"],
            "properties": {"read_count": {"type": "number"}},
            "additionalProperties": false,
        });
        assert!(schema_errors(&json!({"read_count": 1}), &schema).is_empty());

        let missing = schema_errors(&json!({}), &schema);
        assert_eq!(missing, vec!["'read_count' is a required property"]);

        let extra = schema_errors(&json!({"read_count": 1, "other": 0}), &schema);
        assert_eq!(extra, vec!["additional property 'other' is not allowed"]);

        let mistyped = schema_errors(&json!({"read_count": "one"}), &schema);
        assert_eq!(mistyped, vec!["'read_count' is not of type 'number'"]);

        // `additionalProperties: true` (or a missing entry) allows anything.
        let open = json!({"type": "object", "properties": {}});
        assert!(schema_errors(&json!({"anything": 1}), &open).is_empty());
    }

    #[test]
    fn aarch64_template_gains_rtc_metrics() {
        assert!(firecracker_metrics_template("x86_64").get("rtc").is_none());
        let arm = firecracker_metrics_template("aarch64");
        assert_eq!(
            arm["rtc"],
            json!(["error_count", "missed_read_count", "missed_write_count"])
        );
        // The template must stay schema-compatible.
        assert!(create_metrics_schema_objects(&arm).is_ok());
    }

    #[test]
    fn timestamp_sanity_is_checked_first() {
        let mut empty = json!({});
        let err = validate_fc_metrics(&mut empty).expect_err("no timestamp");
        assert!(err.to_string().contains("missing a numeric"), "{err}");

        let mut stale = json!({"utc_timestamp_ms": current_utc_timestamp_ms() - 60_000});
        let err = validate_fc_metrics(&mut stale).expect_err("stale timestamp");
        assert!(
            err.to_string().contains("is not a current UTC timestamp"),
            "{err}"
        );
    }

    #[test]
    fn emf_units_come_from_the_segments() {
        assert_eq!(
            get_emf_unit_for_fc_metrics("fc_metrics.block.read_bytes"),
            "Bytes"
        );
        assert_eq!(
            get_emf_unit_for_fc_metrics("fc_metrics.net.rx_bytes_count"),
            "Bytes"
        );
        assert_eq!(
            get_emf_unit_for_fc_metrics("fc_metrics.latencies_us.pause_vm"),
            "Microseconds"
        );
        assert_eq!(
            get_emf_unit_for_fc_metrics("fc_metrics.api_server.process_startup_time_us"),
            "Microseconds"
        );
        assert_eq!(
            get_emf_unit_for_fc_metrics("fc_metrics.vmm.page_ms"),
            "Milliseconds"
        );
        assert_eq!(
            get_emf_unit_for_fc_metrics("fc_metrics.vmm.panic_count"),
            "Count"
        );
    }

    #[test]
    fn flatten_dict_walks_the_whole_tree() {
        let metrics = json!({
            "utc_timestamp_ms": 7,
            "vmm": {"panic_count": 0},
            "block": {"read_agg": {"min_us": 1}},
        });
        let flattened = flatten_dict(&metrics, "fc_metrics");
        assert_eq!(flattened["fc_metrics.utc_timestamp_ms"], json!(7));
        assert_eq!(flattened["fc_metrics.vmm.panic_count"], json!(0));
        assert_eq!(flattened["fc_metrics.block.read_agg.min_us"], json!(1));
        assert_eq!(flattened.len(), 3);
    }

    #[test]
    fn failure_counters_are_detected_and_ignored() {
        let metrics = json!({
            "utc_timestamp_ms": 7,
            "vmm": {"panic_count": 0},
            "block": {"read_count": 3},
            "vsock": {"tx_write_fails": 9},
            "net": {"rx_fails": 2},
        });
        let flattened = flatten_dict(&metrics, "fc_metrics");
        let failures = failing_metrics(&flattened);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures["fc_metrics.net.rx_fails"], json!(2));
    }

    #[test]
    fn flush_exports_units_and_rejects_failures() {
        let ok_metrics = json!({
            "utc_timestamp_ms": 7,
            "vmm": {"panic_count": 0},
            "block": {"read_bytes": 4096},
        });
        let mut logger = MetricsWrapper::new();
        flush_fc_metrics_to_cw(&ok_metrics, &mut logger).expect("clean metrics flush");

        let read_bytes = logger
            .metrics()
            .get("fc_metrics.block.read_bytes")
            .expect("read_bytes metric");
        assert_eq!(read_bytes.unit, "Bytes");
        assert_eq!(read_bytes.values, vec![4096.0]);
        let timestamp = logger
            .metrics()
            .get("fc_metrics.utc_timestamp_ms")
            .expect("timestamp metric");
        // `*_ms` keys map to Milliseconds in the python original as well.
        assert_eq!(timestamp.unit, "Milliseconds");

        let failing = json!({
            "utc_timestamp_ms": 7,
            "vmm": {"panic_count": 1},
        });
        let mut logger = MetricsWrapper::new();
        let err = flush_fc_metrics_to_cw(&failing, &mut logger).expect_err("panic counted");
        assert!(err.to_string().contains("panic_count"), "{err}");

        let mut logger = MetricsWrapper::new();
        let err = flush_fc_metrics_to_cw(&json!({"vmm": {"panic_count": "many"}}), &mut logger)
            .expect_err("non numeric leaf");
        assert!(err.to_string().contains("not numeric"), "{err}");
    }

    #[test]
    fn device_metrics_aggregate_latency_groups() {
        let fc_metrics = json!({
            "block_0": {"read_count": 1, "read_agg": {"min_us": 1, "max_us": 2, "sum_us": 3}},
            "block_1": {"read_count": 2, "read_agg": {"min_us": 1, "max_us": 2, "sum_us": 3}},
            "block": {
                "read_count": 3,
                "read_agg": {"min_us": 0, "max_us": 0, "sum_us": 6},
            },
        });
        let device = FcDeviceMetrics::new("block", 2, true);
        device
            .validate_per_device_metrics(&fc_metrics)
            .expect("aggregate matches");

        let (count, calculated) = device.aggregate_device_metrics(&fc_metrics).expect("sums");
        assert_eq!(count, 2);
        assert_eq!(calculated["read_count"], json!(3));
        assert_eq!(calculated["read_agg"]["sum_us"], json!(6));
        assert_eq!(calculated["read_agg"]["min_us"], json!(0));

        // Wrong device count.
        let too_many = FcDeviceMetrics::new("block", 3, true);
        let err = too_many
            .validate_per_device_metrics(&fc_metrics)
            .expect_err("device count mismatch");
        assert!(
            err.to_string()
                .contains("expected 3 `block_*` metric groups"),
            "{err}"
        );

        // Aggregate that does not match the per-device sum.
        let broken = json!({
            "block_0": {"read_count": 1},
            "block": {"read_count": 5},
        });
        let err = FcDeviceMetrics::new("block", 1, true)
            .validate_per_device_metrics(&broken)
            .expect_err("aggregate mismatch");
        assert!(err.to_string().contains("is not the sum"), "{err}");

        // No aggregate group is required when aggregation is unsupported.
        let without_aggregate = json!({"net_0": {"rx_count": 4}});
        let device = FcDeviceMetrics::new("net", 1, false);
        device
            .validate_per_device_metrics(&without_aggregate)
            .expect("aggregation is optional here");
    }

    #[test]
    fn extract_fields_reads_definitions() {
        let content = "\
    /// Counter
    pub read_count: SharedIncMetric,
    pub read_agg: LatencyAggregateMetrics,
    pub gauge: SharedStoreMetric,
    pub not_a_metric: u64,
    fn helper() {}
";
        assert_eq!(
            extract_fields_from_content(content),
            vec![
                ("read_count".to_string(), "SharedIncMetric".to_string()),
                (
                    "read_agg".to_string(),
                    "LatencyAggregateMetrics".to_string()
                ),
                ("gauge".to_string(), "SharedStoreMetric".to_string()),
            ]
        );
    }

    #[test]
    fn test_and_definition_files_are_recognised() {
        assert!(is_file_test_or_definition("src/vmm/src/metrics.rs"));
        assert!(is_file_test_or_definition("src/devices/src/test/mod.rs"));
        assert!(is_file_test_or_definition("src/api/tests.rs"));
        assert!(is_file_test_or_definition("src/api/thing_test.rs"));
        assert!(is_file_test_or_definition("src/api/test_thing.rs"));
        assert!(!is_file_test_or_definition("src/api/src/parsers.rs"));
    }

    #[test]
    fn comments_and_strings_are_stripped_before_matching() {
        assert_eq!(
            field_usage_code("    count += self.read_count"),
            Some("count += self.read_count".to_string())
        );
        assert_eq!(field_usage_code("    // self.read_count"), None);
        assert_eq!(field_usage_code("  /* block comment */"), None);
        assert_eq!(field_usage_code("   * doc line"), None);
        assert_eq!(
            field_usage_code("    let x = 1; // self.read_count"),
            Some("let x = 1; ".to_string())
        );
        assert_eq!(
            field_usage_code("    log::warn!(\"read_count {}\", 1)"),
            Some("log::warn!(, 1)".to_string())
        );
    }

    #[test]
    fn used_fields_are_collected_per_line() {
        let fields = vec!["read_count".to_string(), "write_count".to_string()];
        let mut used = BTreeSet::new();
        mark_used_fields_in_line(
            "src/api/src/lib.rs",
            "let x = m.read_count;",
            &fields,
            &mut used,
        );
        mark_used_fields_in_line("src/api/src/lib.rs", "// write_count", &fields, &mut used);
        mark_used_fields_in_line(
            "src/api/tests.rs",
            "let y = m.write_count;",
            &fields,
            &mut used,
        );
        assert_eq!(
            used,
            BTreeSet::from(["read_count".to_string()]),
            "comment and test-file references must not count"
        );
    }

    struct FakeMetricsVm {
        datapoints: Mutex<Vec<Value>>,
        flush_requests: AtomicUsize,
    }

    impl MetricsVm for FakeMetricsVm {
        fn all_metrics(&self) -> Result<Vec<Value>> {
            Ok(self.datapoints.lock().expect("lock").clone())
        }

        fn flush_metrics(&self) -> Result<Value> {
            self.datapoints
                .lock()
                .expect("lock")
                .last()
                .cloned()
                .ok_or_else(|| anyhow!("no metrics available"))
        }

        fn request_metrics_flush(&self) -> Result<()> {
            self.flush_requests.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn metric_dimensions(&self) -> BTreeMap<String, String> {
            BTreeMap::from([
                ("instance".to_string(), "m5.metal".to_string()),
                ("host_kernel".to_string(), "linux-6.1".to_string()),
                ("guest_kernel".to_string(), "linux-5.10".to_string()),
            ])
        }
    }

    #[test]
    fn monitor_exports_new_datapoints_only_once() {
        let vm = Arc::new(FakeMetricsVm {
            datapoints: Mutex::new(vec![
                json!({"utc_timestamp_ms": 1, "vmm": {"panic_count": 0}}),
                json!({"utc_timestamp_ms": 2, "vmm": {"panic_count": 0}}),
            ]),
            flush_requests: AtomicUsize::new(0),
        });
        let metrics_vm: Arc<dyn MetricsVm> = vm.clone();
        let monitor = Arc::new(FCMetricsMonitor::new(metrics_vm, Duration::from_secs(1)));
        assert_eq!(monitor.metrics_index(), 0);
        assert_eq!(monitor.timer(), Duration::from_secs(1));

        // The first synchronous flush exports both datapoints; a second one has nothing left.
        assert_eq!(monitor.flush_metrics().expect("flush"), 2);
        assert_eq!(monitor.metrics_index(), 2);
        assert_eq!(monitor.flush_metrics().expect("flush"), 0);

        monitor.start().expect("start");
        monitor.stop().expect("stop");
        assert_eq!(vm.flush_requests.load(Ordering::SeqCst), 1);
        assert_eq!(monitor.metrics_index(), 2);
        assert!(!monitor.is_running());
    }
}
