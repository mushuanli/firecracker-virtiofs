// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Metrics bookkeeping, ported from `tests/host_tools/metrics.py`.
//!
//! python wraps `aws-embedded-metrics` (`MetricsWrapper.logger`). This port keeps the local
//! bookkeeping (`metrics`, `dimensions`, `metrics.json`) and treats the CloudWatch EMF transport as
//! absent: [`MetricsWrapper::flush`] is a no-op, exactly like python's wrapper when
//! `AWS_EMF_NAMESPACE` is unset (python then passes `logger=None`).
//!
//! python's `set_property` only ever forwarded to the EMF logger, so it has no counterpart here.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

/// Accumulated datapoints of one metric, mirroring python's `{"unit": ..., "values": [...]}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MetricDatum {
    /// Unit the datapoints were recorded with (CloudWatch unit name, e.g. `Milliseconds`).
    pub unit: String,
    /// Recorded datapoints in arrival order.
    pub values: Vec<f64>,
}

impl MetricDatum {
    /// Creates an empty datum for `unit`.
    pub fn new(unit: impl Into<String>) -> Self {
        Self {
            unit: unit.into(),
            values: Vec::new(),
        }
    }
}

/// A convenient metrics logger (python `MetricsWrapper`).
#[derive(Debug, Clone, Default)]
pub struct MetricsWrapper {
    metrics: BTreeMap<String, MetricDatum>,
    dimensions: BTreeMap<String, String>,
}

impl MetricsWrapper {
    /// Creates an empty wrapper with no metrics and no dimensions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every recorded metric, keyed by metric name.
    pub fn metrics(&self) -> &BTreeMap<String, MetricDatum> {
        &self.metrics
    }

    /// Returns the active dimensions (python resets them on every `set_dimensions` call).
    pub fn dimensions(&self) -> &BTreeMap<String, String> {
        &self.dimensions
    }

    /// Replaces the active dimensions, like python's `set_dimensions`.
    pub fn set_dimensions(&mut self, dimensions: &BTreeMap<String, String>) {
        self.dimensions = dimensions.clone();
    }

    /// Records one datapoint for `name` with `unit`, creating the metric on first use.
    pub fn put_metric(&mut self, name: &str, data: f64, unit: &str) {
        self.metrics
            .entry(name.to_string())
            .or_insert_with(|| MetricDatum::new(unit))
            .values
            .push(data);
    }

    /// Flushes pending datapoints; the EMF transport is absent so this only exists for parity.
    pub fn flush(&mut self) {}

    /// Builds the `metrics.json` payload (`metrics`, `dimensions`, `nodeid`).
    pub fn to_json(&self, nodeid: Option<&str>) -> Value {
        json!({
            "metrics": self.metrics,
            "dimensions": self.dimensions,
            "nodeid": nodeid,
        })
    }

    /// Writes `metrics.json` into `dir_path` (python `store_data`).
    pub fn store_data(&self, dir_path: &Path, nodeid: Option<&str>) -> Result<()> {
        let metrics_path = dir_path.join("metrics.json");
        let payload = serde_json::to_string(&self.to_json(nodeid))
            .context("serialising collected metrics")?;
        std::fs::write(&metrics_path, payload)
            .with_context(|| format!("writing {}", metrics_path.display()))
    }
}

/// Returns a metrics logger (python `get_metrics_logger`).
pub fn get_metrics_logger() -> MetricsWrapper {
    MetricsWrapper::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fc-harness-metrics-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn put_metric_groups_values_by_name() {
        let mut wrapper = MetricsWrapper::new();
        wrapper.put_metric("duration", 1.0, "Milliseconds");
        wrapper.put_metric("duration", 2.5, "Milliseconds");
        wrapper.put_metric("bytes", 42.0, "Bytes");

        let duration = wrapper.metrics().get("duration").expect("duration");
        assert_eq!(duration.unit, "Milliseconds");
        assert_eq!(duration.values, vec![1.0, 2.5]);
        assert_eq!(
            wrapper.metrics().get("bytes").expect("bytes").values,
            vec![42.0]
        );
    }

    #[test]
    fn dimensions_are_replaced_not_merged() {
        let mut wrapper = MetricsWrapper::new();
        let mut first = BTreeMap::new();
        first.insert("instance".to_string(), "m5.metal".to_string());
        first.insert("cpu".to_string(), "intel".to_string());
        wrapper.set_dimensions(&first);

        let mut second = BTreeMap::new();
        second.insert("cpu".to_string(), "amd".to_string());
        wrapper.set_dimensions(&second);

        assert_eq!(wrapper.dimensions().len(), 1);
        assert_eq!(wrapper.dimensions()["cpu"], "amd");
    }

    #[test]
    fn json_payload_matches_python_shape() {
        let mut wrapper = MetricsWrapper::new();
        wrapper.put_metric("duration", 3.0, "Milliseconds");
        let payload = wrapper.to_json(Some("integration_tests/functional/test_api.py::test_x"));

        assert!(payload["metrics"]["duration"]["values"].is_array());
        assert_eq!(payload["metrics"]["duration"]["unit"], "Milliseconds");
        assert!(payload["dimensions"]
            .as_object()
            .expect("object")
            .is_empty());
        assert_eq!(
            payload["nodeid"],
            "integration_tests/functional/test_api.py::test_x"
        );
        assert!(wrapper.to_json(None)["nodeid"].is_null());
    }

    #[test]
    fn store_data_writes_metrics_json() {
        let dir = temp_dir("store");
        let mut wrapper = MetricsWrapper::new();
        wrapper.put_metric("duration", 1.0, "Milliseconds");
        wrapper
            .store_data(&dir, Some("nodeid"))
            .expect("store data");

        let written = std::fs::read_to_string(dir.join("metrics.json")).expect("read metrics.json");
        let parsed: Value = serde_json::from_str(&written).expect("valid json");
        assert_eq!(parsed["nodeid"], "nodeid");
        assert_eq!(
            parsed["metrics"]["duration"]["values"][0]
                .as_f64()
                .expect("number"),
            1.0
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
