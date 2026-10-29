// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A/B performance tests across two Firecracker builds, ported from
//! `tools/ab_test.py`.
//!
//! The python script leans on `numpy`/`scipy` for the regression test. This
//! port implements the same non-parametric permutation test directly (a
//! difference-of-means statistic with a two-sided p-value), so it needs neither
//! numpy nor scipy.
//!
//! Two subcommands mirror the python CLI:
//!
//! ```text
//! fc-ab-test run --binaries-a DIR --binaries-b DIR --pytest-opts '...'
//! fc-ab-test analyze PATH_A PATH_B
//! ```

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::Value;

use fc_harness::defs;
use fc_harness::utils;

/// Unit reduction ladder used by [`reduce_value`].
const UNIT_REDUCTIONS: &[(&str, &str)] = &[
    ("Microseconds", "Milliseconds"),
    ("Milliseconds", "Seconds"),
    ("Bytes", "Kilobytes"),
    ("Kilobytes", "Megabytes"),
    ("Megabytes", "Gigabytes"),
    ("Gigabytes", "Terabytes"),
    ("Bits", "Kilobits"),
    ("Kilobits", "Megabits"),
    ("Megabits", "Gigabits"),
    ("Gigabits", "Terabit"),
    ("Bytes/Second", "Kilobytes/Second"),
    ("Kilobytes/Second", "Megabytes/Second"),
    ("Megabytes/Second", "Gigabytes/Second"),
    ("Gigabytes/Second", "Terabytes/Second"),
    ("Bits/Second", "Kilobits/Second"),
    ("Kilobits/Second", "Megabits/Second"),
    ("Megabits/Second", "Gigabits/Second"),
    ("Gigabits/Second", "Terabits/Second"),
];

/// Short unit names used when pretty-printing a value.
const UNIT_SHORTHANDS: &[(&str, &str)] = &[
    ("Seconds", "s"),
    ("Microseconds", "μs"),
    ("Milliseconds", "ms"),
    ("Bytes", "B"),
    ("Kilobytes", "KB"),
    ("Megabytes", "MB"),
    ("Gigabytes", "GB"),
    ("Terabytes", "TB"),
    ("Bits", "Bit"),
    ("Kilobits", "KBit"),
    ("Megabits", "MBit"),
    ("Gigabits", "GBit"),
    ("Terabits", "TBit"),
    ("Percent", "%"),
    ("Count", ""),
    ("Bytes/Second", "B/s"),
    ("Kilobytes/Second", "KB/s"),
    ("Megabytes/Second", "MB/s"),
    ("Gigabytes/Second", "GB/s"),
    ("Terabytes/Second", "TB/s"),
    ("Bits/Second", "Bit/s"),
    ("Kilobits/Second", "KBit/s"),
    ("Megabits/Second", "MBit/s"),
    ("Gigabits/Second", "GBit/s"),
    ("Terabits/Second", "TBit/s"),
    ("Count/Second", "Hz"),
    ("None", ""),
];

/// A sorted dimension set, comparable and hashable (`frozenset(items())`).
type DimensionSet = Vec<(String, String)>;

/// One metric series: raw samples plus their CloudWatch unit.
#[derive(Debug, Clone, PartialEq)]
pub struct Series {
    pub values: Vec<f64>,
    pub unit: String,
}

/// Metrics of one dimension set.
pub type Metrics = BTreeMap<String, Series>;

/// All data collected for one revision.
pub type Data = BTreeMap<DimensionSet, Metrics>;

#[derive(Parser, Debug)]
#[command(
    name = "fc-ab-test",
    about = "Executes Firecracker's A/B testsuite across the specified commits"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// p-value threshold: a float, or `metric=float` for a per-metric override.
    #[arg(long = "significance", value_name = "VALUE")]
    significance: Vec<String>,
    /// Minimum absolute delta: a float, or `metric=float`.
    #[arg(long = "absolute-strength", value_name = "VALUE")]
    absolute_strength: Vec<String>,
    /// Minimal average relative delta: a float, or `metric=float`.
    #[arg(long = "noise-threshold", value_name = "VALUE")]
    noise_threshold: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run one of our tests as an A/B-test across two binary directories.
    Run {
        /// Directory containing the baseline `firecracker` and `jailer`.
        #[arg(long = "binaries-a")]
        binaries_a: PathBuf,
        /// Directory containing the candidate `firecracker` and `jailer`.
        #[arg(long = "binaries-b")]
        binaries_b: PathBuf,
        /// Artifacts directory (or S3 path) for revision A.
        #[arg(long = "artifacts-a")]
        artifacts_a: Option<String>,
        /// Artifacts directory (or S3 path) for revision B.
        #[arg(long = "artifacts-b")]
        artifacts_b: Option<String>,
        /// Parameters forwarded to pytest.
        #[arg(long = "pytest-opts")]
        pytest_opts: String,
        /// Maximum number of iterations; retried only when regressions show up.
        #[arg(long = "max-iterations", default_value_t = 1)]
        max_iterations: usize,
    },
    /// Analyze the metrics.json files of two manually run tests.
    Analyze {
        /// Directory holding run A's metrics.json files.
        path_a: PathBuf,
        /// Directory holding run B's metrics.json files.
        path_b: PathBuf,
    },
}

/// A threshold with optional per-metric overrides.
#[derive(Debug, Clone, PartialEq)]
pub struct Threshold {
    pub default: f64,
    pub overrides: BTreeMap<String, f64>,
}

impl Threshold {
    /// Threshold for a specific metric.
    pub fn get(&self, metric: &str) -> f64 {
        self.overrides.get(metric).copied().unwrap_or(self.default)
    }

    /// Parses a repeated `--flag` list such as `["0.05", "restore=0.1"]`.
    pub fn from_args(args: &[String], default: f64) -> Result<Self> {
        let mut value = default;
        let mut overrides = BTreeMap::new();
        for arg in args {
            match arg.rsplit_once('=') {
                Some((name, raw)) => {
                    let parsed: f64 = raw
                        .parse()
                        .with_context(|| format!("invalid threshold value in {arg:?}"))?;
                    overrides.insert(name.to_string(), parsed);
                }
                None => {
                    value = arg
                        .parse()
                        .with_context(|| format!("invalid threshold value in {arg:?}"))?;
                }
            }
        }
        Ok(Self {
            default: value,
            overrides,
        })
    }
}

/// Expresses `value` in the largest unit in which it stays `>= 1`.
pub fn reduce_value(mut value: f64, mut unit: &str) -> (f64, String) {
    let inverses: BTreeMap<&str, &str> = UNIT_REDUCTIONS
        .iter()
        .map(|(from, to)| (*to, *from))
        .collect();
    while value.abs() < 1.0 {
        match inverses.get(unit) {
            Some(bigger) => {
                value *= 1000.0;
                unit = bigger;
            }
            None => break,
        }
    }
    while value.abs() >= 1000.0 {
        match UNIT_REDUCTIONS.iter().find(|(from, _)| *from == unit) {
            Some((_, smaller)) => {
                value /= 1000.0;
                unit = smaller;
            }
            None => break,
        }
    }
    (value, unit.to_string())
}

/// Pretty prints a value with the largest sensible unit (`1MB`).
pub fn format_with_reduced_unit(value: f64, unit: &str) -> String {
    let (reduced, reduced_unit) = reduce_value(value, unit);
    let shorthand = UNIT_SHORTHANDS
        .iter()
        .find(|(name, _)| *name == reduced_unit)
        .map(|(_, short)| (*short).to_string())
        .unwrap_or(reduced_unit);
    format!("{reduced:.2}{shorthand}")
}

/// Dimensions/metrics the A/B runner deliberately ignores.
pub fn ignored_dimensions() -> Vec<BTreeMap<String, String>> {
    let mut ignored = vec![
        BTreeMap::from([
            ("fio_engine".to_string(), "libaio".to_string()),
            ("metric".to_string(), "clat_read".to_string()),
        ]),
        BTreeMap::from([
            ("fio_engine".to_string(), "libaio".to_string()),
            ("metric".to_string(), "clat_write".to_string()),
        ]),
        BTreeMap::from([
            ("performance_test".to_string(), "test_boottime".to_string()),
            ("metric".to_string(), "resume_time".to_string()),
        ]),
    ];
    for prefix in ["hotplug", "hotunplug", "hotplug_2nd"] {
        for metric in ["api_time", "fc_time"] {
            ignored.push(BTreeMap::from([
                (
                    "performance_test".to_string(),
                    "test_memory_hotplug_latency".to_string(),
                ),
                ("metric".to_string(), format!("{prefix}_{metric}")),
            ]));
        }
    }
    ignored
}

/// Whether `dimensions` match an entry of [`ignored_dimensions`].
pub fn is_ignored(
    dimensions: &BTreeMap<String, String>,
    ignored: &[BTreeMap<String, String>],
) -> bool {
    ignored.iter().any(|entry| {
        entry
            .iter()
            .all(|(key, value)| dimensions.get(key) == Some(value))
    })
}

/// Recursively collects `metrics.json` files under `data_path`.
pub fn load_data_series(data_path: &Path) -> Result<(Data, BTreeMap<DimensionSet, String>)> {
    let mut data = Data::new();
    let mut nodeids = BTreeMap::new();

    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(data_path)
        .follow_links(false)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == "metrics.json")
        .map(|entry| entry.into_path())
        .collect();
    files.sort();

    for file in files {
        let text = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        let document: Value =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;

        let dimensions: DimensionSet = document["dimensions"]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{}: missing dimensions", file.display()))?
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| value.to_string()),
                )
            })
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect();

        if let Some(nodeid) = document.get("nodeid").and_then(|v| v.as_str()) {
            nodeids.insert(dimensions.clone(), nodeid.to_string());
        }

        let mut metrics = Metrics::new();
        if let Some(entries) = document["metrics"].as_object() {
            for (name, metric) in entries {
                // Volatile, never compared.
                if name.contains("cpu_utilization") {
                    continue;
                }
                let values = metric["values"]
                    .as_array()
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| value.as_f64())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let unit = metric["unit"].as_str().unwrap_or("None").to_string();
                metrics.insert(name.clone(), Series { values, unit });
            }
        }
        data.insert(dimensions, metrics);
    }
    Ok((data, nodeids))
}

/// Dimensions that only ever take a single value across the dataset.
pub fn uninteresting_dimensions(data: &Data) -> BTreeSet<String> {
    let mut values: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for dimension_set in data.keys() {
        for (key, value) in dimension_set {
            values
                .entry(key.as_str())
                .or_default()
                .insert(value.as_str());
        }
    }
    values
        .into_iter()
        .filter(|(_, distinct)| distinct.len() == 1)
        .map(|(key, _)| key.to_string())
        .collect()
}

/// Result of the permutation regression test.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Regression {
    pub statistic: f64,
    pub pvalue: f64,
}

impl Regression {
    /// Whether the result clears the supplied thresholds.
    pub fn is_significant(&self, p_thresh: f64, strength_abs_thresh: f64) -> bool {
        self.pvalue < p_thresh && self.statistic.abs() > strength_abs_thresh
    }
}

/// Runs the difference-of-means permutation test (`scipy.stats.permutation_test`).
///
/// `statistic(x, y) = mean(y) - mean(x)`, so a positive statistic means the
/// candidate got slower/larger. The p-value is two-sided, matching scipy's
/// default, with the usual `+1` correction so it can never be zero.
pub fn check_regression(a_samples: &[f64], b_samples: &[f64], n_resamples: usize) -> Regression {
    let statistic = mean(b_samples) - mean(a_samples);
    let pooled: Vec<f64> = a_samples.iter().chain(b_samples).copied().collect();
    let n_a = a_samples.len();
    let total = pooled.len();

    let mut rng = StdRng::seed_from_u64(0x5eed_5eed);
    let mut extreme = 0usize;
    let mut permuted: Vec<f64> = pooled.clone();
    for _ in 0..n_resamples {
        // Fisher-Yates shuffle of the pooled sample.
        for index in (1..total).rev() {
            let swap = rng.gen_range(0..=index);
            permuted.swap(index, swap);
        }
        let perm_a = &permuted[..n_a];
        let perm_b = &permuted[n_a..];
        let perm_statistic = mean(perm_b) - mean(perm_a);
        if perm_statistic.abs() >= statistic.abs() {
            extreme += 1;
        }
    }
    let pvalue = (extreme + 1) as f64 / (n_resamples + 1) as f64;
    Regression { statistic, pvalue }
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

/// Analyzes the collected data, returning human-readable regression messages.
pub fn analyze_data(
    data_a: &Data,
    data_b: &Data,
    p_thresh: &Threshold,
    strength_abs_thresh: &Threshold,
    noise_threshold: &Threshold,
    n_resamples: usize,
) -> Result<Vec<String>> {
    if data_a.keys().collect::<Vec<_>>() != data_b.keys().collect::<Vec<_>>() {
        bail!("A and B run produced incomparable data. This is a bug in the test!");
    }

    let ignored = ignored_dimensions();
    let mut results: BTreeMap<(DimensionSet, String), (Regression, String)> = BTreeMap::new();
    for (dimension_set, metrics_a) in data_a {
        let metrics_b = &data_b[dimension_set];
        if metrics_a.keys().collect::<Vec<_>>() != metrics_b.keys().collect::<Vec<_>>() {
            bail!("A and B run produced incomparable data. This is a bug in the test!");
        }
        for (metric, series_a) in metrics_a {
            let regression =
                check_regression(&series_a.values, &metrics_b[metric].values, n_resamples);
            results.insert(
                (dimension_set.clone(), metric.clone()),
                (regression, series_a.unit.clone()),
            );
        }
    }

    // Every per-metric override must refer to a metric we actually collected.
    let all_metrics: BTreeSet<&String> = results.keys().map(|(_, metric)| metric).collect();
    for threshold in [p_thresh, strength_abs_thresh, noise_threshold] {
        let unknown: Vec<&String> = threshold
            .overrides
            .keys()
            .filter(|name| !all_metrics.contains(name))
            .collect();
        if !unknown.is_empty() {
            bail!("Per-metric overrides refer to unknown metrics: {unknown:?}");
        }
    }

    let mut relative_changes_by_metric: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut relative_changes_significant: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut failures: Vec<(DimensionSet, String, Regression, String)> = Vec::new();

    for ((dimension_set, metric), (regression, unit)) in &results {
        let mut dimensions: BTreeMap<String, String> = dimension_set.iter().cloned().collect();
        dimensions.insert("metric".to_string(), metric.clone());
        if is_ignored(&dimensions, &ignored) {
            continue;
        }
        let baseline_mean = mean(&data_a[dimension_set][metric].values);
        relative_changes_by_metric
            .entry(metric.clone())
            .or_default()
            .push(regression.statistic / baseline_mean);

        if regression.is_significant(p_thresh.get(metric), strength_abs_thresh.get(metric)) {
            relative_changes_significant
                .entry(metric.clone())
                .or_default()
                .push(regression.statistic / baseline_mean);
            failures.push((
                dimension_set.clone(),
                metric.clone(),
                *regression,
                unit.clone(),
            ));
        }
    }

    let mut messages = Vec::new();
    let do_not_print = uninteresting_dimensions(data_a);
    for (dimension_set, metric, regression, unit) in failures {
        let Some(significant_changes) = relative_changes_significant.get(&metric) else {
            continue;
        };
        let relative_change = mean(&relative_changes_by_metric[&metric]);
        let relative_change_significant = mean(significant_changes);
        if relative_change.abs() <= noise_threshold.get(&metric)
            || relative_change_significant.abs() <= noise_threshold.get(&metric)
        {
            continue;
        }
        let old_mean = mean(&data_a[&dimension_set][&metric].values);
        let new_mean = mean(&data_b[&dimension_set][&metric].values);
        let printed: BTreeMap<&String, &String> = dimension_set
            .iter()
            .filter(|(key, _)| !do_not_print.contains(key))
            .map(|(key, value)| (key, value))
            .collect();
        messages.push(format!(
            "\u{1b}[0;32m[Firecracker A/B-Test Runner]\u{1b}[0m A/B-testing shows a change of {}, or {:.2}%, \
(from {} to {}) for metric \u{1b}[1m{metric}\u{1b}[0m with \u{1b}[0;31m\u{1b}[1mp={}\u{1b}[0m. \
This means that observing a change of this magnitude or worse, assuming that performance characteristics \
did not change across the tested commits, has a probability of {:.2}%. Tested Dimensions:\n{}",
            format_with_reduced_unit(regression.statistic, &unit),
            regression.statistic / old_mean * 100.0,
            format_with_reduced_unit(old_mean, &unit),
            format_with_reduced_unit(new_mean, &unit),
            regression.pvalue,
            regression.pvalue * 100.0,
            serde_json::to_string_pretty(&printed)?,
        ));
    }
    Ok(messages)
}

/// Merges `new_data` into `accumulated` by appending each metric's samples.
pub fn merge_data(accumulated: &mut Data, new_data: Data) {
    for (dimension_set, metrics) in new_data {
        let entry = accumulated.entry(dimension_set).or_default();
        for (metric, series) in metrics {
            match entry.get_mut(&metric) {
                Some(existing) => existing.values.extend(series.values),
                None => {
                    entry.insert(metric, series);
                }
            }
        }
    }
}

/// Runs the A/B test, retrying only the regressing test cases.
#[allow(clippy::too_many_arguments)]
pub fn ab_performance_test(
    a_directory: &Path,
    b_directory: &Path,
    a_artifacts: Option<&str>,
    b_artifacts: Option<&str>,
    pytest_opts: &str,
    p_thresh: &Threshold,
    strength_abs_thresh: &Threshold,
    noise_threshold: &Threshold,
    max_iterations: usize,
    n_resamples: usize,
) -> Result<()> {
    let mut data_a = Data::new();
    let mut data_b = Data::new();
    let mut nodeids: BTreeMap<DimensionSet, String> = BTreeMap::new();
    let mut error_messages: Vec<String> = Vec::new();
    let mut retry_nodeids: Option<Vec<String>> = None;

    for iteration in 0..max_iterations {
        println!("\n=== Iteration {}/{} ===", iteration + 1, max_iterations);
        let (new_a, new_b) = if iteration % 2 == 0 {
            let a = collect_data(
                "A",
                a_directory,
                a_artifacts,
                pytest_opts,
                iteration,
                retry_nodeids.as_deref(),
            )?;
            let b = collect_data(
                "B",
                b_directory,
                b_artifacts,
                pytest_opts,
                iteration,
                retry_nodeids.as_deref(),
            )?;
            (a, b)
        } else {
            let b = collect_data(
                "B",
                b_directory,
                b_artifacts,
                pytest_opts,
                iteration,
                retry_nodeids.as_deref(),
            )?;
            let a = collect_data(
                "A",
                a_directory,
                a_artifacts,
                pytest_opts,
                iteration,
                retry_nodeids.as_deref(),
            )?;
            (a, b)
        };

        let (data, nodeids_a) = new_a;
        let (data_b_new, nodeids_b) = new_b;
        merge_data(&mut data_a, data);
        merge_data(&mut data_b, data_b_new);
        nodeids.extend(nodeids_a);
        nodeids.extend(nodeids_b);

        error_messages = analyze_data(
            &data_a,
            &data_b,
            p_thresh,
            strength_abs_thresh,
            noise_threshold,
            n_resamples,
        )?;
        if error_messages.is_empty() {
            println!("No regressions detected!");
            return Ok(());
        }
        if iteration < max_iterations - 1 {
            println!(
                "{} regression(s) detected as of iteration {}/{}:",
                error_messages.len(),
                iteration + 1,
                max_iterations
            );
            println!("{}", error_messages.join("\n"));

            let failing: HashSet<&DimensionSet> = data_a
                .keys()
                .filter(|dimension_set| nodeids.contains_key(*dimension_set))
                .collect();
            let missing: Vec<&DimensionSet> = failing
                .iter()
                .filter(|dimension_set| !nodeids.contains_key(**dimension_set))
                .copied()
                .collect();
            if !missing.is_empty() {
                println!(
                    "Could not determine the pytest node id for every failing test case; \
re-running the full selection."
                );
                retry_nodeids = None;
            } else {
                let mut selected: Vec<String> = failing
                    .iter()
                    .filter_map(|dimension_set| nodeids.get(*dimension_set).cloned())
                    .collect();
                selected.sort();
                selected.dedup();
                println!(
                    "Retrying {} failing test case(s) to collect more data...",
                    selected.len()
                );
                retry_nodeids = Some(selected);
            }
        }
    }

    if error_messages.is_empty() {
        return Ok(());
    }
    bail!("{}", error_messages.join("\n"))
}

/// Runs the selected tests once for one revision and loads the resulting data.
fn collect_data(
    tag: &str,
    binary_dir: &Path,
    artifacts: Option<&str>,
    pytest_opts: &str,
    iteration: usize,
    nodeids: Option<&[String]>,
) -> Result<(Data, BTreeMap<DimensionSet, String>)> {
    let binary_dir = binary_dir
        .canonicalize()
        .unwrap_or_else(|_| binary_dir.to_path_buf());
    match artifacts {
        Some(artifacts) => println!(
            "Collecting samples | binaries path: {} | artifacts path: {artifacts}",
            binary_dir.display()
        ),
        None => println!(
            "Collecting samples | binaries path: {}",
            binary_dir.display()
        ),
    }

    let test_path = format!("test_results/{tag}/{iteration}");
    let report_path = format!("{test_path}/test-report.json");
    let _ = std::fs::remove_dir_all(&test_path);

    if let Some(artifacts) = artifacts {
        utils::check_output(&format!(
            "./tools/devtool set_current_artifacts {artifacts}"
        ))?;
    }

    let selection = match nodeids {
        Some(nodeids) if !nodeids.is_empty() => nodeids
            .iter()
            .map(|nodeid| shell_quote(nodeid))
            .collect::<Vec<_>>()
            .join(" "),
        _ => pytest_opts.to_string(),
    };

    let workspace = defs::workspace_dir();
    let command = format!(
        "cd {} && ./tools/test.sh --binary-dir={} {} -m '' --json-report-file=../{report_path}",
        shell_quote(&workspace.to_string_lossy()),
        shell_quote(&binary_dir.to_string_lossy()),
        selection
    );
    utils::check_output(&command)?;

    load_data_series(Path::new(&test_path))
}

fn shell_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._/:=@,+[]".contains(&byte));
    if safe {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let p_thresh = Threshold::from_args(&cli.significance, 0.01)?;
    let strength_abs_thresh = Threshold::from_args(&cli.absolute_strength, 0.0)?;
    let noise_threshold = Threshold::from_args(&cli.noise_threshold, 0.05)?;

    match cli.command {
        Command::Run {
            binaries_a,
            binaries_b,
            artifacts_a,
            artifacts_b,
            pytest_opts,
            max_iterations,
        } => {
            let started = Instant::now();
            ab_performance_test(
                &binaries_a,
                &binaries_b,
                artifacts_a.as_deref(),
                artifacts_b.as_deref(),
                &pytest_opts,
                &p_thresh,
                &strength_abs_thresh,
                &noise_threshold,
                max_iterations,
                9999,
            )?;
            println!(
                "Total A/B test took {:.2}s",
                started.elapsed().as_secs_f64()
            );
        }
        Command::Analyze { path_a, path_b } => {
            let started = Instant::now();
            let (data_a, _) = load_data_series(&path_a)?;
            let (data_b, _) = load_data_series(&path_b)?;
            println!("Data loading took {:.2}s", started.elapsed().as_secs_f64());

            let started = Instant::now();
            let error_messages = analyze_data(
                &data_a,
                &data_b,
                &p_thresh,
                &strength_abs_thresh,
                &noise_threshold,
                9999,
            )?;
            println!("Analysis took {:.2}s", started.elapsed().as_secs_f64());
            if !error_messages.is_empty() {
                bail!("{}", error_messages.join("\n"));
            }
            println!("No regressions detected!");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reduce_value_picks_the_largest_unit() {
        assert_eq!(
            reduce_value(1_000_000.0, "Bytes"),
            (1.0, "Megabytes".into())
        );
        assert_eq!(reduce_value(0.5, "Seconds"), (500.0, "Milliseconds".into()));
        assert_eq!(
            reduce_value(1500.0, "Microseconds"),
            (1.5, "Milliseconds".into())
        );
        assert_eq!(reduce_value(7.0, "Count"), (7.0, "Count".into()));
    }

    #[test]
    fn format_with_reduced_unit_uses_shorthands() {
        assert_eq!(format_with_reduced_unit(1_000_000.0, "Bytes"), "1.00MB");
        assert_eq!(format_with_reduced_unit(2_500.0, "Microseconds"), "2.50ms");
        assert_eq!(format_with_reduced_unit(3.0, "Count"), "3.00");
        assert_eq!(
            format_with_reduced_unit(12.0, "Interrupts"),
            "12.00Interrupts"
        );
    }

    #[test]
    fn thresholds_parse_defaults_and_overrides() {
        let threshold =
            Threshold::from_args(&["0.05".into(), "restore_latency=0.1".into()], 0.01).unwrap();
        assert_eq!(threshold.get("anything"), 0.05);
        assert_eq!(threshold.get("restore_latency"), 0.1);
        assert!(Threshold::from_args(&["nope".into()], 0.01).is_err());
    }

    #[test]
    fn ignored_dimensions_match_python_table() {
        let ignored = ignored_dimensions();
        // 3 fixed entries + 3 prefixes * 2 metrics.
        assert_eq!(ignored.len(), 9);
        assert!(is_ignored(
            &BTreeMap::from([
                ("fio_engine".to_string(), "libaio".to_string()),
                ("metric".to_string(), "clat_read".to_string()),
            ]),
            &ignored
        ));
        assert!(is_ignored(
            &BTreeMap::from([
                (
                    "performance_test".to_string(),
                    "test_memory_hotplug_latency".to_string()
                ),
                ("metric".to_string(), "hotunplug_fc_time".to_string()),
            ]),
            &ignored
        ));
        assert!(!is_ignored(
            &BTreeMap::from([("metric".to_string(), "clat_read".to_string())]),
            &ignored
        ));
    }

    fn write_metrics(dir: &Path, name: &str, document: Value) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), serde_json::to_string(&document).unwrap()).unwrap();
    }

    #[test]
    fn load_data_series_reads_nested_metrics() {
        let dir = std::env::temp_dir().join(format!("fc-ab-load-{}", std::process::id()));
        let nested = dir.join("a/b");
        write_metrics(
            &nested,
            "metrics.json",
            json!({
                "dimensions": {"performance_test": "test_boottime", "vcpus": "2"},
                "metrics": {
                    "boot_time": {"unit": "Milliseconds", "values": [1.0, 2.0]},
                    "cpu_utilization_vmm": {"unit": "Percent", "values": [50.0]},
                },
                "nodeid": "test_boottime[2]",
            }),
        );

        let (data, nodeids) = load_data_series(&dir).unwrap();
        assert_eq!(data.len(), 1);
        let (dimension_set, metrics) = data.iter().next().unwrap();
        assert_eq!(
            dimension_set,
            &vec![
                ("performance_test".to_string(), "test_boottime".to_string()),
                ("vcpus".to_string(), "2".to_string()),
            ]
        );
        // cpu_utilization metrics are skipped.
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics["boot_time"].unit, "Milliseconds");
        assert_eq!(metrics["boot_time"].values, vec![1.0, 2.0]);
        assert_eq!(nodeids[dimension_set], "test_boottime[2]");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn permutation_test_separates_shifted_populations() {
        let a = vec![10.0, 10.1, 9.9, 10.2, 9.8];
        let b = vec![20.0, 20.1, 19.9, 20.2, 19.8];
        let regression = check_regression(&a, &b, 999);
        assert!(regression.statistic > 9.0, "{regression:?}");
        assert!(regression.pvalue < 0.05, "{regression:?}");
    }

    #[test]
    fn permutation_test_cannot_distinguish_identical_populations() {
        let a = vec![10.0, 10.1, 9.9, 10.2, 9.8];
        let b = a.clone();
        let regression = check_regression(&a, &b, 999);
        assert!(regression.statistic.abs() < f64::EPSILON);
        assert!(regression.pvalue > 0.9, "{regression:?}");
    }

    fn data_with(metric: &str, values: Vec<f64>) -> Data {
        let dimension_set: DimensionSet = vec![
            ("performance_test".to_string(), "test_x".to_string()),
            ("vcpus".to_string(), "2".to_string()),
        ];
        let mut metrics = Metrics::new();
        metrics.insert(
            metric.to_string(),
            Series {
                values,
                unit: "Milliseconds".to_string(),
            },
        );
        Data::from([(dimension_set, metrics)])
    }

    #[test]
    fn analyze_data_flags_a_real_regression() {
        let a = data_with("restore_latency", vec![10.0, 10.1, 9.9, 10.2, 9.8, 10.0]);
        let b = data_with("restore_latency", vec![20.0, 20.1, 19.9, 20.2, 19.8, 20.0]);
        let default = Threshold {
            default: 0.01,
            overrides: BTreeMap::new(),
        };
        let strength = Threshold {
            default: 0.0,
            overrides: BTreeMap::new(),
        };
        let noise = Threshold {
            default: 0.05,
            overrides: BTreeMap::new(),
        };
        let messages = analyze_data(&a, &b, &default, &strength, &noise, 999).unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("restore_latency"), "{}", messages[0]);
        assert!(messages[0].contains("100.00%"), "{}", messages[0]);

        // The same data compared against itself is never a regression.
        let messages = analyze_data(&a, &a, &default, &strength, &noise, 999).unwrap();
        assert!(messages.is_empty());
    }

    #[test]
    fn analyze_data_rejects_mismatched_datasets() {
        let a = data_with("restore_latency", vec![1.0]);
        let b = data_with("other_metric", vec![1.0]);
        let default = Threshold {
            default: 0.01,
            overrides: BTreeMap::new(),
        };
        let err = analyze_data(&a, &b, &default, &default, &default, 99)
            .unwrap_err()
            .to_string();
        assert!(err.contains("incomparable data"), "{err}");
    }

    #[test]
    fn analyze_data_rejects_unknown_overrides() {
        let a = data_with("restore_latency", vec![1.0]);
        let thresholds = Threshold {
            default: 0.01,
            overrides: BTreeMap::from([("nope".to_string(), 0.1)]),
        };
        let err = analyze_data(&a, &a, &thresholds, &thresholds, &thresholds, 99)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown metrics"), "{err}");
    }

    #[test]
    fn merge_data_appends_samples() {
        let mut accumulated = data_with("latency", vec![1.0]);
        merge_data(&mut accumulated, data_with("latency", vec![2.0, 3.0]));
        let series = &accumulated.values().next().unwrap()["latency"];
        assert_eq!(series.values, vec![1.0, 2.0, 3.0]);
    }

    #[test]
    fn uninteresting_dimensions_detects_constant_values() {
        let mut data = data_with("latency", vec![1.0]);
        let second: DimensionSet = vec![
            ("performance_test".to_string(), "test_y".to_string()),
            ("vcpus".to_string(), "2".to_string()),
        ];
        data.insert(second, Metrics::new());
        let uninteresting = uninteresting_dimensions(&data);
        assert!(uninteresting.contains("vcpus"));
        assert!(!uninteresting.contains("performance_test"));
    }

    #[test]
    fn shell_quote_keeps_nodeids_and_protects_spaces() {
        assert_eq!(
            shell_quote("tests/test.py::test_x[vmlinux-6.1.168]"),
            "tests/test.py::test_x[vmlinux-6.1.168]"
        );
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
