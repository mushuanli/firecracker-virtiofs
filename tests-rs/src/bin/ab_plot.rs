// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust port of `tools/ab_plot.py`.
//!
//! The python script renders A/B test results with `matplotlib`/`seaborn`. This
//! port keeps the data pipeline (recursively collect `metrics.json` files,
//! aggregate each metric per group, compute the deltas against group A) and
//! emits a self-contained SVG document written by hand, so no charting crate is
//! needed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;

/// File name collected recursively from each data directory.
const METRICS_FILE: &str = "metrics.json";

/// Dimensions that are host specific and would prevent comparing hosts.
const HOST_DIMENSIONS: [&str; 3] = ["instance", "cpu_model", "host_kernel"];

/// Stroke colours cycled over the series of one panel.
const PALETTE: [&str; 8] = [
    "#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e", "#17becf", "#8c564b", "#7f7f7f",
];

/// Total width of the produced SVG, in user units.
const SVG_WIDTH: f64 = 1000.0;

/// Height of one metric panel, in user units.
const PANEL_HEIGHT: f64 = 210.0;

/// Vertical space reserved for the document title.
const TOP_MARGIN: f64 = 70.0;

/// Left edge of the plot area.
const PLOT_LEFT: f64 = 84.0;

/// Right edge of the plot area.
const PLOT_RIGHT: f64 = 660.0;

/// Offset of the plot area from the top of its panel.
const PLOT_TOP_OFFSET: f64 = 34.0;

/// Offset of the plot area bottom from the top of its panel.
const PLOT_BOTTOM_OFFSET: f64 = 46.0;

/// Left edge of the legend column.
const LEGEND_LEFT: f64 = 686.0;

/// Command line arguments. The positional `paths` and `--errorbar` /
/// `--output_type` flags mirror `ab_plot.py`; `--data-dir` and `--output` are
/// additions of this port.
#[derive(Debug, Parser)]
#[command(
    name = "fc-ab-plot",
    about = "Plot the results of Firecracker's A/B testsuite as a single SVG"
)]
struct Cli {
    /// Paths to directories with test runs' metrics.json file (group A, B, C...).
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Data directory, repeatable alternative to the positional paths.
    #[arg(long = "data-dir", value_name = "DIR")]
    data_dirs: Vec<PathBuf>,

    /// Where to write the resulting SVG plot.
    #[arg(long = "output", value_name = "FILE", default_value = "ab_plot.svg")]
    output: PathBuf,

    /// Errorbar configuration (type, value), accepted for CLI parity with the
    /// python script and recorded in the plot footer.
    #[arg(
        long = "errorbar",
        num_args = 2,
        value_names = ["TYPE", "VALUE"],
        default_values = ["pi", "95"]
    )]
    errorbar: Vec<String>,

    /// Type of the output to generate. Only `svg` is implemented.
    #[arg(long = "output_type", default_value = "svg")]
    output_type: String,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(&cli) {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}

/// Runs the whole pipeline: load, aggregate, render, write.
fn run(cli: &Cli) -> Result<()> {
    if cli.output_type != "svg" {
        bail!(
            "unsupported --output_type '{}': this port only writes 'svg'",
            cli.output_type
        );
    }

    let mut dirs = cli.paths.clone();
    dirs.extend(cli.data_dirs.iter().cloned());
    if dirs.is_empty() {
        bail!("no data directories given; pass them positionally or with --data-dir");
    }

    // Data retrieval.
    let start = Instant::now();
    let mut all_samples = Vec::new();
    for (index, path) in dirs.iter().enumerate() {
        let group = group_label(index)?;
        let samples = load_samples(path, group)?;
        println!(
            "getting data {index} from {}: {}",
            path.display(),
            samples.len()
        );
        all_samples.extend(samples);
    }
    println!("Data retrieval: {:.2}s", start.elapsed().as_secs_f64());

    // Data processing.
    let start = Instant::now();
    let series = group_series(&all_samples);
    let aggregates = aggregate(&series, group_label(0)?);
    println!("Data processing: {:.2}s", start.elapsed().as_secs_f64());

    // Plotting.
    let start = Instant::now();
    let subtitle = format!(
        "errorbar={} {}",
        cli.errorbar.first().map(String::as_str).unwrap_or("pi"),
        cli.errorbar.get(1).map(String::as_str).unwrap_or("95")
    );
    let svg = render_svg(&series, &aggregates, "Firecracker A/B plot", &subtitle);
    write_svg(&cli.output, &svg)?;
    println!("Ready: {}", cli.output.display());
    println!("Plotting: {:.2}s", start.elapsed().as_secs_f64());

    Ok(())
}

/// Maps a zero-based group index to its label (`A`, `B`, `C`, ...).
pub fn group_label(index: usize) -> Result<char> {
    let label = char::from(b'A' + u8::try_from(index).context("group index out of range")?);
    if !label.is_ascii_uppercase() {
        bail!("too many groups: {index}");
    }
    Ok(label)
}

/// Identifies one plot panel: the performance test, the metric and the
/// dimension set the samples were collected with.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PanelKey {
    /// Performance test name (`dimensions.performance_test`).
    pub test: String,
    /// Metric name.
    pub metric: String,
    /// Remaining dimensions, sorted by name.
    pub dimensions: Vec<(String, String)>,
}

/// One metric as found in a `metrics.json` file or a CSV file.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricRecord {
    /// Performance test name.
    pub test: String,
    /// Metric name.
    pub metric: String,
    /// Unit reported by the test (e.g. `ms`).
    pub unit: String,
    /// Raw sample values.
    pub values: Vec<f64>,
    /// Dimension set, sorted by name, host-specific dimensions removed.
    pub dimensions: Vec<(String, String)>,
}

/// One sample of one metric in one group.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Cumulative iteration index within the panel, used as the x axis.
    pub index: usize,
    /// Panel this sample belongs to.
    pub key: PanelKey,
    /// Unit reported by the test.
    pub unit: String,
    /// Measured value.
    pub value: f64,
    /// Group label (`A`, `B`, ...).
    pub group: char,
}

/// All samples of one (panel, group) pair, ordered by iteration index.
#[derive(Debug, Clone, PartialEq)]
pub struct PlotSeries {
    /// Panel this series belongs to.
    pub key: PanelKey,
    /// Unit reported by the test.
    pub unit: String,
    /// Group label (`A`, `B`, ...).
    pub group: char,
    /// `(index, value)` pairs, ascending.
    pub samples: Vec<(usize, f64)>,
}

/// Aggregated statistics of one series plus its delta against the baseline.
#[derive(Debug, Clone, PartialEq)]
pub struct SeriesAggregate {
    /// Group label (`A`, `B`, ...).
    pub group: char,
    /// Number of samples.
    pub count: usize,
    /// 50th percentile, `None` when the series is empty.
    pub p50: Option<f64>,
    /// 90th percentile, `None` when the series is empty.
    pub p90: Option<f64>,
    /// Percent change of `p50` against the baseline group.
    pub delta_p50_pct: Option<f64>,
    /// Percent change of `p90` against the baseline group.
    pub delta_p90_pct: Option<f64>,
}

/// Collects the data files (`metrics.json` and `*.csv`) below `root`.
pub fn collect_data_files(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        bail!("data directory {} does not exist", root.display());
    }

    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.with_context(|| format!("failed to walk {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let is_metrics = entry.file_name().to_str() == Some(METRICS_FILE);
        let is_csv = entry
            .path()
            .extension()
            .map(|extension| extension == "csv")
            .unwrap_or(false);
        if is_metrics || is_csv {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

/// Loads every data file below `data_path` into samples tagged with `group`.
///
/// Mirrors `load_data` in `ab_plot.py`: the offsets of the cumulative sample
/// index are tracked per panel, so consecutive files continue the same x axis.
pub fn load_samples(data_path: &Path, group: char) -> Result<Vec<Sample>> {
    let mut offsets: BTreeMap<PanelKey, usize> = BTreeMap::new();
    let mut samples = Vec::new();

    for file in collect_data_files(data_path)? {
        let text = std::fs::read_to_string(&file)
            .with_context(|| format!("failed to read {}", file.display()))?;

        if file.file_name().and_then(|name| name.to_str()) == Some(METRICS_FILE) {
            let document: serde_json::Value = serde_json::from_str(&text)
                .with_context(|| format!("failed to parse {}", file.display()))?;
            match records_from_metrics_json(&document)? {
                Some(records) => {
                    samples.extend(samples_from_records(&records, group, &mut offsets))
                }
                None => println!("skipping: {}", file.display()),
            }
        } else {
            let records = records_from_csv(&text)
                .with_context(|| format!("failed to parse {}", file.display()))?;
            samples.extend(samples_from_records(&records, group, &mut offsets));
        }
    }

    Ok(samples)
}

/// Extracts the metric records of one `metrics.json` document.
///
/// Returns `None` when the document has no `performance_test` dimension, which
/// the python script skips as well.
pub fn records_from_metrics_json(
    document: &serde_json::Value,
) -> Result<Option<Vec<MetricRecord>>> {
    let dimensions = document
        .get("dimensions")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow!("metrics document has no 'dimensions' object"))?;

    let Some(performance_test) = dimensions
        .get("performance_test")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };

    let mut kept: Vec<(String, String)> = Vec::new();
    for (name, value) in dimensions {
        if name == "performance_test" || HOST_DIMENSIONS.contains(&name.as_str()) {
            continue;
        }
        let value = match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        kept.push((name.clone(), value));
    }
    kept.sort();

    let metrics = document
        .get("metrics")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow!("metrics document has no 'metrics' object"))?;

    let mut records = Vec::new();
    for (name, metric) in metrics {
        // Volatile by construction, the python script ignores these too.
        if name.contains("cpu_utilization") {
            continue;
        }

        let unit = metric
            .get("unit")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let values = metric
            .get("values")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow!("metric '{name}' has no 'values' array"))?
            .iter()
            .map(|value| {
                value
                    .as_f64()
                    .ok_or_else(|| anyhow!("metric '{name}' has a non-numeric value"))
            })
            .collect::<Result<Vec<f64>>>()?;

        records.push(MetricRecord {
            test: performance_test.to_string(),
            metric: name.clone(),
            unit,
            values,
            dimensions: kept.clone(),
        });
    }

    records.sort_by(|left, right| left.metric.cmp(&right.metric));
    Ok(Some(records))
}

/// Parses a flat A/B CSV export.
///
/// The header must contain `test`, `metric` and `value`; `unit` is optional and
/// every remaining column is treated as a dimension. Rows of the same
/// (test, metric, unit, dimensions) tuple are folded into one record.
///
/// A `group` column is ignored: the group of a data set comes from its position
/// on the command line (`A`, `B`, ...), and honouring the column would split
/// every group into its own panel. Host specific columns are dropped as well.
pub fn records_from_csv(text: &str) -> Result<Vec<MetricRecord>> {
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| anyhow!("empty CSV file"))?
        .to_string();
    let columns: Vec<String> = header
        .split(',')
        .map(|name| name.trim().to_string())
        .collect();
    let column = |name: &str| -> Option<usize> {
        columns
            .iter()
            .position(|candidate| candidate.eq_ignore_ascii_case(name))
    };

    let test_column = column("test").ok_or_else(|| anyhow!("CSV header has no 'test' column"))?;
    let metric_column =
        column("metric").ok_or_else(|| anyhow!("CSV header has no 'metric' column"))?;
    let value_column =
        column("value").ok_or_else(|| anyhow!("CSV header has no 'value' column"))?;
    let unit_column = column("unit");
    let group_column = column("group");

    let mut grouped: BTreeMap<(String, String, String, Vec<(String, String)>), Vec<f64>> =
        BTreeMap::new();

    for (offset, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let cells: Vec<&str> = line.split(',').map(|cell| cell.trim()).collect();
        let cell = |index: usize| cells.get(index).copied().unwrap_or_default();

        let value: f64 = cell(value_column).parse().with_context(|| {
            format!(
                "invalid value '{}' on CSV line {}",
                cell(value_column),
                offset + 2
            )
        })?;

        let mut dimensions = Vec::new();
        for (index, name) in columns.iter().enumerate() {
            if index == test_column
                || index == metric_column
                || index == value_column
                || Some(index) == unit_column
                || Some(index) == group_column
                || HOST_DIMENSIONS.contains(&name.to_lowercase().as_str())
            {
                continue;
            }
            let dimension_value = cell(index);
            if !dimension_value.is_empty() {
                dimensions.push((name.to_lowercase(), dimension_value.to_string()));
            }
        }
        dimensions.sort();

        let unit = unit_column.map(cell).unwrap_or_default().to_string();
        grouped
            .entry((
                cell(test_column).to_string(),
                cell(metric_column).to_string(),
                unit,
                dimensions,
            ))
            .or_default()
            .push(value);
    }

    Ok(grouped
        .into_iter()
        .map(|((test, metric, unit, dimensions), values)| MetricRecord {
            test,
            metric,
            unit,
            values,
            dimensions,
        })
        .collect())
}

/// Turns metric records into samples, continuing the per-panel index.
pub fn samples_from_records(
    records: &[MetricRecord],
    group: char,
    offsets: &mut BTreeMap<PanelKey, usize>,
) -> Vec<Sample> {
    let mut samples = Vec::new();

    for record in records {
        let key = PanelKey {
            test: record.test.clone(),
            metric: record.metric.clone(),
            dimensions: record.dimensions.clone(),
        };
        let offset = offsets.entry(key.clone()).or_insert(0);

        for (position, value) in record.values.iter().enumerate() {
            samples.push(Sample {
                index: *offset + position,
                key: key.clone(),
                unit: record.unit.clone(),
                value: *value,
                group,
            });
        }

        *offset += record.values.len();
    }

    samples
}

/// The 50th percentile of `values`, using linear interpolation like
/// `numpy.percentile`.
pub fn p50(values: &[f64]) -> Option<f64> {
    percentile(values, 50.0)
}

/// The 90th percentile of `values`, using linear interpolation like
/// `numpy.percentile`.
pub fn p90(values: &[f64]) -> Option<f64> {
    percentile(values, 90.0)
}

/// The `pct` percentile of `values`, using linear interpolation.
pub fn percentile(values: &[f64], pct: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }

    let mut sorted: Vec<f64> = values.to_vec();
    sorted.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));

    let last = (sorted.len() - 1) as f64;
    let position = last * (pct.clamp(0.0, 100.0) / 100.0);
    let lower = position.floor();
    let upper = position.ceil();
    let lower_value = sorted[lower as usize];
    let upper_value = sorted[upper as usize];

    if upper == lower {
        Some(lower_value)
    } else {
        Some(lower_value + (upper_value - lower_value) * (position - lower))
    }
}

/// Groups samples into one series per (panel, group), both sorted.
pub fn group_series(samples: &[Sample]) -> Vec<PlotSeries> {
    let mut grouped: BTreeMap<(PanelKey, char), (String, Vec<(usize, f64)>)> = BTreeMap::new();

    for sample in samples {
        let entry = grouped
            .entry((sample.key.clone(), sample.group))
            .or_insert_with(|| (sample.unit.clone(), Vec::new()));
        entry.1.push((sample.index, sample.value));
    }

    grouped
        .into_iter()
        .map(|((key, group), (unit, mut samples))| {
            samples.sort_by_key(|(index, _)| *index);
            PlotSeries {
                key,
                unit,
                group,
                samples,
            }
        })
        .collect()
}

/// Computes `p50`/`p90` per series plus the percent delta of each series against
/// the series of `baseline` group in the same panel.
///
/// The result is index-aligned with `series`.
pub fn aggregate(series: &[PlotSeries], baseline: char) -> Vec<SeriesAggregate> {
    let stats: Vec<(Option<f64>, Option<f64>)> = series
        .iter()
        .map(|entry| {
            let values: Vec<f64> = entry.samples.iter().map(|(_, value)| *value).collect();
            (p50(&values), p90(&values))
        })
        .collect();

    series
        .iter()
        .enumerate()
        .map(|(position, entry)| {
            let (p50_value, p90_value) = stats[position];
            let baseline_position = series
                .iter()
                .position(|candidate| candidate.group == baseline && candidate.key == entry.key);
            let baseline_stats = baseline_position.and_then(|index| stats.get(index).copied());

            SeriesAggregate {
                group: entry.group,
                count: entry.samples.len(),
                p50: p50_value,
                p90: p90_value,
                delta_p50_pct: relative_delta(p50_value, baseline_stats.and_then(|s| s.0)),
                delta_p90_pct: relative_delta(p90_value, baseline_stats.and_then(|s| s.1)),
            }
        })
        .collect()
}

/// Percent change of `value` against `baseline`, `None` when it cannot be given.
pub fn relative_delta(value: Option<f64>, baseline: Option<f64>) -> Option<f64> {
    let baseline = baseline?;
    let value = value?;
    if baseline == 0.0 {
        return None;
    }
    Some((value - baseline) / baseline * 100.0)
}

/// Groups the series by panel, keeping the sorted panel order.
pub fn panel_groups(series: &[PlotSeries]) -> Vec<(PanelKey, Vec<usize>)> {
    let mut panels: BTreeMap<PanelKey, Vec<usize>> = BTreeMap::new();
    for (index, entry) in series.iter().enumerate() {
        panels.entry(entry.key.clone()).or_default().push(index);
    }
    panels.into_iter().collect()
}

/// Escapes the five XML predefined entities.
pub fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Formats a metric value compactly for axis and legend labels.
pub fn format_value(value: f64) -> String {
    format_axis_value(value, value.abs())
}

/// Formats `value` with the precision implied by `magnitude`.
///
/// All the labels of one panel use the same magnitude, so `900.0`, `1050.0` and
/// `1200.0` render as `900`, `1050` and `1200` instead of mixing precisions.
pub fn format_axis_value(value: f64, magnitude: f64) -> String {
    if !value.is_finite() {
        return "n/a".to_string();
    }
    if magnitude >= 1000.0 {
        format!("{value:.0}")
    } else if magnitude >= 100.0 {
        format!("{value:.1}")
    } else if magnitude >= 10.0 {
        format!("{value:.2}")
    } else {
        format!("{value:.3}")
    }
}

/// Formats an optional relative delta as `+1.2%` / `-3.4%`.
pub fn format_delta(delta: Option<f64>) -> String {
    match delta {
        Some(delta) if delta.is_finite() => format!("{delta:+.1}%"),
        _ => "n/a".to_string(),
    }
}

/// Linear map of `value` from `[low, high]` onto `[out_low, out_high]`.
fn map_range(value: f64, low: f64, high: f64, out_low: f64, out_high: f64) -> f64 {
    if (high - low).abs() < f64::EPSILON {
        return (out_low + out_high) / 2.0;
    }
    out_low + (value - low) / (high - low) * (out_high - out_low)
}

/// Renders the plot as one self-contained SVG document.
///
/// Every panel gets one `<polyline>` per series, so the number of
/// `<polyline>` elements equals `series.len()`.
pub fn render_svg(
    series: &[PlotSeries],
    aggregates: &[SeriesAggregate],
    title: &str,
    subtitle: &str,
) -> String {
    let panels = panel_groups(series);
    let height = TOP_MARGIN + PANEL_HEIGHT * panels.len() as f64 + 44.0;

    let mut svg = String::new();
    svg.push_str(&format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{SVG_WIDTH:.0}\" height=\"{height:.0}\" viewBox=\"0 0 {SVG_WIDTH:.0} {height:.0}\" font-family=\"DejaVu Sans, Helvetica, Arial, sans-serif\">\n"
    ));
    svg.push_str(&format!(
        "<rect x=\"0\" y=\"0\" width=\"{SVG_WIDTH:.0}\" height=\"{height:.0}\" fill=\"#ffffff\"/>\n"
    ));
    svg.push_str(&format!(
        "<text class=\"title\" x=\"{:.1}\" y=\"32\" font-size=\"18\" font-weight=\"bold\" text-anchor=\"middle\">{}</text>\n",
        SVG_WIDTH / 2.0,
        escape_xml(title)
    ));
    svg.push_str(&format!(
        "<text class=\"subtitle\" x=\"{:.1}\" y=\"52\" font-size=\"11\" fill=\"#555555\" text-anchor=\"middle\">{}</text>\n",
        SVG_WIDTH / 2.0,
        escape_xml(subtitle)
    ));

    if panels.is_empty() {
        svg.push_str(&format!(
            "<text x=\"{:.1}\" y=\"{:.1}\" font-size=\"14\" fill=\"#aa0000\" text-anchor=\"middle\">no samples found</text>\n",
            SVG_WIDTH / 2.0,
            TOP_MARGIN + 40.0
        ));
    }

    for (panel_index, (key, members)) in panels.iter().enumerate() {
        let panel_top = TOP_MARGIN + PANEL_HEIGHT * panel_index as f64;
        render_panel(&mut svg, panel_top, key, series, aggregates, members);
    }

    svg.push_str(&format!(
        "<text class=\"footer\" x=\"{:.1}\" y=\"{:.1}\" font-size=\"10\" fill=\"#777777\">{n_series} series in {n_panels} panels</text>\n",
        PLOT_LEFT,
        height - 14.0,
        n_series = series.len(),
        n_panels = panels.len()
    ));
    svg.push_str("</svg>\n");

    svg
}

/// Renders one metric panel into `svg`.
fn render_panel(
    svg: &mut String,
    panel_top: f64,
    key: &PanelKey,
    series: &[PlotSeries],
    aggregates: &[SeriesAggregate],
    members: &[usize],
) {
    let plot_top = panel_top + PLOT_TOP_OFFSET;
    let plot_bottom = panel_top + PANEL_HEIGHT - PLOT_BOTTOM_OFFSET;

    let mut min_x = f64::INFINITY;
    let mut max_x = f64::NEG_INFINITY;
    let mut min_y = f64::INFINITY;
    let mut max_y = f64::NEG_INFINITY;
    for member in members {
        for (index, value) in &series[*member].samples {
            if value.is_finite() {
                min_y = min_y.min(*value);
                max_y = max_y.max(*value);
            }
            min_x = min_x.min(*index as f64);
            max_x = max_x.max(*index as f64);
        }
    }
    if !min_y.is_finite() {
        min_y = 0.0;
        max_y = 1.0;
    }
    if !min_x.is_finite() {
        min_x = 0.0;
        max_x = 1.0;
    }
    if (max_y - min_y).abs() < f64::EPSILON {
        min_y -= 0.5;
        max_y += 0.5;
    }
    // One precision for every label of this panel.
    let magnitude = min_y.abs().max(max_y.abs());

    let unit = series
        .get(members.first().copied().unwrap_or(0))
        .map(|entry| entry.unit.clone())
        .unwrap_or_default();
    let dimensions = key
        .dimensions
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(", ");
    let label = if dimensions.is_empty() {
        format!("{} [{}]", key.metric, unit)
    } else {
        format!("{} [{}] | {}", key.metric, unit, dimensions)
    };

    let panel_index = ((panel_top - TOP_MARGIN) / PANEL_HEIGHT).round() as u64;
    svg.push_str(&format!(
        "<g class=\"panel\" id=\"panel-{panel_index}\" transform=\"translate(0,0)\">\n"
    ));
    svg.push_str(&format!(
        "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"#fafafa\" stroke=\"#e0e0e0\"/>\n",
        PLOT_LEFT - 12.0,
        panel_top + 4.0,
        SVG_WIDTH - 2.0 * (PLOT_LEFT - 12.0),
        PANEL_HEIGHT - 8.0
    ));
    svg.push_str(&format!(
        "<text class=\"panel-title\" x=\"{:.1}\" y=\"{:.1}\" font-size=\"13\" font-weight=\"bold\">{}</text>\n",
        PLOT_LEFT,
        panel_top + 22.0,
        escape_xml(&label)
    ));
    svg.push_str(&format!(
        "<text class=\"test-name\" x=\"{:.1}\" y=\"{:.1}\" font-size=\"10\" fill=\"#777777\" text-anchor=\"end\">{}</text>\n",
        SVG_WIDTH - (PLOT_LEFT - 12.0) - 4.0,
        panel_top + 22.0,
        escape_xml(&key.test)
    ));

    // Horizontal grid lines and y axis labels.
    for step in 0..3 {
        let fraction = step as f64 / 2.0;
        let value = max_y - (max_y - min_y) * fraction;
        let y = map_range(value, min_y, max_y, plot_bottom, plot_top);
        svg.push_str(&format!(
            "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"#e6e6e6\" stroke-dasharray=\"2,3\"/>\n",
            PLOT_LEFT, y, PLOT_RIGHT, y
        ));
        svg.push_str(&format!(
            "<text x=\"{:.1}\" y=\"{:.1}\" font-size=\"9\" fill=\"#666666\" text-anchor=\"end\">{}</text>\n",
            PLOT_LEFT - 6.0,
            y + 3.0,
            format_axis_value(value, magnitude)
        ));
    }

    // Axes.
    svg.push_str(&format!(
        "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"#999999\"/>\n",
        PLOT_LEFT, plot_bottom, PLOT_RIGHT, plot_bottom
    ));
    svg.push_str(&format!(
        "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"#999999\"/>\n",
        PLOT_LEFT, plot_top, PLOT_LEFT, plot_bottom
    ));
    svg.push_str(&format!(
        "<text x=\"{:.1}\" y=\"{:.1}\" font-size=\"9\" fill=\"#666666\" text-anchor=\"middle\">iteration</text>\n",
        (PLOT_LEFT + PLOT_RIGHT) / 2.0,
        plot_bottom + 16.0
    ));
    svg.push_str(&format!(
        "<text x=\"{:.1}\" y=\"{:.1}\" font-size=\"9\" fill=\"#666666\">idx {}</text>\n",
        PLOT_LEFT,
        plot_bottom + 16.0,
        min_x as i64
    ));

    // One polyline per series.
    for (slot, member) in members.iter().enumerate() {
        let entry = &series[*member];
        let colour = PALETTE[slot % PALETTE.len()];
        let points = entry
            .samples
            .iter()
            .map(|(index, value)| {
                format!(
                    "{:.2},{:.2}",
                    map_range(*index as f64, min_x, max_x, PLOT_LEFT, PLOT_RIGHT),
                    map_range(*value, min_y, max_y, plot_bottom, plot_top)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        svg.push_str(&format!(
            "<polyline class=\"series\" data-group=\"{group}\" fill=\"none\" stroke=\"{colour}\" stroke-width=\"1.4\" points=\"{points}\"/>\n",
            group = entry.group
        ));

        // Legend entry with the aggregated statistics.
        let legend_y = plot_top + 10.0 + slot as f64 * 15.0;
        let stats = aggregates.get(*member);
        let legend = format!(
            "{} n={} p50={} p90={} delta={}",
            entry.group,
            stats.map(|s| s.count).unwrap_or(entry.samples.len()),
            stats
                .and_then(|s| s.p50)
                .map(|value| format_axis_value(value, magnitude))
                .unwrap_or_else(|| "n/a".to_string()),
            stats
                .and_then(|s| s.p90)
                .map(|value| format_axis_value(value, magnitude))
                .unwrap_or_else(|| "n/a".to_string()),
            format_delta(stats.and_then(|s| s.delta_p50_pct))
        );
        svg.push_str(&format!(
            "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"{colour}\" stroke-width=\"3\"/>\n",
            LEGEND_LEFT,
            legend_y,
            LEGEND_LEFT + 14.0,
            legend_y
        ));
        svg.push_str(&format!(
            "<text x=\"{:.1}\" y=\"{:.1}\" font-size=\"10\" fill=\"#333333\">{}</text>\n",
            LEGEND_LEFT + 20.0,
            legend_y + 3.5,
            escape_xml(&legend)
        ));
    }

    svg.push_str("</g>\n");
}

/// Writes `svg` to `output`, creating parent directories when needed.
pub fn write_svg(output: &Path, svg: &str) -> Result<()> {
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    std::fs::write(output, svg).with_context(|| format!("failed to write {}", output.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two groups, one panel, one metric with three samples each.
    fn fixture_series() -> Vec<PlotSeries> {
        let records = vec![MetricRecord {
            test: "test_boottime".to_string(),
            metric: "boot_time".to_string(),
            unit: "ms".to_string(),
            values: vec![10.0, 11.0, 12.0],
            dimensions: vec![("rootfs".to_string(), "ext4".to_string())],
        }];

        // Each data directory restarts the per-panel index, like `load_data`.
        let mut samples = samples_from_records(&records, 'A', &mut BTreeMap::new());
        let records_b = vec![MetricRecord {
            values: vec![12.0, 13.0, 14.0],
            ..records[0].clone()
        }];
        samples.extend(samples_from_records(&records_b, 'B', &mut BTreeMap::new()));

        group_series(&samples)
    }

    fn metrics_document() -> serde_json::Value {
        serde_json::json!({
            "dimensions": {
                "performance_test": "test_boottime",
                "instance": "m5d.metal",
                "cpu_model": "Intel",
                "host_kernel": "6.1",
                "rootfs": "ext4"
            },
            "metrics": {
                "boot_time": {"unit": "ms", "values": [1.0, 2.0, 3.0]},
                "cpu_utilization_vmm": {"unit": "percent", "values": [9.0]}
            },
            "nodeid": "integration_tests/performance/test_boottime.py::test_boottime"
        })
    }

    #[test]
    fn records_require_a_performance_test_dimension() {
        let mut document = metrics_document();
        document["dimensions"]
            .as_object_mut()
            .expect("dimensions is an object")
            .remove("performance_test");
        assert!(records_from_metrics_json(&document)
            .expect("parses")
            .is_none());
    }

    #[test]
    fn records_drop_host_dimensions_and_cpu_utilization() {
        let records = records_from_metrics_json(&metrics_document())
            .expect("parses")
            .expect("performance test present");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].metric, "boot_time");
        assert_eq!(records[0].test, "test_boottime");
        assert_eq!(records[0].unit, "ms");
        assert_eq!(records[0].values, vec![1.0, 2.0, 3.0]);
        assert_eq!(
            records[0].dimensions,
            vec![("rootfs".to_string(), "ext4".to_string())]
        );
    }

    #[test]
    fn samples_continue_the_panel_index_across_files() {
        let records = records_from_metrics_json(&metrics_document())
            .expect("parses")
            .expect("performance test present");
        let mut offsets = BTreeMap::new();
        let first = samples_from_records(&records, 'A', &mut offsets);
        let second = samples_from_records(&records, 'A', &mut offsets);
        assert_eq!(
            first.iter().map(|s| s.index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            second.iter().map(|s| s.index).collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
    }

    #[test]
    fn csv_rows_are_grouped_into_records() {
        let text = "\
test,metric,value,unit,group,rootfs,instance
test_boottime,boot_time,10.0,ms,A,ext4,i3.metal
test_boottime,boot_time,12.0,ms,A,ext4,i3.metal
test_boottime,boot_time,14.0,ms,A,xfs,i3.metal
";
        let records = records_from_csv(text).expect("parses");
        assert_eq!(records.len(), 2);
        let ext4 = records
            .iter()
            .find(|record| record.dimensions.iter().any(|(_, v)| v == "ext4"))
            .expect("ext4 record");
        assert_eq!(ext4.values, vec![10.0, 12.0]);
        assert_eq!(ext4.test, "test_boottime");
        // `instance` is host specific and `group` is positional: neither may
        // become a dimension, or the panel would be split per group.
        assert!(!ext4.dimensions.iter().any(|(name, _)| name == "instance"));
        assert!(!ext4.dimensions.iter().any(|(name, _)| name == "group"));
    }

    #[test]
    fn csv_without_required_column_fails() {
        assert!(records_from_csv("test,value\na,1\n").is_err());
        assert!(records_from_csv("").is_err());
    }

    #[test]
    fn percentiles_use_linear_interpolation() {
        let values = vec![1.0, 2.0, 3.0, 4.0];
        assert_eq!(p50(&values), Some(2.5));
        let p90_value = p90(&values).expect("p90");
        assert!((p90_value - 3.7).abs() < 1e-9, "p90 was {p90_value}");
        assert_eq!(p50(&[]), None);
        assert_eq!(percentile(&[5.0], 90.0), Some(5.0));
    }

    #[test]
    fn aggregation_computes_deltas_against_baseline() {
        let series = fixture_series();
        let aggregates = aggregate(&series, 'A');
        assert_eq!(aggregates.len(), series.len());

        let group_a = aggregates
            .iter()
            .find(|entry| entry.group == 'A')
            .expect("group A");
        assert_eq!(group_a.count, 3);
        assert_eq!(group_a.p50, Some(11.0));
        assert_eq!(group_a.delta_p50_pct, Some(0.0));

        let group_b = aggregates
            .iter()
            .find(|entry| entry.group == 'B')
            .expect("group B");
        assert_eq!(group_b.count, 3);
        assert_eq!(group_b.p50, Some(13.0));
        let delta = group_b.delta_p50_pct.expect("delta is defined");
        assert!((delta - 100.0 * 2.0 / 11.0).abs() < 1e-9, "delta {delta}");
    }

    #[test]
    fn relative_delta_handles_degenerate_inputs() {
        assert_eq!(relative_delta(Some(2.0), Some(1.0)), Some(100.0));
        assert_eq!(relative_delta(Some(2.0), Some(0.0)), None);
        assert_eq!(relative_delta(None, Some(1.0)), None);
        assert_eq!(relative_delta(Some(1.0), None), None);
    }

    #[test]
    fn svg_has_one_polyline_per_series() {
        let series = fixture_series();
        let aggregates = aggregate(&series, 'A');
        let svg = render_svg(&series, &aggregates, "A/B <test>", "errorbar=pi 95");

        assert_eq!(svg.matches("<polyline").count(), series.len());
        assert!(svg.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(svg.trim_end().ends_with("</svg>"));
        assert!(svg.contains("data-group=\"A\""));
        assert!(svg.contains("data-group=\"B\""));
        assert!(!svg.contains("<test>"), "the title must be XML escaped");
        assert!(svg.contains("A/B &lt;test&gt;"));
    }

    #[test]
    fn svg_is_written_to_disk() {
        let dir = std::env::temp_dir().join(format!("fc-ab-plot-{}", std::process::id()));
        let output = dir.join("nested/plot.svg");
        let series = fixture_series();
        let aggregates = aggregate(&series, 'A');
        let svg = render_svg(&series, &aggregates, "title", "subtitle");
        write_svg(&output, &svg).expect("writes the svg");

        let written = std::fs::read_to_string(&output).expect("reads back");
        assert_eq!(written, svg);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_series_still_produces_a_document() {
        let svg = render_svg(&[], &[], "empty", "");
        assert!(svg.contains("no samples found"));
        assert_eq!(svg.matches("<polyline").count(), 0);
    }

    #[test]
    fn group_labels_follow_the_alphabet() {
        assert_eq!(group_label(0).expect("A"), 'A');
        assert_eq!(group_label(1).expect("B"), 'B');
        assert_eq!(group_label(25).expect("Z"), 'Z');
        assert!(group_label(26).is_err());
    }

    #[test]
    fn format_helpers() {
        assert_eq!(format_value(1234.0), "1234");
        assert_eq!(format_value(150.0), "150.0");
        assert_eq!(format_value(12.5), "12.50");
        assert_eq!(format_value(1.5), "1.500");
        assert_eq!(format_axis_value(900.0, 1200.0), "900");
        assert_eq!(format_axis_value(1050.0, 1200.0), "1050");
        assert_eq!(format_axis_value(9.0, 9.0), "9.000");
        assert_eq!(format_delta(Some(12.34)), "+12.3%");
        assert_eq!(format_delta(None), "n/a");
    }
}
