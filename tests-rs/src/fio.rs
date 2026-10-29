// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! fio workload and log helpers, ported from `tests/framework/utils_fio.py`.
//!
//! [`build_cmd`] mirrors the python command assembly exactly, including the
//! `CmdBuilder` quirk of emitting `flag ""` pairs with a double space for
//! valueless options. The two log parsers keep the python grouping: one entry
//! per log/JSON file, one inner vector per direction (reads, writes).

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};

use crate::utils::CmdBuilder;

/// Default fio runtime in seconds (`DEFAULT_RUNTIME_SEC`).
pub const DEFAULT_RUNTIME_SEC: u64 = 30;

/// Default fio ramp-up time in seconds (`DEFAULT_WARMUP_SEC`).
pub const DEFAULT_WARMUP_SEC: u64 = 10;

/// fio output file, relative to the guest working directory (`--output`).
pub const OUTPUT_JSON: &str = "./fio.json";

/// Modes of fio operation (python `Mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Sequential reads (`READ = "read"`).
    Read,
    /// Sequential writes (`WRITE = "write"`).
    Write,
    /// Sequential trims (`TRIM = "trim"`).
    Trim,
    /// Random reads (`RANDREAD = "randread"`).
    RandRead,
    /// Random writes (`RANDWRITE = "randwrite"`).
    RandWrite,
    /// Random trims (`RANDTRIM = "randtrim"`).
    RandTrim,
    /// Sequential mixed reads and writes (`READWRITE = "readwrite"`).
    ReadWrite,
    /// Random mixed reads and writes (`RANDRW = "randrw"`).
    RandRw,
}

impl Mode {
    /// The fio `--rw` value, i.e. the python enum value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Mode::Read => "read",
            Mode::Write => "write",
            Mode::Trim => "trim",
            Mode::RandRead => "randread",
            Mode::RandWrite => "randwrite",
            Mode::RandTrim => "randtrim",
            Mode::ReadWrite => "readwrite",
            Mode::RandRw => "randrw",
        }
    }
}

impl FromStr for Mode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "read" => Ok(Mode::Read),
            "write" => Ok(Mode::Write),
            "trim" => Ok(Mode::Trim),
            "randread" => Ok(Mode::RandRead),
            "randwrite" => Ok(Mode::RandWrite),
            "randtrim" => Ok(Mode::RandTrim),
            "readwrite" => Ok(Mode::ReadWrite),
            "randrw" => Ok(Mode::RandRw),
            other => Err(anyhow!("unknown fio mode {other}")),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// fio backend engines (python `Engine`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Engine {
    /// Linux native asynchronous I/O (`LIBAIO = "libaio"`).
    LibAio,
    /// Synchronous I/O (`PSYNC = "psync"`).
    Psync,
}

impl Engine {
    /// The fio `--ioengine` value, i.e. the python enum value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Engine::LibAio => "libaio",
            Engine::Psync => "psync",
        }
    }
}

impl FromStr for Engine {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "libaio" => Ok(Engine::LibAio),
            "psync" => Ok(Engine::Psync),
            other => Err(anyhow!("unknown fio ioengine {other}")),
        }
    }
}

/// fio log types (python `LogType`), used as the file name suffix filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogType {
    /// Bandwidth log (`BW = "_bw"`).
    Bw,
    /// Completion latency log (`CLAT = "_clat"`).
    Clat,
}

impl LogType {
    /// The suffix that identifies the log files of this type.
    pub const fn suffix(self) -> &'static str {
        match self {
            LogType::Bw => "_bw",
            LogType::Clat => "_clat",
        }
    }
}

/// Builds a fio command string (python `build_cmd`).
///
/// `file_size_mb` is `--size=<n>M` and is skipped when `None`; `runtime` and
/// `warmup_time` are skipped when `None` or zero, matching the python truthiness
/// checks. `write_lat_log` is only emitted for [`Engine::Psync`], as in python.
#[allow(clippy::too_many_arguments)]
pub fn build_cmd(
    file_path: &str,
    file_size_mb: Option<u64>,
    block_size: u64,
    mode: Mode,
    num_jobs: usize,
    io_engine: Engine,
    runtime: Option<u64>,
    warmup_time: Option<u64>,
    write_logs: bool,
) -> String {
    let mut cmd = CmdBuilder::new("fio")
        .with_arg(format!("--name={}-{}", mode.as_str(), block_size), "")
        .with_arg(format!("--filename={file_path}"), "");

    if let Some(size) = file_size_mb {
        cmd = cmd.with_arg(format!("--size={size}M"), "");
    }

    cmd = cmd.with_arg(format!("--bs={block_size}"), "");

    if let Some(runtime) = runtime.filter(|value| *value > 0) {
        cmd = cmd
            .with_arg("--time_based=1", "")
            .with_arg(format!("--runtime={runtime}"), "");
    }
    if let Some(warmup_time) = warmup_time.filter(|value| *value > 0) {
        cmd = cmd.with_arg(format!("--ramp_time={warmup_time}"), "");
    }

    let cpus = (0..num_jobs)
        .map(|cpu| cpu.to_string())
        .collect::<Vec<_>>()
        .join(",");

    cmd = cmd
        .with_arg(format!("--rw={}", mode.as_str()), "")
        .with_arg("--direct=1", "")
        .with_arg("--randrepeat=0", "")
        .with_arg(format!("--ioengine={}", io_engine.as_str()), "")
        .with_arg("--iodepth=32", "")
        .with_arg(format!("--numjobs={num_jobs}"), "")
        // Set affinity of the entire fio process to a set of vCPUs equal in
        // size to the number of workers.
        .with_arg(format!("--cpus_allowed={cpus}"), "")
        // Instruct fio to pin one worker per vcpu.
        .with_arg("--cpus_allowed_policy=split", "")
        .with_arg("--output-format=json+", "")
        .with_arg(format!("--output={OUTPUT_JSON}"), "");

    if write_logs {
        cmd = cmd
            .with_arg("--log_avg_msec=1000", "")
            .with_arg(format!("--write_bw_log={}", mode.as_str()), "");
        // Latency measurements only make sense for the psync engine.
        if io_engine == Engine::Psync {
            cmd = cmd.with_arg(format!("--write_lat_log={}", mode.as_str()), "");
        }
    }

    cmd.build()
}

/// Parses the per-job fio logs under `root_dir` (python `process_log_files`).
///
/// Returns `(reads, writes)` where every inner vector belongs to one log file,
/// files sorted by path. Log lines look like `1000, 2007920, 0, 0, 0`: the
/// second column is the bandwidth/latency value and the third is the direction
/// (`0` = read, `1` = write).
pub fn process_log_files(
    root_dir: &Path,
    log_type: LogType,
) -> Result<(Vec<Vec<i64>>, Vec<Vec<i64>>)> {
    let paths = files_matching(root_dir, |name| {
        name.ends_with(".log") && name.contains(log_type.suffix())
    })?;
    if paths.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut reads = Vec::with_capacity(paths.len());
    let mut writes = Vec::with_capacity(paths.len());
    for path in paths {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("reading fio log {}", path.display()))?;
        let mut read_values = Vec::new();
        let mut write_values = Vec::new();
        for (line_index, line) in contents.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            // See https://fio.readthedocs.io/en/latest/fio_doc.html#log-file-formats
            let mut fields = line.splitn(4, ',');
            let _timestamp = fields.next();
            let value = fields.next().ok_or_else(|| {
                anyhow!(
                    "{}:{}: malformed fio log line {line:?}",
                    path.display(),
                    line_index + 1
                )
            })?;
            let direction = fields.next().ok_or_else(|| {
                anyhow!(
                    "{}:{}: malformed fio log line {line:?}",
                    path.display(),
                    line_index + 1
                )
            })?;
            let value: i64 = value.trim().parse().with_context(|| {
                format!(
                    "{}:{}: invalid fio log value {:?}",
                    path.display(),
                    line_index + 1,
                    value.trim()
                )
            })?;
            match direction.trim() {
                "0" => read_values.push(value),
                "1" => write_values.push(value),
                other => bail!(
                    "{}:{}: unexpected fio log direction {other:?}",
                    path.display(),
                    line_index + 1
                ),
            }
        }
        reads.push(read_values);
        writes.push(write_values);
    }

    Ok((reads, writes))
}

/// Reads `bw_bytes` from every `fio*.json` file under `root_dir`
/// (python `process_json_files`).
///
/// Returns `(bw_reads, bw_writes)`, one entry per JSON file and one value per
/// job that reported that direction.
pub fn process_json_files(root_dir: &Path) -> Result<(Vec<Vec<u64>>, Vec<Vec<u64>>)> {
    let paths = files_matching(root_dir, |name| {
        name.ends_with(".json") && name.contains("fio")
    })?;

    let mut bw_reads = Vec::with_capacity(paths.len());
    let mut bw_writes = Vec::with_capacity(paths.len());
    for path in paths {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("reading fio output {}", path.display()))?;
        let data: serde_json::Value = serde_json::from_str(&contents)
            .with_context(|| format!("parsing fio output {}", path.display()))?;
        let jobs = data
            .get("jobs")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow!("{}: no `jobs` array in fio output", path.display()))?;

        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for (job_index, job) in jobs.iter().enumerate() {
            if job.get("read").is_some() {
                reads.push(job_bw_bytes(job, "read", &path, job_index)?);
            }
            if job.get("write").is_some() {
                writes.push(job_bw_bytes(job, "write", &path, job_index)?);
            }
        }
        bw_reads.push(reads);
        bw_writes.push(writes);
    }

    Ok((bw_reads, bw_writes))
}

/// Reads `jobs[i].<direction>.bw_bytes` from a parsed fio output document.
fn job_bw_bytes(
    job: &serde_json::Value,
    direction: &str,
    path: &Path,
    job_index: usize,
) -> Result<u64> {
    job.get(direction)
        .and_then(|entry| entry.get("bw_bytes"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            anyhow!(
                "{}: jobs[{job_index}].{direction}.bw_bytes is missing or not an integer",
                path.display()
            )
        })
}

/// Lists regular files of `root_dir` whose name matches `predicate`, sorted.
fn files_matching(root_dir: &Path, predicate: impl Fn(&str) -> bool) -> Result<Vec<PathBuf>> {
    let entries =
        fs::read_dir(root_dir).with_context(|| format!("listing {}", root_dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("listing {}", root_dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if predicate(&name) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static UNIQUE: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let unique = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "fc-harness-fio-{}-{}-{tag}",
            std::process::id(),
            unique
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn build_cmd_matches_python_output() {
        let cmd = build_cmd(
            "/dev/vdb",
            Some(1024),
            4096,
            Mode::Write,
            2,
            Engine::LibAio,
            Some(DEFAULT_RUNTIME_SEC),
            Some(DEFAULT_WARMUP_SEC),
            true,
        );
        assert_eq!(
            cmd,
            "fio --name=write-4096  --filename=/dev/vdb  --size=1024M  --bs=4096  \
--time_based=1  --runtime=30  --ramp_time=10  --rw=write  --direct=1  --randrepeat=0  \
--ioengine=libaio  --iodepth=32  --numjobs=2  --cpus_allowed=0,1  \
--cpus_allowed_policy=split  --output-format=json+  --output=./fio.json  \
--log_avg_msec=1000  --write_bw_log=write  "
        );
    }

    #[test]
    fn build_cmd_omits_size_runtime_and_latency_log_for_libaio() {
        let cmd = build_cmd(
            "/dev/vdb",
            None,
            512,
            Mode::RandRead,
            1,
            Engine::LibAio,
            None,
            Some(0),
            false,
        );
        assert!(!cmd.contains("--size="));
        assert!(!cmd.contains("--time_based=1"));
        assert!(!cmd.contains("--ramp_time="));
        assert!(!cmd.contains("--log_avg_msec=1000"));
        assert!(!cmd.contains("--write_bw_log="));
        assert!(!cmd.contains("--write_lat_log="));
        assert!(cmd.contains("--bs=512"));
        assert!(cmd.contains("--rw=randread"));
        assert!(cmd.contains("--cpus_allowed=0"));
    }

    #[test]
    fn build_cmd_emits_latency_log_for_psync() {
        let cmd = build_cmd(
            "/dev/vdb",
            Some(64),
            4096,
            Mode::ReadWrite,
            3,
            Engine::Psync,
            Some(5),
            Some(1),
            true,
        );
        assert!(cmd.contains("--write_bw_log=readwrite"));
        assert!(cmd.contains("--write_lat_log=readwrite"));
        assert!(cmd.contains("--cpus_allowed=0,1,2"));
        assert!(cmd.contains("--ioengine=psync"));
    }

    #[test]
    fn mode_and_engine_round_trip() {
        for mode in [
            "read",
            "write",
            "trim",
            "randread",
            "randwrite",
            "randtrim",
            "readwrite",
            "randrw",
        ] {
            let parsed: Mode = mode.parse().expect("known mode");
            assert_eq!(parsed.as_str(), mode);
        }
        assert!("bogus".parse::<Mode>().is_err());
        assert_eq!("libaio".parse::<Engine>().expect("engine"), Engine::LibAio);
        assert_eq!("psync".parse::<Engine>().expect("engine"), Engine::Psync);
        assert!("io_uring".parse::<Engine>().is_err());
    }

    #[test]
    fn process_log_files_groups_per_file_and_direction() {
        let dir = temp_dir("logs");
        fs::write(
            dir.join("readwrite_bw.1.log"),
            "1000, 2007920, 0, 0, 0\n1000, 2005276, 1, 0, 0\n",
        )
        .expect("write log");
        fs::write(
            dir.join("readwrite_bw.2.log"),
            "2000, 1996240, 0, 0, 0\n2000, 1993861, 1, 0, 0\n",
        )
        .expect("write log");
        fs::write(dir.join("readwrite_clat.1.log"), "1000, 45, 0, 0, 0\n").expect("write log");
        fs::write(dir.join("notes.txt"), "ignored\n").expect("write log");

        let (reads, writes) = process_log_files(&dir, LogType::Bw).expect("parse logs");
        assert_eq!(reads, vec![vec![2007920], vec![1996240]]);
        assert_eq!(writes, vec![vec![2005276], vec![1993861]]);

        let (reads, writes) = process_log_files(&dir, LogType::Clat).expect("parse logs");
        assert_eq!(reads, vec![vec![45]]);
        assert_eq!(writes, vec![Vec::<i64>::new()]);

        let empty = temp_dir("empty");
        let (reads, writes) = process_log_files(&empty, LogType::Bw).expect("parse logs");
        assert!(reads.is_empty() && writes.is_empty());

        fs::remove_dir_all(&dir).expect("cleanup");
        fs::remove_dir_all(&empty).expect("cleanup");
    }

    #[test]
    fn process_log_files_rejects_unknown_direction() {
        let dir = temp_dir("bad-direction");
        fs::write(dir.join("read_bw.1.log"), "1000, 1, 7, 0, 0\n").expect("write log");
        assert!(process_log_files(&dir, LogType::Bw).is_err());
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn process_json_files_reads_bw_bytes() {
        let dir = temp_dir("json");
        let first = serde_json::json!({
            "jobs": [
                {"read": {"bw_bytes": 1024}, "write": {"bw_bytes": 2048}},
                {"read": {"bw_bytes": 4096}},
            ]
        });
        let second = serde_json::json!({
            "jobs": [{"write": {"bw_bytes": 512}}]
        });
        fs::write(
            dir.join("fio-first.json"),
            serde_json::to_string(&first).expect("json"),
        )
        .expect("write json");
        fs::write(
            dir.join("fio-second.json"),
            serde_json::to_string(&second).expect("json"),
        )
        .expect("write json");
        fs::write(dir.join("other.json"), "{}").expect("write json");

        let (bw_reads, bw_writes) = process_json_files(&dir).expect("parse json");
        assert_eq!(bw_reads, vec![vec![1024, 4096], Vec::new()]);
        assert_eq!(bw_writes, vec![vec![2048], vec![512]]);

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn process_json_files_rejects_missing_jobs() {
        let dir = temp_dir("bad-json");
        fs::write(dir.join("fio.json"), "{\"jobs\": [{}]}").expect("write json");
        // A job without any direction simply produces empty vectors.
        let (bw_reads, bw_writes) = process_json_files(&dir).expect("parse json");
        assert_eq!(bw_reads, vec![Vec::<u64>::new()]);
        assert_eq!(bw_writes, vec![Vec::<u64>::new()]);
        fs::write(dir.join("fio.json"), "{\"jobs\": [{\"read\": {}}]}").expect("write json");
        assert!(process_json_files(&dir).is_err());
        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
