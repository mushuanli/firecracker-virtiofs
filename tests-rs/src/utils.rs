// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic utilities, ported from `tests/framework/utils.py`.
//!
//! Python's `CommandReturn` named tuple becomes [`CommandReturn`];
//! `tenacity` retry loops become [`retry_for`] / [`retry_attempts`].

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::network::SshConnection;

/// Output of a host command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReturn {
    pub returncode: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandReturn {
    pub fn new(returncode: i32, stdout: String, stderr: String) -> Self {
        Self {
            returncode,
            stdout,
            stderr,
        }
    }

    /// Python tuple unpacking `_, stdout, _ = ...` equivalent.
    pub fn split(self) -> (i32, String, String) {
        (self.returncode, self.stdout, self.stderr)
    }

    pub fn success(&self) -> bool {
        self.returncode == 0
    }

    /// Full diagnostic dump, matching `_format_output_message`.
    pub fn describe(&self, cmd: &str) -> String {
        let mut msg = format!("Command:\n{cmd}");
        if !self.stdout.is_empty() {
            msg.push_str(&format!("\nstdout:\n{}", self.stdout));
        }
        if !self.stderr.is_empty() {
            msg.push_str(&format!("\nstderr:\n{}", self.stderr));
        }
        msg.push_str(&format!("\nReturned error code: {}", self.returncode));
        msg
    }
}

/// Runs a command in a shell (`cmd /bin/sh -c`), like `run_cmd(..., shell=True)`.
pub fn run_cmd(cmd: &str) -> Result<CommandReturn> {
    run_cmd_timeout(cmd, None)
}

/// Runs a shell command with an optional timeout.
pub fn run_cmd_timeout(cmd: &str, timeout: Option<Duration>) -> Result<CommandReturn> {
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(cmd);
    execute(command, cmd, timeout)
}

/// Runs a command without a shell (python `run_cmd(list, shell=False)`).
pub fn run_cmd_args<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> Result<CommandReturn> {
    run_cmd_args_timeout(args, None)
}

/// Runs an argv-style command with an optional timeout.
pub fn run_cmd_args_timeout<S: AsRef<std::ffi::OsStr>>(
    args: &[S],
    timeout: Option<Duration>,
) -> Result<CommandReturn> {
    let program = args
        .first()
        .ok_or_else(|| anyhow!("empty command"))?
        .as_ref()
        .to_os_string();
    let mut command = Command::new(&program);
    command.args(args.iter().skip(1).map(|a| a.as_ref()));
    let printable = args
        .iter()
        .map(|a| a.as_ref().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    execute(command, &printable, timeout)
}

/// Runs a shell command and fails on a non-zero exit code (`check_output`).
pub fn check_output(cmd: &str) -> Result<CommandReturn> {
    let result = run_cmd(cmd)?;
    if !result.success() {
        bail!("{}", result.describe(cmd));
    }
    Ok(result)
}

/// Runs an argv command and fails on a non-zero exit code.
pub fn check_output_args<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> Result<CommandReturn> {
    let result = run_cmd_args(args)?;
    if !result.success() {
        let printable = args
            .iter()
            .map(|a| a.as_ref().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        bail!("{}", result.describe(&printable));
    }
    Ok(result)
}

fn execute(
    mut command: Command,
    printable: &str,
    timeout: Option<Duration>,
) -> Result<CommandReturn> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn: {printable}"))?;

    // Read pipes from helper threads so a chatty child cannot dead-lock on a
    // full pipe while we wait for it to exit.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_reader = stdout.map(spawn_reader);
    let err_reader = stderr.map(spawn_reader);

    let deadline = timeout.map(|t| Instant::now() + t);
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if let Some(deadline) = deadline {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        bail!("Timeout executing command: {printable}");
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };

    let stdout = out_reader
        .map(|r| r.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = err_reader
        .map(|r| r.join().unwrap_or_default())
        .unwrap_or_default();
    Ok(CommandReturn::new(exit_code(status), stdout, stderr))
}

fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    })
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        // Mirror the shell convention: negative signal number.
        -status.signal().unwrap_or(0)
    })
}

/// Retry helper replacing `tenacity.Retrying(wait=wait_fixed, stop=stop_after_delay)`.
pub fn retry_for<T, F>(timeout: Duration, interval: Duration, mut op: F) -> Result<T>
where
    F: FnMut() -> Result<T>,
{
    let deadline = Instant::now() + timeout;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(err);
                }
                std::thread::sleep(interval);
            }
        }
    }
}

/// Retry helper replacing `stop_after_attempt(n)`.
pub fn retry_attempts<T, F>(attempts: u32, interval: Duration, mut op: F) -> Result<T>
where
    F: FnMut() -> Result<T>,
{
    let mut last = None;
    for attempt in 0..attempts {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                last = Some(err);
                if attempt + 1 < attempts {
                    std::thread::sleep(interval);
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no attempts made")))
}

/// Random lowercase alphanumeric string of length `k` (python `random_str`).
pub fn random_str(k: usize) -> String {
    crate::network::random_str(k)
}

/// Maps a virtual cpu index to the real host cpu (python `CpuMap`).
pub fn cpu_map(cpu: usize) -> Result<usize> {
    let cpus = host_cpus();
    cpus.get(cpu)
        .copied()
        .ok_or_else(|| anyhow!("cpu index {cpu} out of range for {} cpus", cpus.len()))
}

/// Host cpus visible to this process, from `sched_getaffinity`.
pub fn host_cpus() -> Vec<usize> {
    match get_cpu_affinity(0) {
        Ok(cpus) => cpus,
        Err(_) => (0..std::thread::available_parallelism().map_or(1, |p| p.get())).collect(),
    }
}

/// Returns the CPU affinity of a pid/thread id.
pub fn get_cpu_affinity(pid: i32) -> Result<Vec<usize>> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a valid `cpu_set_t` for the duration of the call.
    let rc =
        unsafe { libc::sched_getaffinity(pid, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("sched_getaffinity");
    }
    let mut cpus = Vec::new();
    for cpu in 0..libc::CPU_SETSIZE as usize {
        // SAFETY: `cpu` is within `CPU_SETSIZE`.
        if unsafe { libc::CPU_ISSET(cpu, &set) } {
            cpus.push(cpu);
        }
    }
    Ok(cpus)
}

/// Sets the CPU affinity of a pid/thread id, returning the previous mask.
pub fn set_cpu_affinity(pid: i32, cpulist: &[usize]) -> Result<Vec<usize>> {
    let previous = get_cpu_affinity(pid)?;
    let mapped: Vec<usize> = cpulist
        .iter()
        .map(|cpu| cpu_map(*cpu))
        .collect::<Result<_>>()?;

    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for cpu in &mapped {
        // SAFETY: `cpu` is validated by `cpu_map` against the host mask.
        unsafe { libc::CPU_SET(*cpu, &mut set) };
    }
    // SAFETY: `set` is initialised for `size_of::<cpu_set_t>()` bytes.
    let rc = unsafe { libc::sched_setaffinity(pid, std::mem::size_of::<libc::cpu_set_t>(), &set) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("sched_setaffinity");
    }
    Ok(previous)
}

/// Maps thread name to the list of tids (python `get_threads`).
pub fn get_threads(pid: i32) -> BTreeMap<String, Vec<i32>> {
    let mut map: BTreeMap<String, Vec<i32>> = BTreeMap::new();
    let tasks = PathBuf::from(format!("/proc/{pid}/task"));
    let Ok(entries) = std::fs::read_dir(&tasks) else {
        return map;
    };
    for entry in entries.flatten() {
        let Ok(tid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm"))
            .map(|c| c.trim().to_string())
            .unwrap_or_default();
        map.entry(comm).or_default().push(tid);
    }
    map
}

/// Per-thread CPU times in seconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuTimes {
    pub user: f64,
    pub system: f64,
}

impl CpuTimes {
    pub fn total(&self) -> f64 {
        self.user + self.system
    }
}

/// Per-thread CPU times of a process, keyed by thread name.
pub fn get_cpu_times(pid: i32) -> BTreeMap<String, CpuTimes> {
    let mut result = BTreeMap::new();
    for (name, tids) in get_threads(pid) {
        let mut user = 0.0;
        let mut system = 0.0;
        for tid in tids {
            if let Some((u, s)) = thread_cpu_seconds(tid) {
                user += u;
                system += s;
            }
        }
        result.insert(name, CpuTimes { user, system });
    }
    result
}

fn thread_cpu_seconds(tid: i32) -> Option<(f64, f64)> {
    let stat = std::fs::read_to_string(format!("/proc/{tid}/stat")).ok()?;
    let rest = stat
        .rsplit(')')
        .next()?
        .split_whitespace()
        .collect::<Vec<_>>();
    // Fields after comm: state(3) ... utime(14) stime(15)
    let utime: f64 = rest.get(11)?.parse().ok()?;
    let stime: f64 = rest.get(12)?.parse().ok()?;
    let hz = ticks_per_second();
    Some((utime / hz, stime / hz))
}

fn ticks_per_second() -> f64 {
    // SAFETY: `sysconf` is thread-safe and takes a plain int.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 {
        hz as f64
    } else {
        100.0
    }
}

/// Current per-thread CPU utilization (percent) over `interval`.
pub fn get_cpu_utilization(pid: i32, interval: Duration) -> BTreeMap<String, f64> {
    let before = get_cpu_times(pid);
    std::thread::sleep(interval);
    let after = get_cpu_times(pid);
    let seconds = interval.as_secs_f64().max(f64::EPSILON);
    let mut util = BTreeMap::new();
    for (name, b) in &before {
        if let Some(a) = after.get(name) {
            let user = (a.user - b.user) / seconds * 100.0;
            let system = (a.system - b.system) / seconds * 100.0;
            util.insert(name.clone(), user + system);
        }
    }
    util
}

/// Tracks CPU utilization over `iterations` samples after sleeping `omit`.
pub fn track_cpu_utilization(
    pid: i32,
    iterations: usize,
    omit: Duration,
) -> BTreeMap<String, Vec<f64>> {
    assert!(iterations > 0, "iterations must be positive");
    std::thread::sleep(omit);
    let mut samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for _ in 0..iterations {
        let current = get_cpu_utilization(pid, Duration::from_secs(1));
        assert!(!current.is_empty(), "no threads found for pid {pid}");
        for (name, value) in current {
            samples.entry(name).or_default().push(value);
        }
    }
    samples
}

/// Resident memory in KiB including HugeTLB pages (python `get_resident_memory`).
pub fn get_resident_memory(pid: i32) -> Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("reading /proc/{pid}/status"))?;
    let hugetlb_kib = status
        .lines()
        .find_map(|line| line.strip_prefix("HugetlbPages:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("HugetlbPages not found in /proc/{pid}/status"))?;

    let statm = std::fs::read_to_string(format!("/proc/{pid}/statm"))?;
    let resident_pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| anyhow!("malformed /proc/{pid}/statm"))?;
    Ok(hugetlb_kib + resident_pages * (page_size() / 1024))
}

fn page_size() -> u64 {
    // SAFETY: `sysconf` is thread-safe.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as u64
    } else {
        4096
    }
}

/// Waits until RSS fluctuations drop below `percentage_delta`.
pub fn get_stable_rss_mem(pid: i32, percentage_delta: f64) -> Result<u64> {
    let mut second_rss = 0u64;
    for _ in 0..5 {
        let first_rss = get_resident_memory(pid)?;
        std::thread::sleep(Duration::from_secs(1));
        second_rss = get_resident_memory(pid)?;
        let abs_diff = first_rss.abs_diff(second_rss) as f64;
        let abs_delta = if first_rss == 0 {
            0.0
        } else {
            abs_diff / first_rss as f64 * 100.0
        };
        if abs_delta < percentage_delta {
            return Ok(second_rss);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(second_rss)
}

/// Command builder (python `CmdBuilder`). Insertion order is preserved.
#[derive(Debug, Clone, Default)]
pub struct CmdBuilder {
    bin_path: String,
    args: Vec<(String, String)>,
}

impl CmdBuilder {
    pub fn new(bin_path: impl Into<String>) -> Self {
        Self {
            bin_path: bin_path.into(),
            args: Vec::new(),
        }
    }

    pub fn with_arg(mut self, flag: impl Into<String>, value: impl Into<String>) -> Self {
        let flag = flag.into();
        if let Some(slot) = self.args.iter_mut().find(|(f, _)| *f == flag) {
            slot.1 = value.into();
        } else {
            self.args.push((flag, value.into()));
        }
        self
    }

    pub fn build(&self) -> String {
        let mut cmd = format!("{} ", self.bin_path);
        for (flag, value) in &self.args {
            cmd.push_str(&format!("{flag} {value} "));
        }
        cmd
    }
}

/// Runs `cmd` and returns the first regex match in its stdout.
pub fn search_output_from_cmd(cmd: &str, pattern: &str) -> Result<String> {
    let regex = regex::Regex::new(pattern).context("invalid regex")?;
    let stdout = check_output(cmd)?.stdout;
    let caps = regex
        .captures(&stdout)
        .ok_or_else(|| anyhow!("Could not find '{pattern}' in output for '{cmd}'"))?;
    // Group 1 when present, otherwise the whole match.
    let matched = caps
        .get(1)
        .or_else(|| caps.get(0))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    Ok(matched)
}

/// `chroot` context manager: restores the previous root on drop.
pub struct ChrootGuard {
    real_root: std::fs::File,
    working_dir: PathBuf,
}

impl ChrootGuard {
    /// Enters the chroot at `path`. Requires `CAP_SYS_CHROOT`.
    pub fn enter(path: &Path) -> Result<Self> {
        let real_root = std::fs::File::open("/")?;
        let working_dir = std::env::current_dir()?;
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())?;
        // SAFETY: `c_path` is a valid NUL-terminated path string.
        if unsafe { libc::chroot(c_path.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("chroot");
        }
        std::env::set_current_dir("/")?;
        Ok(Self {
            real_root,
            working_dir,
        })
    }
}

impl Drop for ChrootGuard {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: both calls only touch process-global state we own; the
        // fd is kept open by `self.real_root` for the duration of the call.
        unsafe {
            libc::fchdir(self.real_root.as_raw_fd());
            let dot = CString::new(".").expect("literal has no NUL");
            libc::chroot(dot.as_ptr());
        }
        let _ = std::env::set_current_dir(&self.working_dir);
    }
}

/// Waits for a process to disappear using `waitpid(WNOHANG)`.
pub fn wait_process_termination(pid: i32, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `waitpid` with WNOHANG only inspects kernel state.
        let rc = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        if rc == pid {
            return Ok(());
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                // Not our child: already reaped, or never reparented to us.
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("Process {pid} did not exit within {timeout:?}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Logs diagnostic information for a process that survived `SIGKILL`.
pub fn dump_proc_state(pid: i32) {
    // SAFETY: `kill` with signal 0 only probes existence.
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    if !alive {
        log_line(&format!("Process {pid} kill -0: gone or invisible"));
        return;
    }
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
        log_line(&format!(
            "Process {pid} did not exit after SIGKILL. status:\n{status}"
        ));
    }
    if let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        let cmdline = String::from_utf8_lossy(&cmdline).replace('\u{0}', " ");
        log_line(&format!("Process {pid} cmdline: {cmdline}"));
    }
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        if let Some(rest) = stat.rsplit(')').next() {
            if let Some(field) = rest.split_whitespace().nth(38) {
                log_line(&format!("Process {pid} exit_state (stat[41]): {field}"));
            }
        }
    }
    if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
        let mut tids: Vec<i32> = tasks
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
            .collect();
        tids.sort_unstable();
        for tid in tids {
            for name in ["comm", "wchan", "syscall", "stack"] {
                if let Ok(content) =
                    std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/{name}"))
                {
                    log_line(&format!(
                        "Process {pid} task {tid} {name}:\n{}",
                        content.trim()
                    ));
                }
            }
        }
    }
    if let Ok(result) = run_cmd_args(&["dmesg", "--ctime"]) {
        let tail = result
            .stdout
            .lines()
            .rev()
            .take(50)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        if !tail.is_empty() {
            log_line(&format!("dmesg tail (last 50 lines):\n{tail}"));
        }
    }
}

fn log_line(message: &str) {
    eprintln!("{message}");
}

/// Waits until `op` succeeds or the deadline passes (`tenacity` equivalent).
pub fn wait_until<F>(timeout: Duration, interval: Duration, mut predicate: F) -> Result<()>
where
    F: FnMut() -> Result<bool>,
{
    let deadline = Instant::now() + timeout;
    loop {
        match predicate() {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(err);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("condition not met within {timeout:?}"));
        }
        std::thread::sleep(interval);
    }
}

/// Asserts `Seccomp:` mode for every thread of a process.
pub fn assert_seccomp_level(pid: i32, seccomp_level: &str) -> Result<()> {
    let expected = format!("Seccomp:{seccomp_level}");
    for (_, tids) in get_threads(pid) {
        for tid in tids {
            let status = std::fs::read_to_string(format!("/proc/{tid}/status"))?;
            let line = status
                .lines()
                .find(|l| l.starts_with("Seccomp:"))
                .map(|l| l.split_whitespace().collect::<String>())
                .unwrap_or_default();
            if line != expected {
                bail!("thread {tid}: expected {expected}, found {line}");
            }
        }
    }
    Ok(())
}

/// MMDS session token request command (python `generate_mmds_session_token`).
pub fn generate_mmds_session_token(
    ssh: &SshConnection,
    ipv4_address: &str,
    token_ttl: u32,
    imds_compat: bool,
) -> Result<String> {
    let header = if imds_compat {
        "X-aws-ec2-metadata-token-ttl-seconds"
    } else {
        "X-metadata-token-ttl-seconds"
    };
    let cmd = format!(
        "curl -m 2 -s -X PUT -H \"{header}: {token_ttl}\" http://{ipv4_address}/latest/api/token"
    );
    Ok(ssh.run(&cmd, Duration::from_secs(100))?.stdout)
}

/// MMDS GET request command (python `generate_mmds_get_request`).
pub fn generate_mmds_get_request(
    ipv4_address: &str,
    token: Option<&str>,
    app_json: bool,
    imds_compat: bool,
) -> String {
    let mut cmd = String::from("curl -m 2 -s");
    if let Some(token) = token {
        cmd.push_str(" -X GET");
        if imds_compat {
            cmd.push_str(&format!(" -H \"X-aws-ec2-metadata-token: {token}\""));
        } else {
            cmd.push_str(&format!(" -H \"X-metadata-token: {token}\""));
        }
    }
    if app_json {
        cmd.push_str(" -H \"Accept: application/json\"");
    }
    cmd.push_str(&format!(" http://{ipv4_address}/"));
    cmd
}

/// Starts a binary inside a `screen` session and returns the screen pid.
pub fn start_screen_process(
    screen_log: &Path,
    session_name: &str,
    binary_path: &Path,
    binary_params: &[String],
) -> Result<i32> {
    let start_cmd = format!(
        "screen -L -Logfile {} -dmS {} {} {}",
        screen_log.display(),
        session_name,
        binary_path.display(),
        binary_params.join(" ")
    );
    check_output(&start_cmd)?;

    let pattern = format!(r"([0-9]+)\.{}", regex::escape(session_name));
    let screen_pid: i32 = retry_attempts(30, Duration::from_secs(1), || {
        let pid = search_output_from_cmd("screen -ls", &pattern)?;
        pid.parse::<i32>().context("invalid screen pid")
    })?;

    // Make sure the screen process launched successfully, as the parent
    // process for the binary.
    retry_attempts(5, Duration::from_millis(500), || {
        process_is_running(screen_pid)
    })?;

    // Configure screen to flush stdout to file.
    check_output(&format!(
        "screen -S {session_name} -X colon \"logfile flush 0^M\""
    ))?;
    Ok(screen_pid)
}

fn process_is_running(pid: i32) -> Result<()> {
    // SAFETY: `kill` with signal 0 only probes existence.
    if unsafe { libc::kill(pid, 0) } == 0 {
        Ok(())
    } else {
        bail!("process {pid} is not running")
    }
}

/// Runs the standard fio workload inside a guest and checks I/O happened.
pub fn guest_run_fio_iteration(ssh: &SshConnection, iteration: usize) -> Result<()> {
    let fio = "fio --filename=/dev/vda --direct=1 --rw=randread --bs=4k \
--ioengine=libaio --iodepth=16 --runtime=10 --numjobs=4 --time_based \
--group_reporting --name=iops-test-job --readonly --output-format=json";
    let stdout = ssh.check_output(fio, Duration::from_secs(100))?.stdout;
    let parsed: serde_json::Value = serde_json::from_str(&stdout).context("parsing fio output")?;
    let total_read = parsed["jobs"][0]["read"]["io_bytes"]
        .as_u64()
        .ok_or_else(|| anyhow!("fio output has no jobs[0].read.io_bytes"))?;
    if total_read == 0 {
        bail!("fio iteration {iteration}: no bytes read from block device");
    }
    Ok(())
}

/// Verifies the guest filesystem is intact (`fsck -n`).
pub fn check_filesystem(ssh: &SshConnection, disk_fmt: &str, disk: &str) -> Result<()> {
    if disk_fmt == "squashfs" {
        return Ok(());
    }
    ssh.check_output(
        &format!("fsck.{disk_fmt} -n {disk}"),
        Duration::from_secs(100),
    )?;
    Ok(())
}

/// Checks that `/dev/hwrng` yields data.
pub fn check_entropy(ssh: &SshConnection) -> Result<()> {
    ssh.check_output(
        "dd if=/dev/hwrng of=/dev/null bs=4096 count=1",
        Duration::from_secs(100),
    )?;
    Ok(())
}

/// Pushes random bytes to the guest and compares the guest-side sha256.
pub fn check_network_data_integrity(ssh: &SshConnection, size_bytes: usize) -> Result<()> {
    let payload: Vec<u8> = (0..size_bytes).map(|i| (i * 31 + 7) as u8).collect();
    let host_hash = sha256_hex(&payload);
    let b64 = base64_encode(&payload);
    let stdout = ssh
        .check_output(
            &format!("echo {b64} | base64 -d | sha256sum"),
            Duration::from_secs(100),
        )?
        .stdout;
    let guest_hash = stdout
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    if guest_hash != host_hash {
        bail!("Guest hash {guest_hash} does not match host hash {host_hash}");
    }
    Ok(())
}

/// Minimal base64 encoder (std only, no extra dependency).
pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(triple >> 18) as usize & 0x3f] as char);
        out.push(TABLE[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// SHA-256, used for the network integrity check (std only).
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h;
        for i in 0..64 {
            let s1 = a[4].rotate_right(6) ^ a[4].rotate_right(11) ^ a[4].rotate_right(25);
            let ch = (a[4] & a[5]) ^ (!a[4] & a[6]);
            let t1 = a[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a[0].rotate_right(2) ^ a[0].rotate_right(13) ^ a[0].rotate_right(22);
            let maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
            let t2 = s0.wrapping_add(maj);
            a[7] = a[6];
            a[6] = a[5];
            a[5] = a[4];
            a[4] = a[3].wrapping_add(t1);
            a[3] = a[2];
            a[2] = a[1];
            a[1] = a[0];
            a[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(a[i]);
        }
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Firecracker crate version taken from `src/firecracker/Cargo.toml`.
pub fn get_firecracker_version_from_toml() -> Result<String> {
    let manifest = crate::defs::workspace_dir().join("src/firecracker/Cargo.toml");
    let contents = std::fs::read_to_string(&manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let mut in_package = false;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            if let Some(rest) = line.strip_prefix("version") {
                let value = rest.trim_start().trim_start_matches('=').trim();
                return Ok(value.trim_matches('"').to_string());
            }
        }
    }
    bail!("no version found in {}", manifest.display())
}

/// `/proc/<pid>/status`'s `VmHWM` in bytes, useful for peak-RSS assertions.
pub fn peak_resident_memory(pid: i32) -> Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("VmHWM not found for pid {pid}"))?;
    Ok(kib * 1024)
}

/// Device and inode of a path, used to decide hardlink-vs-copy.
pub fn device_id(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)?.dev())
}

/// Waits until a child process is still running (python `wait_process_running`).
pub fn wait_process_running(mut child: Child, timeout: Duration) -> Result<()> {
    retry_for(timeout, Duration::from_millis(500), || {
        match child.try_wait()? {
            None => Ok(()),
            Some(status) => bail!("process exited early: {status}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_reference() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn sha256_matches_reference() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn cmd_builder_preserves_order_and_overrides() {
        let cmd = CmdBuilder::new("firecracker")
            .with_arg("--api-sock", "/tmp/s")
            .with_arg("--id", "x")
            .with_arg("--id", "y")
            .build();
        assert_eq!(cmd, "firecracker --api-sock /tmp/s --id y ");
    }

    #[test]
    fn run_cmd_captures_streams() {
        let out = check_output("echo hi; echo err >&2").unwrap();
        assert_eq!(out.stdout.trim(), "hi");
        assert_eq!(out.stderr.trim(), "err");
        assert!(out.success());
    }

    #[test]
    fn run_cmd_reports_nonzero() {
        let out = run_cmd("exit 3").unwrap();
        assert_eq!(out.returncode, 3);
        assert!(check_output("exit 3").is_err());
    }

    #[test]
    fn active_threads_are_visible() {
        let threads = get_threads(std::process::id() as i32);
        assert!(!threads.is_empty());
    }
}
