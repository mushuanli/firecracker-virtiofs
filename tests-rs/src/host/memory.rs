// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! RSS memory monitoring, ported from `tests/host_tools/memory.py`.
//!
//! `psutil.Process.memory_maps()` is replaced by a direct `/proc/<pid>/smaps` parser: guest memory
//! mappings are skipped so the sampled value is Firecracker's own (VMM) overhead.
//!
//! `MemoryMonitor` is a **background monitor**: python forks a `threading.Thread` subclass, this
//! port keeps a `std::thread` plus an `Arc<AtomicBool>` stop flag and a `JoinHandle`. Sampling
//! happens off the caller's thread; `check_samples` is what surfaces an exceedance, and
//! [`MemoryMonitor::scope`] mirrors python's `with MemoryMonitor(...)` block.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};

use crate::defs::host_arch;

/// What the monitor needs to know about a microVM.
pub trait MemoryMonitoredVm: Send + Sync {
    /// Firecracker process id, or `None` while the VM has not been spawned.
    fn firecracker_pid(&self) -> Option<i32>;
    /// Configured guest memory size in bytes, or `None` before the machine config is applied.
    fn mem_size_bytes(&self) -> Option<u64>;
}

/// One `/proc/<pid>/smaps` VMA reduced to the two values the monitor needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmapsRegion {
    /// Virtual size of the mapping in bytes (the `Size:` field).
    pub size: u64,
    /// Resident set size of the mapping in bytes (the `Rss:` field).
    pub rss: u64,
}

/// Error raised when the sampled overhead RSS crossed the active threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryUsageExceeded {
    /// Sampled overhead RSS in bytes.
    pub usage: u64,
    /// Threshold that was exceeded, in bytes.
    pub threshold: u64,
}

impl fmt::Display for MemoryUsageExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mib = (1u64 << 20) as f64;
        // `{:?}` prints `5.0` like python's float formatting of `threshold / (1 << 20)`.
        write!(
            f,
            "Memory usage ({:.2} MiB) exceeded maximum threshold ({:?} MiB)",
            self.usage as f64 / mib,
            self.threshold as f64 / mib
        )
    }
}

impl std::error::Error for MemoryUsageExceeded {}

/// Parses `/proc/<pid>/smaps` contents into per-VMA size/rss pairs (sizes in bytes).
pub fn parse_smaps(content: &str) -> Vec<SmapsRegion> {
    let mut regions = Vec::new();
    let mut current: Option<SmapsRegion> = None;
    for line in content.lines() {
        if is_mapping_header(line) {
            if let Some(region) = current.take() {
                regions.push(region);
            }
            current = Some(SmapsRegion { size: 0, rss: 0 });
            continue;
        }
        let Some(region) = current.as_mut() else {
            continue;
        };
        if let Some(value) = smaps_kib_value(line, "Size:") {
            region.size = value;
        } else if let Some(value) = smaps_kib_value(line, "Rss:") {
            region.rss = value;
        }
    }
    if let Some(region) = current {
        regions.push(region);
    }
    regions
}

fn is_mapping_header(line: &str) -> bool {
    let Some(range) = line.split_whitespace().next() else {
        return false;
    };
    let mut parts = range.split('-');
    let (Some(start), Some(end)) = (parts.next(), parts.next()) else {
        return false;
    };
    parts.next().is_none()
        && !start.is_empty()
        && !end.is_empty()
        && start.chars().all(|c| c.is_ascii_hexdigit())
        && end.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parses a `Size:`/`Rss:` line of `smaps` (or `smaps_rollup`) into bytes.
fn smaps_kib_value(line: &str, key: &str) -> Option<u64> {
    let rest = line.strip_prefix(key)?;
    let kib: u64 = rest.split_whitespace().next()?.parse().ok()?;
    Some(kib * 1024)
}

/// Sums the RSS of every VMA that is not a guest memory region.
pub fn overhead_rss(regions: &[SmapsRegion], guest_mem_bytes: u64, arch: &str) -> u64 {
    regions
        .iter()
        .filter(|region| !is_guest_mem(region.size, guest_mem_bytes, arch))
        .map(|region| region.rss)
        .sum()
}

/// Returns `true` when `size` belongs to guest memory under the x86_64 physical layout.
pub fn is_guest_mem_x86(size: u64, guest_mem_bytes: u64) -> bool {
    // It could be bigger if hotplugging is enabled; if it is, it is likely not from Firecracker
    // because we do not have allocations that large.
    size >= guest_mem_bytes
        || [
            // Memory fits before the first gap.
            guest_mem_bytes,
            // Guest memory spans at least two regions and fits before the second gap.
            MemoryMonitor::X86_32BIT_MEMORY_GAP_START,
            // Guest memory spans exactly two regions.
            guest_mem_bytes.saturating_sub(MemoryMonitor::X86_32BIT_MEMORY_GAP_START),
            // Guest memory fills the space between the two gaps.
            MemoryMonitor::X86_64BIT_MEMORY_GAP_START
                - MemoryMonitor::X86_32BIT_MEMORY_GAP_START
                - MemoryMonitor::X86_32BIT_MEMORY_GAP_SIZE,
            // Guest memory spans three regions, this is what remains past the second gap.
            guest_mem_bytes.saturating_sub(MemoryMonitor::X86_64BIT_MEMORY_GAP_START)
                + MemoryMonitor::X86_32BIT_MEMORY_GAP_SIZE,
        ]
        .contains(&size)
}

/// Returns `true` when `size` belongs to guest memory under the ARM64 physical layout.
pub fn is_guest_mem_aarch64(size: u64, guest_mem_bytes: u64) -> bool {
    size >= guest_mem_bytes
        || [
            // Guest memory fits before the gap.
            guest_mem_bytes,
            // Guest memory fills the space before the gap.
            MemoryMonitor::ARM64_64BIT_MEMORY_GAP_START - MemoryMonitor::ARM64_MEMORY_START,
            // Guest memory spans two regions, this is what remains past the gap.
            guest_mem_bytes.saturating_sub(MemoryMonitor::ARM64_64BIT_MEMORY_GAP_START)
                + MemoryMonitor::ARM64_MEMORY_START,
        ]
        .contains(&size)
}

/// Dispatches the guest memory check to the layout of `arch`.
pub fn is_guest_mem(size: u64, guest_mem_bytes: u64, arch: &str) -> bool {
    if arch == "x86_64" {
        return is_guest_mem_x86(size, guest_mem_bytes);
    }
    is_guest_mem_aarch64(size, guest_mem_bytes)
}

/// Background RSS sampler for a Firecracker process (`MemoryMonitor` in python).
pub struct MemoryMonitor {
    vm: Arc<dyn MemoryMonitoredVm>,
    /// Threshold used while the VM runs from a cold boot.
    threshold_booted: u64,
    /// Threshold used while a snapshot is being created.
    threshold_snapshot: u64,
    /// Threshold used for a restored VM.
    threshold_restored: u64,
    threshold: AtomicU64,
    period: Duration,
    should_stop: AtomicBool,
    current_rss: AtomicU64,
    exceeded: AtomicBool,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl MemoryMonitor {
    /// Guest memory is split into a second region above 3 GiB; that gap starts at 3 GiB.
    pub const X86_32BIT_MEMORY_GAP_START: u64 = 3 << 30;
    /// Length of the 32-bit memory gap: 1 GiB.
    pub const X86_32BIT_MEMORY_GAP_SIZE: u64 = 1 << 30;
    /// Above 255 GiB guest memory is split into a third region; that gap starts at 256 GiB.
    pub const X86_64BIT_MEMORY_GAP_START: u64 = 256 << 30;
    /// ARM64 has a single gap starting at 256 GiB.
    pub const ARM64_64BIT_MEMORY_GAP_START: u64 = 256 << 30;
    /// ARM64 guest memory starts at the 2 GiB offset.
    pub const ARM64_MEMORY_START: u64 = 2 << 30;
    /// Default sampling period of the python monitor (10 ms).
    pub const DEFAULT_PERIOD: Duration = Duration::from_millis(10);
    /// Default overhead threshold for a booted VM: 5 MiB.
    pub const DEFAULT_THRESHOLD_BOOTED: u64 = 5 << 20;
    /// Default overhead threshold while creating a snapshot: 7 MiB.
    pub const DEFAULT_THRESHOLD_SNAPSHOT: u64 = 7 << 20;
    /// Default overhead threshold for a restored VM: 5 MiB.
    pub const DEFAULT_THRESHOLD_RESTORED: u64 = 5 << 20;

    /// Creates a monitor with explicit thresholds and sampling period.
    pub fn new(
        vm: Arc<dyn MemoryMonitoredVm>,
        threshold_booted: u64,
        threshold_snapshot: u64,
        threshold_restored: u64,
        period: Duration,
    ) -> Self {
        Self {
            vm,
            threshold_booted,
            threshold_snapshot,
            threshold_restored,
            // Start with the booted threshold, like python.
            threshold: AtomicU64::new(threshold_booted),
            period,
            should_stop: AtomicBool::new(false),
            current_rss: AtomicU64::new(0),
            exceeded: AtomicBool::new(false),
            handle: Mutex::new(None),
        }
    }

    /// Creates a monitor with python's default thresholds and period.
    pub fn with_defaults(vm: Arc<dyn MemoryMonitoredVm>) -> Self {
        Self::new(
            vm,
            Self::DEFAULT_THRESHOLD_BOOTED,
            Self::DEFAULT_THRESHOLD_SNAPSHOT,
            Self::DEFAULT_THRESHOLD_RESTORED,
            Self::DEFAULT_PERIOD,
        )
    }

    /// Returns the currently active threshold in bytes.
    pub fn threshold(&self) -> u64 {
        self.threshold.load(Ordering::SeqCst)
    }

    /// Returns the threshold used for a booted VM.
    pub fn threshold_booted(&self) -> u64 {
        self.threshold_booted
    }

    /// Returns the threshold used while creating a snapshot.
    pub fn threshold_snapshot(&self) -> u64 {
        self.threshold_snapshot
    }

    /// Returns the threshold used for a restored VM.
    pub fn threshold_restored(&self) -> u64 {
        self.threshold_restored
    }

    /// Returns the sampling period.
    pub fn period(&self) -> Duration {
        self.period
    }

    /// Activates the restored-VM threshold (python `set_threshold_for_restored_vm`).
    pub fn set_threshold_for_restored_vm(&self) {
        self.threshold
            .store(self.threshold_restored, Ordering::SeqCst);
    }

    /// Activates the snapshot threshold (python `set_threshold_for_snapshot`).
    pub fn set_threshold_for_snapshot(&self) {
        self.threshold
            .store(self.threshold_snapshot, Ordering::SeqCst);
    }

    /// Signals the sampling thread to stop (python `signal_stop`).
    pub fn signal_stop(&self) {
        self.should_stop.store(true, Ordering::SeqCst);
    }

    /// Returns `true` while the background sampling thread is alive.
    pub fn is_alive(&self) -> bool {
        match self.handle.lock() {
            Ok(handle) => handle.as_ref().is_some_and(|h| !h.is_finished()),
            Err(_) => false,
        }
    }

    /// Starts the background sampling thread (python `Thread.start`).
    pub fn start(self: &Arc<Self>) -> Result<()> {
        let mut handle = self
            .handle
            .lock()
            .map_err(|_| anyhow!("memory monitor handle mutex is poisoned"))?;
        if handle.as_ref().is_some_and(|h| !h.is_finished()) {
            return Err(anyhow!("memory monitor is already running"));
        }
        let monitor = Arc::clone(self);
        *handle = Some(thread::spawn(move || monitor.run()));
        Ok(())
    }

    /// Stops the sampling thread, waiting up to one second like python's `stop`.
    pub fn stop(&self) -> Result<()> {
        if !self.is_alive() {
            self.signal_stop();
            return Ok(());
        }
        self.signal_stop();
        let mut slot = self
            .handle
            .lock()
            .map_err(|_| anyhow!("memory monitor handle mutex is poisoned"))?;
        let Some(handle) = slot.take() else {
            return Ok(());
        };
        // python uses `join(timeout=1)`: give the sampler a bounded grace period, then leave it
        // detached instead of deadlocking the caller.
        let deadline = Instant::now() + Duration::from_secs(1);
        while !handle.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if handle.is_finished() {
            let _ = handle.join();
        }
        Ok(())
    }

    /// Runs `body` with the monitor running, mirroring python's `with MemoryMonitor(...)` block.
    pub fn scope<T>(self: &Arc<Self>, body: impl FnOnce() -> Result<T>) -> Result<T> {
        self.start()?;
        let guard = MemoryMonitorGuard {
            monitor: Arc::clone(self),
        };
        let output = body();
        guard.finish()?;
        output
    }

    /// Returns the last sampled overhead RSS, after waiting for a fresh sample (python property).
    pub fn current_rss(&self) -> u64 {
        // Give the sampler time to publish another datapoint, like the python property does.
        thread::sleep(2 * self.period);
        self.sampled_rss()
    }

    /// Returns the last sampled overhead RSS without waiting for a new sample.
    pub fn sampled_rss(&self) -> u64 {
        self.current_rss.load(Ordering::SeqCst)
    }

    /// Returns `true` when sampling latched an exceedance.
    pub fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::SeqCst)
    }

    /// Fails with [`MemoryUsageExceeded`] if any sample crossed the threshold (python
    pub fn check_samples(&self) -> Result<()> {
        if self.exceeded() {
            return Err(MemoryUsageExceeded {
                usage: self.sampled_rss(),
                threshold: self.threshold(),
            }
            .into());
        }
        Ok(())
    }

    /// Body of the sampling thread (python `MemoryMonitor.run`).
    fn run(self: Arc<Self>) {
        let Some(pid) = self.vm.firecracker_pid() else {
            return;
        };
        let guest_mem_bytes = self.vm.mem_size_bytes().unwrap_or(0);
        let smaps_path = format!("/proc/{pid}/smaps");
        while !self.should_stop.load(Ordering::SeqCst) {
            // A vanished process ends the sampler, like `psutil.NoSuchProcess` in python.
            let Ok(contents) = std::fs::read_to_string(&smaps_path) else {
                return;
            };
            let total = overhead_rss(&parse_smaps(&contents), guest_mem_bytes, host_arch());
            self.current_rss.store(total, Ordering::SeqCst);
            if total > self.threshold() {
                self.exceeded.store(true, Ordering::SeqCst);
                return;
            }
            thread::sleep(self.period);
        }
    }
}

impl Drop for MemoryMonitor {
    /// Signals the sampler on drop; python's monitor thread is a daemon.
    fn drop(&mut self) {
        self.should_stop.store(true, Ordering::SeqCst);
    }
}

/// Scope guard returned by [`MemoryMonitor::scope`], the `with`-block counterpart.
pub struct MemoryMonitorGuard {
    monitor: Arc<MemoryMonitor>,
}

impl MemoryMonitorGuard {
    /// Stops the monitor and validates the collected samples (python `__exit__`).
    pub fn finish(self) -> Result<()> {
        self.monitor.stop()?;
        self.monitor.check_samples()
    }
}

impl Drop for MemoryMonitorGuard {
    /// Best-effort stop when the guard is dropped without [`MemoryMonitorGuard::finish`].
    fn drop(&mut self) {
        let _ = self.monitor.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMAPS: &str = "\
5555d000-5556d000 rw-p 00000000 00:00 0                                  [heap]
Size:               1024 kB
Rss:                 512 kB
Pss:                 512 kB
7f0000000000-7f4000000000 rw-p 00000000 00:00 0
Size:            4194304 kB
Rss:                   0 kB
700000000000-700000100000 r-xp 00000000 fd:01 1234                   /firecracker
Size:                 64 kB
Rss:                  32 kB
";

    #[test]
    fn smaps_parser_reads_size_and_rss_in_bytes() {
        let regions = parse_smaps(SMAPS);
        assert_eq!(regions.len(), 3);
        assert_eq!(
            regions[0],
            SmapsRegion {
                size: 1024 * 1024,
                rss: 512 * 1024
            }
        );
        assert_eq!(regions[1].size, 4194304 * 1024);
        assert_eq!(regions[2].rss, 32 * 1024);
    }

    #[test]
    fn overhead_rss_skips_guest_memory_mapping() {
        let regions = parse_smaps(SMAPS);
        // 4 GiB guest mapping is recognised as guest memory and contributes nothing.
        let total = overhead_rss(&regions, 4 << 30, "x86_64");
        assert_eq!(total, 512 * 1024 + 32 * 1024);
    }

    #[test]
    fn guest_mem_layouts() {
        // guested memory with no split.
        assert!(is_guest_mem_x86(1 << 30, 1 << 30));
        // anything bigger than guest memory counts as guest memory.
        assert!(is_guest_mem_x86((1 << 30) + 4096, 1 << 30));
        // >3 GiB guest memory is split at the 32-bit gap.
        let guest = 4 << 30;
        assert!(is_guest_mem_x86(
            MemoryMonitor::X86_32BIT_MEMORY_GAP_START,
            guest
        ));
        assert!(is_guest_mem_x86(
            guest - MemoryMonitor::X86_32BIT_MEMORY_GAP_START,
            guest
        ));
        // Unrelated 4 KiB mapping is not guest memory.
        assert!(!is_guest_mem_x86(4 * 1024, guest));
        // ARM64: split at 256 GiB offset by the 2 GiB memory start.
        let arm_guest = 256 << 30;
        assert!(is_guest_mem_aarch64(
            MemoryMonitor::ARM64_64BIT_MEMORY_GAP_START - MemoryMonitor::ARM64_MEMORY_START,
            arm_guest
        ));
        assert!(!is_guest_mem_aarch64(8 * 1024, 1 << 30));
        assert!(!is_guest_mem(8 * 1024, 1 << 30, "x86_64"));
        assert!(!is_guest_mem(8 * 1024, 1 << 30, "aarch64"));
    }

    #[test]
    fn error_message_matches_python_format() {
        let err = MemoryUsageExceeded {
            usage: 6 * (1 << 20),
            threshold: 5 << 20,
        };
        assert_eq!(
            err.to_string(),
            "Memory usage (6.00 MiB) exceeded maximum threshold (5.0 MiB)"
        );
    }

    struct FakeVm {
        pid: Option<i32>,
        mem: Option<u64>,
    }

    impl MemoryMonitoredVm for FakeVm {
        fn firecracker_pid(&self) -> Option<i32> {
            self.pid
        }

        fn mem_size_bytes(&self) -> Option<u64> {
            self.mem
        }
    }

    #[test]
    fn thresholds_switch_and_default_to_booted() {
        let monitor = MemoryMonitor::new(
            Arc::new(FakeVm {
                pid: None,
                mem: None,
            }),
            1 << 20,
            2 << 20,
            3 << 20,
            Duration::from_millis(1),
        );
        assert_eq!(monitor.threshold(), 1 << 20);
        monitor.set_threshold_for_snapshot();
        assert_eq!(monitor.threshold_snapshot(), monitor.threshold());
        monitor.set_threshold_for_restored_vm();
        assert_eq!(monitor.threshold_restored(), monitor.threshold());
    }

    #[test]
    fn check_samples_passes_when_nothing_sampled() {
        let monitor = MemoryMonitor::with_defaults(Arc::new(FakeVm {
            pid: None,
            mem: None,
        }));
        assert!(monitor.check_samples().is_ok());
        assert!(!monitor.exceeded());
        assert_eq!(monitor.current_rss(), 0);
    }

    #[test]
    fn monitor_without_pid_never_starts_sampling() {
        let monitor = MemoryMonitor::with_defaults(Arc::new(FakeVm {
            pid: None,
            mem: None,
        }));
        let monitor = Arc::new(monitor);
        monitor.start().expect("first start succeeds");
        monitor.stop().expect("stop succeeds");
        assert!(monitor.check_samples().is_ok());
        assert!(!monitor.is_alive());
    }
}
