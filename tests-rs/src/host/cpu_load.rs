// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! CPU load monitoring, ported from `tests/host_tools/cpu_load.py`.
//!
//! `psutil` is replaced by `crate::utils`' `/proc`-based helpers.
//!
//! `CpuLoadMonitor` is a **background monitor**: python forks a `threading.Thread` subclass, this
//! port keeps a `std::thread`, an `Arc<AtomicBool>` stop flag and a `JoinHandle`. Samples are
//! collected in a `Mutex<Vec<f64>>` that `check_samples` inspects.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::utils;

/// Thread name whose utilization is sampled, i.e. Firecracker's main VMM thread.
pub const FC_THREAD_NAME: &str = "firecracker";

/// Error raised when at least one sample crossed the threshold (`CpuLoadExceededException`).
#[derive(Debug, Clone, PartialEq)]
pub struct CpuLoadExceeded {
    /// Samples that were above the threshold, in percent.
    pub cpu_load_samples: Vec<f64>,
    /// Threshold the samples were compared against, in percent.
    pub threshold: f64,
}

impl fmt::Display for CpuLoadExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // python concatenates "exceeded maximum" and "threshold ..." without a space; keep it.
        write!(
            f,
            "Cpu load samples {:?} exceeded maximumthreshold {}.\n",
            self.cpu_load_samples, self.threshold
        )
    }
}

impl std::error::Error for CpuLoadExceeded {}

/// Background CPU load monitor for one Firecracker thread (`CpuLoadMonitor` in python).
pub struct CpuLoadMonitor {
    process_pid: i32,
    thread_pid: i32,
    threshold: f64,
    samples: Mutex<Vec<f64>>,
    should_stop: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl CpuLoadMonitor {
    /// Python's sampling granularity between two utilization windows, in seconds.
    pub const CPU_LOAD_SAMPLES_TIMEOUT_S: u64 = 1;
    /// Python's pause between two sampling iterations (50 ms).
    pub const SAMPLE_PAUSE: Duration = Duration::from_millis(50);

    /// Creates a monitor for `process_pid` with an explicit utilization threshold in percent.
    pub fn new(process_pid: i32, thread_pid: i32, threshold: f64) -> Self {
        Self {
            process_pid,
            thread_pid,
            threshold,
            samples: Mutex::new(Vec::new()),
            should_stop: Arc::new(AtomicBool::new(false)),
            handle: Mutex::new(None),
        }
    }

    /// Returns the monitored process pid.
    pub fn process_pid(&self) -> i32 {
        self.process_pid
    }

    /// Returns the monitored thread pid (python only stores it; sampling is per process).
    pub fn thread_pid(&self) -> i32 {
        self.thread_pid
    }

    /// Returns the CPU load threshold in percent.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Returns the samples collected so far that were above the threshold.
    pub fn cpu_load_samples(&self) -> Vec<f64> {
        self.samples
            .lock()
            .map(|samples| samples.clone())
            .unwrap_or_default()
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
            .map_err(|_| anyhow!("cpu load monitor handle mutex is poisoned"))?;
        if handle.as_ref().is_some_and(|h| !h.is_finished()) {
            return Err(anyhow!("cpu load monitor is already running"));
        }
        let monitor = Arc::clone(self);
        *handle = Some(thread::spawn(move || monitor.run()));
        Ok(())
    }

    /// Stops the sampling thread and joins it (python `Thread.join`).
    pub fn stop(&self) -> Result<()> {
        self.signal_stop();
        let handle = self
            .handle
            .lock()
            .map_err(|_| anyhow!("cpu load monitor handle mutex is poisoned"))?
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
        Ok(())
    }

    /// Runs `body` with the monitor running, mirroring python's `with CpuLoadMonitor(...)` block.
    pub fn scope<T>(self: &Arc<Self>, body: impl FnOnce() -> Result<T>) -> Result<T> {
        self.start()?;
        let output = body();
        self.check_samples()?;
        self.stop()?;
        output
    }

    /// Fails with [`CpuLoadExceeded`] when any sample was above the threshold.
    pub fn check_samples(&self) -> Result<()> {
        let samples = self.cpu_load_samples();
        if samples.is_empty() {
            return Ok(());
        }
        Err(CpuLoadExceeded {
            cpu_load_samples: samples,
            threshold: self.threshold,
        }
        .into())
    }

    /// Body of the sampling thread (python `CpuLoadMonitor.run`).
    fn run(self: Arc<Self>) {
        while !self.should_stop.load(Ordering::SeqCst) {
            let utilization = utils::get_cpu_utilization(
                self.process_pid,
                Duration::from_secs(Self::CPU_LOAD_SAMPLES_TIMEOUT_S),
            );
            // A missing `firecracker` thread means the process is gone or not started yet; python
            // swallows the resulting `KeyError`.
            if let Some(value) = utilization.get(FC_THREAD_NAME) {
                if *value > self.threshold {
                    if let Ok(mut samples) = self.samples.lock() {
                        samples.push(*value);
                    }
                }
            }
            thread::sleep(Self::SAMPLE_PAUSE);
        }
    }
}

impl Drop for CpuLoadMonitor {
    /// Signals the sampler on drop so a forgotten monitor cannot spin forever.
    fn drop(&mut self) {
        self.should_stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_samples_means_no_failure() {
        let monitor = CpuLoadMonitor::new(std::process::id() as i32, 1, 45.0);
        assert!(monitor.check_samples().is_ok());
        assert!(monitor.cpu_load_samples().is_empty());
        assert_eq!(monitor.threshold(), 45.0);
    }

    #[test]
    fn recorded_samples_fail_the_check() {
        let monitor = CpuLoadMonitor::new(1, 2, 45.0);
        monitor.samples.lock().expect("lock").push(90.5);
        let err = monitor.check_samples().expect_err("should fail");
        let exceeded = err
            .downcast_ref::<CpuLoadExceeded>()
            .expect("CpuLoadExceeded");
        assert_eq!(exceeded.cpu_load_samples, vec![90.5]);
        assert_eq!(exceeded.threshold, 45.0);
    }

    #[test]
    fn error_message_matches_python_format() {
        let err = CpuLoadExceeded {
            cpu_load_samples: vec![90.5, 91.0],
            threshold: 45.0,
        };
        assert_eq!(
            err.to_string(),
            "Cpu load samples [90.5, 91.0] exceeded maximumthreshold 45.\n"
        );
    }

    #[test]
    fn monitor_of_dead_pid_collects_nothing() {
        let monitor = Arc::new(CpuLoadMonitor::new(i32::MAX, i32::MAX, 0.0));
        monitor.start().expect("start succeeds");
        monitor.stop().expect("stop succeeds");
        assert!(monitor.check_samples().is_ok());
        assert!(!monitor.is_alive());
    }
}
