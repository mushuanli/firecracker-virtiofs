// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kernel ftrace helpers, ported from `tests/framework/utils_ftrace.py`.
//!
//! Python uses a `contextlib.contextmanager`; the port offers both an explicit
//! [`FtraceEvents`] guard (mount on construction, umount on drop) and
//! [`with_ftrace_events`], which propagates the teardown error the way the
//! python `finally` block does.

use anyhow::{Context, Result};

use crate::utils;

/// Default event selector, matching `events: str = "*:*"`.
pub const DEFAULT_EVENTS: &str = "*:*";

/// Mount point of the tracefs instance.
pub const TRACING_DIR: &str = "/sys/kernel/tracing";

/// Commands enabling tracing for `events`, in the order python runs them.
///
/// Tracing is system wide because the harness lives in a pid namespace that
/// `trace-cmd` cannot translate; only one VM runs at a time, so every KVM event
/// belongs to it.
pub fn enable_commands(events: &str) -> Vec<String> {
    vec![
        format!("mount -t tracefs nodev {TRACING_DIR}"),
        format!("echo > {TRACING_DIR}/trace"),
        format!("echo {events} > {TRACING_DIR}/set_event"),
        format!("echo nop > {TRACING_DIR}/current_tracer"),
        format!("echo 1 > {TRACING_DIR}/tracing_on"),
    ]
}

/// Commands disabling tracing, in the order python runs them.
pub fn disable_commands() -> Vec<String> {
    vec![
        format!("echo 0 > {TRACING_DIR}/tracing_on"),
        format!("umount {TRACING_DIR}"),
    ]
}

/// Enables ftrace events while alive and disables them on drop.
///
/// Assumes the caller is the only test executing on the host.
#[derive(Debug)]
pub struct FtraceEvents {
    events: String,
    enabled: bool,
}

impl FtraceEvents {
    /// Creates a guard for the default `*:*` event selector without enabling it.
    pub fn new() -> Self {
        Self::with_events(DEFAULT_EVENTS)
    }

    /// Creates a guard for `events` without enabling it.
    pub fn with_events(events: &str) -> Self {
        Self {
            events: events.to_string(),
            enabled: false,
        }
    }

    /// The event selector this guard uses.
    pub fn events(&self) -> &str {
        &self.events
    }

    /// Mounts tracefs and starts tracing; fails if tracing was already started.
    pub fn enable(&mut self) -> Result<()> {
        if self.enabled {
            anyhow::bail!("ftrace events already enabled");
        }
        for cmd in enable_commands(&self.events) {
            utils::check_output(&cmd).with_context(|| format!("enabling ftrace: {cmd}"))?;
        }
        self.enabled = true;
        Ok(())
    }

    /// Stops tracing and unmounts tracefs; a no-op when never enabled.
    pub fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        self.enabled = false;
        for cmd in disable_commands() {
            utils::check_output(&cmd).with_context(|| format!("disabling ftrace: {cmd}"))?;
        }
        Ok(())
    }

    /// Whether tracing is currently enabled by this guard.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for FtraceEvents {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FtraceEvents {
    fn drop(&mut self) {
        // Best effort: `Drop` cannot report errors. Use `with_ftrace_events` or
        // an explicit `disable()` when the teardown error matters.
        let _ = self.disable();
    }
}

/// Runs `op` with ftrace enabled for `events`, always disabling it afterwards.
///
/// The operation error wins over a teardown error, mirroring a python
/// `try/finally` that only reports `finally` failures when the body succeeded.
pub fn with_ftrace_events<T>(events: &str, op: impl FnOnce() -> Result<T>) -> Result<T> {
    let mut guard = FtraceEvents::with_events(events);
    guard.enable()?;
    let outcome = op();
    let teardown = guard.disable();
    match (outcome, teardown) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), _) => Err(err),
        (Ok(_), Err(err)) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_commands_match_python_order() {
        assert_eq!(
            enable_commands("kvm:*"),
            vec![
                "mount -t tracefs nodev /sys/kernel/tracing",
                "echo > /sys/kernel/tracing/trace",
                "echo kvm:* > /sys/kernel/tracing/set_event",
                "echo nop > /sys/kernel/tracing/current_tracer",
                "echo 1 > /sys/kernel/tracing/tracing_on",
            ]
        );
    }

    #[test]
    fn disable_commands_match_python_order() {
        assert_eq!(
            disable_commands(),
            vec![
                "echo 0 > /sys/kernel/tracing/tracing_on",
                "umount /sys/kernel/tracing",
            ]
        );
    }

    #[test]
    fn guard_defaults_to_star_events_and_stays_disabled() {
        let guard = FtraceEvents::new();
        assert_eq!(guard.events(), DEFAULT_EVENTS);
        assert!(!guard.is_enabled());
        assert_eq!(FtraceEvents::default().events(), DEFAULT_EVENTS);
    }

    #[test]
    fn disabling_a_disabled_guard_is_a_noop() {
        let mut guard = FtraceEvents::with_events("kvm:*");
        assert!(guard.disable().is_ok(), "no-op teardown never fails");
    }
}
