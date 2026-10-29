// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side test tooling, ported from `tests/host_tools/*.py`.
//!
//! The module tree mirrors the python package one to one, so both trees can be read side by side:
//!
//! | Rust module | python source |
//! | --- | --- |
//! | [`cargo_build`] | `tests/host_tools/cargo_build.py` |
//! | [`cpu_load`] | `tests/host_tools/cpu_load.py` |
//! | [`drive`] | `tests/host_tools/drive.py` |
//! | [`fcmetrics`] | `tests/host_tools/fcmetrics.py` |
//! | [`memory`] | `tests/host_tools/memory.py` |
//! | [`metrics`] | `tests/host_tools/metrics.py` |
//! | [`network`] | `tests/host_tools/network.py` (host helpers) + `tests/host_tools/udp_offload.py` |
//! | [`proc`] | `tests/host_tools/proc.py` |
//!
//! The python monitors (`MemoryMonitor`, `CpuLoadMonitor`, `FCMetricsMonitor`) are `threading.Thread`
//! subclasses; here they are plain structs that own a `std::thread`, an `Arc<AtomicBool>` stop flag
//! and a `JoinHandle`, so they can run as background monitors without a python runtime.

pub mod cargo_build;
pub mod cpu_load;
pub mod drive;
pub mod fcmetrics;
pub mod memory;
pub mod metrics;
pub mod network;
pub mod proc;

pub use cargo_build::{
    build_fuzzing, build_gdb, cargo, cargo_command, cargo_test, default_target, default_target_dir,
    gcc_compile, get_binary, get_example, get_rustflags, nightly_toolchain, run_rebase_snap_bin,
    run_seccompiler_bin, run_snap_editor_rebase, CargoOptions,
};
pub use cpu_load::{CpuLoadExceeded, CpuLoadMonitor};
pub use drive::{FilesystemFile, KNOWN_FILEFS_FORMATS};
pub use fcmetrics::{
    find_unused_metrics, flush_fc_metrics_to_cw, get_emf_unit_for_fc_metrics,
    is_file_test_or_definition, validate_fc_metrics, FCMetricsMonitor, FcDeviceMetrics, MetricsVm,
};
pub use memory::{MemoryMonitor, MemoryMonitoredVm, MemoryUsageExceeded, SmapsRegion};
pub use metrics::{get_metrics_logger, MetricsWrapper};
pub use network::{send_udp_with_offload, UdpEchoServer};
pub use proc::proc_type;
