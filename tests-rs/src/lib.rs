// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust port of the Firecracker python test harness.
//!
//! The module tree mirrors `tests/framework`, `tests/host_tools` and the
//! standalone scripts under `tools/*.py` so both trees can be read side by
//! side. See `PORTING.md` for the file-by-file mapping.

pub mod ab_test;
pub mod artifacts;
pub mod cpu_templates;
pub mod defs;
pub mod drive;
pub mod fio;
pub mod ftrace;
pub mod guest;
pub mod guest_stats;
pub mod host;
pub mod http_api;
pub mod hugepages;
pub mod imdsv2;
pub mod iperf;
pub mod jailer;
pub mod kvm;
pub mod microvm;
pub mod microvm_helpers;
pub mod network;
pub mod pipeline;
pub mod properties;
pub mod repo;
pub mod snapshot;
pub mod static_analysis;
pub mod swagger;
pub mod uffd;
pub mod utils;
pub mod vm_backend;
pub mod vsock;

pub use microvm::{CpuTemplate, MicroVm, MicroVmFactory};
pub use snapshot::{Snapshot, SnapshotType};
pub use vm_backend::VmBackend;

/// Result type used across the harness.
pub type Result<T> = anyhow::Result<T>;
