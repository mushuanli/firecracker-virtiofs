// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Common defines, ported from `tests/framework/defs.py`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Firecracker's binary name.
pub const FC_BINARY_NAME: &str = "firecracker";

/// Maximum accepted duration of an API call, in milliseconds.
pub const MAX_API_CALL_DURATION_MS: u64 = 700;

/// Default test session root directory path.
pub const DEFAULT_TEST_SESSION_ROOT_PATH: &str = "/srv";

/// Guest kernels the suite supports (`<major>.<minor>`).
pub const SUPPORTED_HOST_KERNELS: [&str; 3] = ["5.10", "6.1", "6.18"];

/// Folder containing the JSON seccomp filters.
pub fn seccomp_json_dir() -> PathBuf {
    workspace_dir().join("resources/seccomp")
}

/// The Firecracker sources workspace dir.
///
/// Equivalent of `Path(__file__).parent.parent.parent.resolve()` in
/// `framework/defs.py`: the crate lives at `<workspace>/tests-rs`.
pub fn workspace_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        // `CARGO_MANIFEST_DIR` is `<workspace>/tests-rs` at build time. Fall
        // back to walking up from the executable for installed binaries.
        if let Some(dir) = option_env!("CARGO_MANIFEST_DIR") {
            let candidate = Path::new(dir);
            if candidate.join("Cargo.toml").exists() {
                return candidate
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| candidate.to_path_buf());
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            for ancestor in exe.ancestors() {
                if ancestor.join("SPECIFICATION.md").exists() && ancestor.join("src").is_dir() {
                    return ancestor.to_path_buf();
                }
            }
        }
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    })
}

/// `build/` inside the workspace.
pub fn local_build_path() -> PathBuf {
    workspace_dir().join("build")
}

/// Directory holding the freshly built release binaries.
pub fn default_binary_dir() -> PathBuf {
    local_build_path()
        .join("cargo_target")
        .join(format!("{}-unknown-linux-musl", host_arch()))
        .join("release")
}

/// The host architecture as spelled in the musl target triple.
pub fn host_arch() -> &'static str {
    // `env::consts::ARCH` is `x86_64` / `aarch64`, matching `platform.machine()`
    // on the hosts the suite supports.
    std::env::consts::ARCH
}

/// Test artifacts directory (`/srv/test_artifacts` when running in devctr,
/// otherwise the checked out `build/<id>` pointed at by
/// `build/current_artifacts`).
pub fn artifact_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let shared = Path::new(DEFAULT_TEST_SESSION_ROOT_PATH).join("test_artifacts");
        if shared.exists() {
            return shared;
        }
        let pointer = local_build_path().join("current_artifacts");
        match std::fs::read_to_string(&pointer) {
            Ok(contents) => workspace_dir().join(contents.trim()),
            // No `current_artifacts` pointer: behave like the python code with
            // an empty glob instead of panicking, so `--help`-style commands
            // keep working outside a prepared session.
            Err(_) => workspace_dir().join("build/no-artifacts"),
        }
    })
}

/// Convenience wrapper returning an owned artifacts dir.
pub fn artifact_dir_owned() -> PathBuf {
    artifact_dir().to_path_buf()
}

/// Parses a byte size such as `1MB` / `2GB` (see `tools/sandbox.py`).
pub fn parse_byte_size(param: &str) -> Option<u64> {
    let upper = param.trim().to_uppercase();
    let (digits, multiplier) = upper
        .strip_suffix("MB")
        .map(|d| (d, 1u64 << 20))
        .or_else(|| upper.strip_suffix("GB").map(|d| (d, 1u64 << 30)))?;
    digits.trim().parse::<u64>().ok().map(|v| v * multiplier)
}

/// Extracts `major.minor.patch` from the running host kernel release.
pub fn host_kernel_version(level: usize) -> String {
    let release = uname_release();
    let mut dots = 0usize;
    for (idx, ch) in release.char_indices() {
        if ch == '.' {
            dots += 1;
        }
        if dots > level || (!ch.is_ascii_digit() && ch != '.') {
            return release[..idx].to_string();
        }
    }
    release
}

fn uname_release() -> String {
    // SAFETY: `uname` writes into a zeroed `utsname` that we own.
    let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::uname(&mut buf) };
    if rc != 0 {
        return String::new();
    }
    let bytes: Vec<u8> = buf
        .release
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_byte_size_mb_gb() {
        assert_eq!(parse_byte_size("1MB"), Some(1 << 20));
        assert_eq!(parse_byte_size("3gb"), Some(3 << 30));
        assert_eq!(parse_byte_size("0.5MB"), None);
        assert_eq!(parse_byte_size("1024"), None);
    }

    #[test]
    fn workspace_dir_contains_specification() {
        assert!(workspace_dir().join("Cargo.toml").exists());
        assert!(workspace_dir().join("tests").is_dir());
    }
}
