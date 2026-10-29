// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared cargo build helpers, ported from `tests/host_tools/cargo_build.py`.
//!
//! `platform.machine()` becomes [`crate::defs::host_arch`]; the `@with_filelock` decorator is
//! replaced by an explicit `flock` on `/tmp/<name>.lock` around the same critical section.
//!
//! `run_seccompiler_bin` takes the filter JSON as `Option<&Path>`: `None` selects the default
//! filter for the current target, replacing python's `json_path == SECCOMP_JSON_DIR` sentinel.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::defs;
use crate::utils;

/// Rust target triple used for the release builds of the harness.
pub fn default_target() -> String {
    format!("{}-unknown-linux-musl", defs::host_arch())
}

/// Release directory inside the target triple, as spelled in python's `DEFAULT_TARGET_DIR`.
pub fn default_target_dir() -> String {
    format!("{}/release/", default_target())
}

/// Keyword-only style arguments of [`cargo`] (python's `env`/`cwd`/`nightly`/`timeout`).
#[derive(Debug, Clone, Default)]
pub struct CargoOptions {
    /// Environment variables exported for the cargo invocation.
    pub env: BTreeMap<String, String>,
    /// Directory cargo runs from (`cd <cwd>` in the generated command).
    pub cwd: Option<PathBuf>,
    /// Run cargo with the installed nightly toolchain.
    pub nightly: bool,
    /// Kill cargo after this duration.
    pub timeout: Option<Duration>,
}

impl CargoOptions {
    /// Returns options that only set `env`.
    pub fn with_env(env: BTreeMap<String, String>) -> Self {
        Self {
            env,
            ..Self::default()
        }
    }
}

/// Returns the name of the installed nightly toolchain (python `nightly_toolchain`).
pub fn nightly_toolchain() -> Result<String> {
    let result = utils::check_output("rustup toolchain list | grep nightly")
        .context("listing rustup toolchains")?;
    Ok(result.stdout.trim().to_string())
}

/// Renders the shell command python's `cargo` helper would run.
pub fn cargo_command(
    subcommand: &str,
    cargo_args: &str,
    subcommand_args: &str,
    options: &CargoOptions,
) -> Result<String> {
    let toolchain = if options.nightly {
        format!("+{}", nightly_toolchain()?)
    } else {
        String::new()
    };
    let env_string = options
        .env
        .iter()
        .map(|(key, value)| format!("{key}=\"{value}\""))
        .collect::<Vec<_>>()
        .join(" ");
    // Same tokens as python's f-string, with the empty placeholders collapsed so the rendered
    // command stays readable (shell semantics are unchanged).
    let mut parts: Vec<String> = Vec::new();
    if !env_string.is_empty() {
        parts.push(env_string);
    }
    parts.push("cargo".to_string());
    if !toolchain.is_empty() {
        parts.push(toolchain);
    }
    parts.push(subcommand.to_string());
    if !cargo_args.is_empty() {
        parts.push(cargo_args.to_string());
    }
    parts.push("--".to_string());
    if !subcommand_args.is_empty() {
        parts.push(subcommand_args.to_string());
    }
    let command = parts.join(" ");
    Ok(match &options.cwd {
        Some(cwd) => format!("cd {} && {command}", cwd.display()),
        None => command,
    })
}

/// Executes the specified cargo subcommand (python `cargo`).
pub fn cargo(
    subcommand: &str,
    cargo_args: &str,
    subcommand_args: &str,
    options: &CargoOptions,
) -> Result<utils::CommandReturn> {
    let command = cargo_command(subcommand, cargo_args, subcommand_args, options)?;
    let result = utils::run_cmd_timeout(&command, options.timeout)?;
    if !result.success() {
        anyhow::bail!("{}", result.describe(&command));
    }
    Ok(result)
}

/// Returns the linker flags needed on aarch64, empty otherwise (python `get_rustflags`).
pub fn get_rustflags() -> &'static str {
    if defs::host_arch() == "aarch64" {
        return "-C link-arg=-lgcc -C link-arg=-lfdt ";
    }
    ""
}

/// Runs the unit tests of `path` under `<path>/unit-tests` (python `cargo_test`).
pub fn cargo_test(path: &Path, extra_args: &str) -> Result<utils::CommandReturn> {
    let mut env = BTreeMap::new();
    env.insert(
        "CARGO_TARGET_DIR".to_string(),
        path.join("unit-tests").display().to_string(),
    );
    env.insert("RUST_TEST_THREADS".to_string(), "1".to_string());
    env.insert("RUST_BACKTRACE".to_string(), "1".to_string());
    env.insert("RUSTFLAGS".to_string(), get_rustflags().to_string());
    let options = CargoOptions {
        env,
        // Kill cargo test 60s before pytest's 600s timeout so pytest can report the failure and
        // upload artifacts cleanly instead of being killed itself.
        timeout: Some(Duration::from_secs(540)),
        ..CargoOptions::default()
    };
    cargo(
        "test",
        &format!("{extra_args} --all --no-fail-fast"),
        "--nocapture",
        &options,
    )
}

/// Returns the path of a binary from the shared binary directory (python `get_binary`).
pub fn get_binary(name: &str, binary_dir: Option<&Path>, example: Option<&str>) -> PathBuf {
    let dir = match binary_dir {
        Some(dir) => dir.to_path_buf(),
        None => defs::default_binary_dir(),
    };
    match example {
        Some(example) => dir.join("examples").join(example),
        None => dir.join(name),
    }
}

/// Returns the path of an example binary of `package` (python `get_example`).
pub fn get_example(name: &str, package: &str, binary_dir: Option<&Path>) -> PathBuf {
    get_binary(package, binary_dir, Some(name))
}

/// Renders the `seccompiler-bin` argument list for a filter compile.
pub fn seccompiler_args(
    json_path: &Path,
    arch: &str,
    bpf_path: &Path,
    basic: bool,
    split_output: bool,
) -> String {
    let mut args = format!(
        "--input-file {} --target-arch {arch} --output-file {}",
        json_path.display(),
        bpf_path.display()
    );
    if basic {
        args.push_str(" --basic");
    }
    if split_output {
        args.push_str(" --split-output");
    }
    args
}

/// Compiles a seccomp filter from JSON into a BPF blob (python `run_seccompiler_bin`).
pub fn run_seccompiler_bin(
    bpf_path: &Path,
    json_path: Option<&Path>,
    basic: bool,
    split_output: bool,
    binary_dir: Option<&Path>,
) -> Result<()> {
    let json_path = match json_path {
        Some(path) => path.to_path_buf(),
        None => defs::seccomp_json_dir().join(format!("{}.json", default_target())),
    };
    let args = seccompiler_args(&json_path, defs::host_arch(), bpf_path, basic, split_output);
    let seccompiler = get_binary("seccompiler-bin", binary_dir, None);
    utils::check_output(&format!("{} {args}", seccompiler.display()))?;
    Ok(())
}

/// Rebuilds a diff snapshot memory file on top of its base (python `run_snap_editor_rebase`).
pub fn run_snap_editor_rebase(
    base_snap: &Path,
    diff_snap: &Path,
    binary_dir: Option<&Path>,
) -> Result<()> {
    let snap_ed = get_binary("snapshot-editor", binary_dir, None);
    utils::check_output(&format!(
        "{} edit-memory rebase --memory-path {} --diff-path {}",
        snap_ed.display(),
        base_snap.display(),
        diff_snap.display()
    ))?;
    Ok(())
}

/// Rebuilds a diff snapshot memory file with `rebase-snap` (python `run_rebase_snap_bin`).
pub fn run_rebase_snap_bin(base_snap: &Path, diff_snap: &Path) -> Result<()> {
    let rebase_snap = get_binary("rebase-snap", None, None);
    utils::check_output(&format!(
        "{} --base-file {} --diff-file {}",
        rebase_snap.display(),
        base_snap.display(),
        diff_snap.display()
    ))?;
    Ok(())
}

/// Builds a source file with gcc unless the output already exists (python `gcc_compile`).
pub fn gcc_compile(src_file: &Path, output_file: &Path, extra_flags: &str) -> Result<()> {
    with_file_lock("gcc_compile", || {
        if output_file.exists() {
            return Ok(());
        }
        utils::check_output(&format!(
            "gcc {} -o {} {extra_flags}",
            src_file.display(),
            output_file.display()
        ))
        .context("compiling the host helper binary with gcc")?;
        Ok(())
    })
}

/// Builds Firecracker with the GDB feature and returns its binary directory (python `build_gdb`).
pub fn build_gdb() -> Result<PathBuf> {
    let build_path = defs::local_build_path().join("gdb");
    let mut env = BTreeMap::new();
    env.insert(
        "CARGO_TARGET_DIR".to_string(),
        build_path.display().to_string(),
    );
    cargo(
        "build",
        &format!("--features gdb --target {} --all", default_target()),
        "",
        &CargoOptions::with_env(env),
    )?;
    Ok(build_path.join(default_target()).join("debug"))
}

/// Builds Firecracker with the fuzzing feature and returns its binary directory.
pub fn build_fuzzing(release: bool) -> Result<PathBuf> {
    let profile = if release { "release" } else { "debug" };
    let build_path = defs::local_build_path().join("fuzzing");
    let release_flag = if release { " --release" } else { "" };
    let mut env = BTreeMap::new();
    env.insert(
        "CARGO_TARGET_DIR".to_string(),
        build_path.display().to_string(),
    );
    cargo(
        "build",
        &format!(
            "--features fuzzing{release_flag} --target {} --all",
            default_target()
        ),
        "",
        &CargoOptions::with_env(env),
    )?;
    Ok(build_path.join(default_target()).join(profile))
}

/// Runs `op` while holding an exclusive `flock` on `<temp_dir>/<name>.lock`.
pub fn with_file_lock<T>(name: &str, op: impl FnOnce() -> Result<T>) -> Result<T> {
    let lock_path = std::env::temp_dir().join(format!("{name}.lock"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("opening the lock file {}", lock_path.display()))?;
    // SAFETY: `file` keeps the descriptor open for the whole critical section.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("acquiring the lock {}", lock_path.display()));
    }
    let output = op();
    // SAFETY: same descriptor as above, still open.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_matches_python_default_target() {
        assert_eq!(
            default_target(),
            format!("{}-unknown-linux-musl", defs::host_arch())
        );
        assert!(default_target_dir().ends_with("/release/"));
        assert!(default_target_dir().starts_with(&default_target()));
    }

    #[test]
    fn rustflags_depend_on_the_arch() {
        let expected = if defs::host_arch() == "aarch64" {
            "-C link-arg=-lgcc -C link-arg=-lfdt "
        } else {
            ""
        };
        assert_eq!(get_rustflags(), expected);
    }

    #[test]
    fn cargo_command_renders_env_and_separator() {
        let mut env = BTreeMap::new();
        env.insert("CARGO_TARGET_DIR".to_string(), "/tmp/target".to_string());
        env.insert("RUST_BACKTRACE".to_string(), "1".to_string());
        let command = cargo_command(
            "test",
            "--all --no-fail-fast",
            "--nocapture",
            &CargoOptions::with_env(env),
        )
        .expect("command");
        assert_eq!(
            command,
            "CARGO_TARGET_DIR=\"/tmp/target\" RUST_BACKTRACE=\"1\" cargo test --all --no-fail-fast -- --nocapture"
        );
    }

    #[test]
    fn cargo_command_honours_cwd() {
        let options = CargoOptions {
            cwd: Some(PathBuf::from("/src/firecracker")),
            ..CargoOptions::default()
        };
        let command = cargo_command("build", "", "", &options).expect("command");
        assert_eq!(command, "cd /src/firecracker && cargo build --");
    }

    #[test]
    fn binaries_come_from_the_default_binary_dir() {
        assert_eq!(
            get_binary("firecracker", None, None),
            defs::default_binary_dir().join("firecracker")
        );
        assert_eq!(
            get_binary(
                "firecracker",
                Some(Path::new("/tmp/bin")),
                Some("gdb_socket")
            ),
            PathBuf::from("/tmp/bin/examples/gdb_socket")
        );
        assert_eq!(
            get_example("gdb_socket", "firecracker", Some(Path::new("/tmp/bin"))),
            PathBuf::from("/tmp/bin/examples/gdb_socket")
        );
    }

    #[test]
    fn seccompiler_args_follow_the_flags() {
        let base = seccompiler_args(
            Path::new("/json/x86_64.json"),
            "x86_64",
            Path::new("/tmp/filter.bpf"),
            false,
            false,
        );
        assert_eq!(
            base,
            "--input-file /json/x86_64.json --target-arch x86_64 --output-file /tmp/filter.bpf"
        );
        let full = seccompiler_args(
            Path::new("/json/x86_64.json"),
            "x86_64",
            Path::new("/tmp/filter.bpf"),
            true,
            true,
        );
        assert!(full.ends_with(" --basic --split-output"));
    }
}
