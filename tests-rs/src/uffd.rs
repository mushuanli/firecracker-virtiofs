// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Userfaultfd (UFFD) page fault handler helpers, ported from
//! `tests/framework/utils_uffd.py`.
//!
//! Python enters the jail with the `framework.utils.chroot` context manager and
//! then `Popen`s the handler; the port instead uses
//! `std::os::unix::process::CommandExt::pre_exec` to `chroot(2)` the child only.
//! That keeps the calling process (and its other threads) out of the jail, so
//! `UffdHandler::spawn` no longer needs a process-global chroot.
//!
//! Python resolves every jail-relative path by running inside the chroot; the
//! port keeps the same absolute jail paths ([`SOCKET_PATH`]) and resolves them
//! with [`jailed_path`] against the chroot directory.

use std::ffi::CString;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::defs::default_binary_dir;
use crate::microvm::MemBackendHandler;
use crate::snapshot::Snapshot;

/// UFFD socket path relative to the microVM jail (`SOCKET_PATH`).
pub const SOCKET_PATH: &str = "/firecracker-uffd.sock";

/// Log file the handler writes, relative to the microVM jail.
pub const LOG_FILE_NAME: &str = "uffd.log";

/// Default timeout of [`UffdHandler::mark_killed`], matching `timeout=10`.
pub const DEFAULT_MARK_KILLED_TIMEOUT: Duration = Duration::from_secs(10);

/// Time the handler gets to start (and fail) before it is checked.
pub const HANDLER_STARTUP_DELAY: Duration = Duration::from_secs(1);

/// Timeout used when waiting for a killed handler to be reaped.
pub const KILL_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolves an absolute path from inside the jail against `chroot`.
///
/// `jailed_path("/jail/root", "/firecracker-uffd.sock")` is
/// `/jail/root/firecracker-uffd.sock`, i.e. the host view of the path the
/// handler sees after `chroot(2)`.
pub fn jailed_path(chroot: &Path, path: &Path) -> PathBuf {
    let mut resolved = chroot.to_path_buf();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(part) => resolved.push(part),
        }
    }
    resolved
}

/// Describes the UFFD page fault handler process (python `UffdHandler`).
#[derive(Debug)]
pub struct UffdHandler {
    handler_name: String,
    socket_path: PathBuf,
    mem_name: String,
    chroot: PathBuf,
    log_file_name: String,
    proc: Option<Child>,
    exit_status: Option<ExitStatus>,
}

impl UffdHandler {
    /// Creates the handler description without spawning anything.
    ///
    /// `socket_path` is the path the handler sees after `chroot(2)`, usually
    /// [`SOCKET_PATH`]; `mem_name` is the snapshot memory file name (python
    /// `snapshot.mem.name`).
    pub fn new(
        handler_name: impl Into<String>,
        socket_path: impl Into<PathBuf>,
        mem_name: impl Into<String>,
        chroot: impl Into<PathBuf>,
        log_file_name: impl Into<String>,
    ) -> Self {
        Self {
            handler_name: handler_name.into(),
            socket_path: socket_path.into(),
            mem_name: mem_name.into(),
            chroot: chroot.into(),
            log_file_name: log_file_name.into(),
            proc: None,
            exit_status: None,
        }
    }

    /// Handler executable name, relative to the jail root.
    pub fn handler_name(&self) -> &str {
        &self.handler_name
    }

    /// UFFD socket path as seen inside the jail.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Snapshot memory file name passed to the handler.
    pub fn mem_name(&self) -> &str {
        &self.mem_name
    }

    /// MicroVM jail root the handler runs in.
    pub fn chroot(&self) -> &Path {
        &self.chroot
    }

    /// Host path of the handler log file.
    pub fn log_file(&self) -> PathBuf {
        jailed_path(&self.chroot, Path::new(&self.log_file_name))
    }

    /// Contents of the handler log file.
    pub fn log_data(&self) -> Result<String> {
        let path = self.log_file();
        std::fs::read_to_string(&path)
            .with_context(|| format!("reading UFFD handler log {}", path.display()))
    }

    /// The running handler process, if any.
    pub fn proc(&self) -> Option<&Child> {
        self.proc.as_ref()
    }

    /// Exit status recorded by the last [`Self::is_running`] / wait call.
    pub fn exit_status(&self) -> Option<ExitStatus> {
        self.exit_status
    }

    /// Checks whether the handler is still running (python `is_running`).
    ///
    /// Takes `&mut self` because Rust's `Child::try_wait` reaps the child.
    pub fn is_running(&mut self) -> Result<bool> {
        let Some(child) = self.proc.as_mut() else {
            return Ok(false);
        };
        match child.try_wait().context("polling UFFD handler")? {
            Some(status) => {
                self.exit_status = Some(status);
                Ok(false)
            }
            None => Ok(true),
        }
    }

    /// Spawns the handler inside the jail and hands the socket to `uid:gid`.
    ///
    /// Mirrors python `spawn(uid, gid)`: make the handler executable, start it
    /// with stdout/stderr redirected to the log file, give it one second to fail,
    /// then `chown` the socket it created to the jailer user.
    pub fn spawn(&mut self, uid: u32, gid: u32) -> Result<()> {
        if self.proc.is_some() {
            bail!("UFFD handler '{}' was already spawned", self.handler_name);
        }

        let handler_path = self.chroot.join(&self.handler_name);
        let metadata = std::fs::metadata(&handler_path)
            .with_context(|| format!("stat {}", handler_path.display()))?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o100);
        std::fs::set_permissions(&handler_path, permissions)
            .with_context(|| format!("chmod {}", handler_path.display()))?;

        let log_path = self.log_file();
        let log_file = File::create(&log_path)
            .with_context(|| format!("creating UFFD handler log {}", log_path.display()))?;
        let stderr = log_file
            .try_clone()
            .context("duplicating UFFD handler log handle")?;

        let mut command = Command::new(format!("/{}", self.handler_name));
        command
            .arg(self.socket_path.as_os_str())
            .arg(&self.mem_name)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr));

        let chroot = self.chroot.clone();
        // SAFETY: the closure only calls async-signal-safe libc functions and
        // captures a `PathBuf` allocated before `fork`.
        unsafe {
            command.pre_exec(move || {
                let root = CString::new(chroot.as_os_str().as_encoded_bytes())
                    .map_err(|_| std::io::Error::other("chroot path contains NUL"))?;
                if libc::chroot(root.as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::chdir(c"/".as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = command
            .spawn()
            .with_context(|| format!("spawning UFFD handler '{}'", self.handler_name))?;
        self.proc = Some(child);
        self.exit_status = None;

        // Give it time to start and fail, if it really has to.
        std::thread::sleep(HANDLER_STARTUP_DELAY);
        if !self.is_running()? {
            bail!(
                "Could not start PF handler!\n{}",
                self.log_data().unwrap_or_default()
            );
        }

        // The page fault handler created the socket with root rights.
        // Change rights to the jailer's.
        chown(&jailed_path(&self.chroot, &self.socket_path), uid, gid)
    }

    /// Kills the handler and reaps it (python `kill`).
    pub fn kill(&mut self) -> Result<()> {
        if !self.is_running()? {
            bail!("UFFD handler '{}' is not running", self.handler_name);
        }

        let mut status = None;
        let mut timed_out = false;
        if let Some(child) = self.proc.as_mut() {
            child
                .kill()
                .with_context(|| format!("killing UFFD handler '{}'", self.handler_name))?;
            let deadline = Instant::now() + KILL_WAIT_TIMEOUT;
            loop {
                match child.try_wait().context("reaping UFFD handler")? {
                    Some(exit) => {
                        status = Some(exit);
                        break;
                    }
                    None if Instant::now() >= deadline => {
                        timed_out = true;
                        break;
                    }
                    None => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        }
        self.proc = None;
        self.exit_status = status;

        if timed_out {
            bail!(
                "UFFD handler '{}' did not exit within {}s of SIGKILL",
                self.handler_name,
                KILL_WAIT_TIMEOUT.as_secs()
            );
        }
        Ok(())
    }

    /// Waits for a handler that is expected to die on its own (python `mark_killed`).
    ///
    /// Used e.g. for the malicious handler that panics on the first page fault;
    /// process exit after a panic is not instantaneous, so the call waits up to
    /// `timeout` before failing with the handler log.
    pub fn mark_killed(&mut self, timeout: Duration) -> Result<()> {
        let mut status = None;
        let mut timed_out = false;
        if let Some(child) = self.proc.as_mut() {
            let deadline = Instant::now() + timeout;
            loop {
                match child.try_wait().context("polling UFFD handler")? {
                    Some(exit) => {
                        status = Some(exit);
                        break;
                    }
                    None if Instant::now() >= deadline => {
                        timed_out = true;
                        break;
                    }
                    None => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        }
        self.proc = None;
        self.exit_status = status;

        if timed_out {
            bail!(
                "UFFD handler '{}' still running {}s after it should have died. Logs:\n{}",
                self.handler_name,
                timeout.as_secs(),
                self.log_data().unwrap_or_default()
            );
        }
        Ok(())
    }
}

impl Drop for UffdHandler {
    fn drop(&mut self) {
        if matches!(self.is_running(), Ok(true)) {
            let _ = self.kill();
        }
    }
}

/// Spawns the page fault handler for a jailed snapshot (python `spawn_pf_handler`).
///
/// Python copies the handler into the jail itself through
/// `vm.create_jailed_resource(handler_path)`; the port expects that copy to be
/// done by the caller (the microVM jailing API lives in `microvm.rs`), so
/// `jailed_handler` is the host path of the handler binary inside `chroot` and
/// `mem_name` is the basename of the jailed snapshot memory file.
pub fn spawn_pf_handler(
    jailed_handler: &Path,
    mem_name: &str,
    chroot: &Path,
    uid: u32,
    gid: u32,
) -> Result<UffdHandler> {
    let handler_name = jailed_handler
        .file_name()
        .ok_or_else(|| anyhow!("no file name in {}", jailed_handler.display()))?
        .to_string_lossy()
        .into_owned();

    let mut handler = UffdHandler::new(handler_name, SOCKET_PATH, mem_name, chroot, LOG_FILE_NAME);
    handler.spawn(uid, gid)?;
    Ok(handler)
}

impl MemBackendHandler for UffdHandler {
    fn socket_path(&self) -> &Path {
        UffdHandler::socket_path(self)
    }

    fn log_data(&self) -> String {
        UffdHandler::log_data(self).unwrap_or_default()
    }

    fn is_running(&mut self) -> bool {
        UffdHandler::is_running(self).unwrap_or(false)
    }

    fn kill(&mut self) {
        let _ = UffdHandler::kill(self);
    }
}

/// [`spawn_pf_handler`] taking the snapshot object directly, like python
/// `spawn_pf_handler(vm, handler_path, jailed_snapshot)`, which passes
/// `snapshot.mem.name` to the handler.
pub fn spawn_pf_handler_for_snapshot(
    jailed_handler: &Path,
    snapshot: &Snapshot,
    chroot: &Path,
    uid: u32,
    gid: u32,
) -> Result<UffdHandler> {
    let mem_name = snapshot
        .mem
        .file_name()
        .ok_or_else(|| anyhow!("no file name in snapshot memory {}", snapshot.mem.display()))?
        .to_string_lossy()
        .into_owned();
    spawn_pf_handler(jailed_handler, &mem_name, chroot, uid, gid)
}

/// Path of the `uffd_<handler_name>_handler` example binary (python `uffd_handler`).
pub fn uffd_handler(handler_name: &str) -> PathBuf {
    uffd_handler_in(&default_binary_dir(), handler_name)
}

/// [`uffd_handler`] with an explicit binary dir (python `binary_dir=` keyword).
pub fn uffd_handler_in(binary_dir: &Path, handler_name: &str) -> PathBuf {
    binary_dir
        .join("examples")
        .join(format!("uffd_{handler_name}_handler"))
}

/// Changes ownership of `path` to `uid:gid` (`os.chown`).
fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("chown target {} contains NUL", path.display()))?;
    // SAFETY: `c_path` is a valid NUL-terminated path owned by the caller.
    if unsafe { libc::chown(c_path.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("chown {} to {uid}:{gid}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_matches_python_constant() {
        assert_eq!(SOCKET_PATH, "/firecracker-uffd.sock");
        assert_eq!(LOG_FILE_NAME, "uffd.log");
        assert_eq!(
            jailed_path(Path::new("/jail/root"), Path::new(SOCKET_PATH)),
            PathBuf::from("/jail/root/firecracker-uffd.sock")
        );
    }

    #[test]
    fn jailed_path_handles_relative_and_parent_components() {
        let chroot = Path::new("/srv/jail/root");
        assert_eq!(
            jailed_path(chroot, Path::new("uffd.log")),
            PathBuf::from("/srv/jail/root/uffd.log")
        );
        assert_eq!(
            jailed_path(chroot, Path::new("/logs/./uffd.log")),
            PathBuf::from("/srv/jail/root/logs/uffd.log")
        );
        assert_eq!(
            jailed_path(chroot, Path::new("logs/../uffd.log")),
            PathBuf::from("/srv/jail/root/uffd.log")
        );
    }

    #[test]
    fn handler_reports_log_file_and_socket_path() {
        let handler = UffdHandler::new(
            "uffd_on_demand_handler",
            SOCKET_PATH,
            "mem_file",
            "/srv/jail/root",
            LOG_FILE_NAME,
        );
        assert_eq!(handler.handler_name(), "uffd_on_demand_handler");
        assert_eq!(handler.socket_path(), Path::new(SOCKET_PATH));
        assert_eq!(handler.mem_name(), "mem_file");
        assert_eq!(handler.chroot(), Path::new("/srv/jail/root"));
        assert_eq!(handler.log_file(), PathBuf::from("/srv/jail/root/uffd.log"));
        assert!(handler.proc().is_none());
        assert!(handler.exit_status().is_none());
    }

    #[test]
    fn mark_killed_without_process_is_a_noop() {
        let mut handler = UffdHandler::new(
            "uffd_malicious_handler",
            SOCKET_PATH,
            "mem_file",
            "/srv/jail/root",
            LOG_FILE_NAME,
        );
        handler
            .mark_killed(Duration::from_millis(1))
            .expect("no process to wait for");
        assert!(handler.exit_status().is_none());
    }

    #[test]
    fn missing_handler_executable_is_reported() {
        let mut handler = UffdHandler::new(
            "does_not_exist",
            SOCKET_PATH,
            "mem_file",
            "/tmp/fc-harness-uffd-missing",
            LOG_FILE_NAME,
        );
        let error = handler.spawn(0, 0).expect_err("handler binary is missing");
        assert!(format!("{error:#}").contains("does_not_exist"), "{error:#}");
    }

    #[test]
    fn snapshot_mem_name_is_the_handler_argument() {
        let snapshot = Snapshot {
            vmstate: PathBuf::from("/srv/jail/vmstate"),
            mem: PathBuf::from("/srv/jail/mem_file"),
            net_ifaces: Vec::new(),
            disks: std::collections::BTreeMap::new(),
            ssh_key: PathBuf::from("/srv/jail/ssh_key"),
            snapshot_type: crate::snapshot::SnapshotType::Full,
            meta: std::collections::BTreeMap::new(),
        };
        let mut handler = UffdHandler::new(
            "does_not_exist",
            SOCKET_PATH,
            snapshot
                .mem
                .file_name()
                .expect("mem file name")
                .to_string_lossy(),
            "/tmp/fc-harness-uffd-snapshot",
            LOG_FILE_NAME,
        );
        assert_eq!(handler.mem_name(), "mem_file");
        assert!(handler.spawn(0, 0).is_err());
    }

    #[test]
    fn uffd_handler_paths_follow_cargo_build_get_example() {
        let binary_dir = Path::new("/build/cargo_target/x86_64-unknown-linux-musl/release");
        assert_eq!(
            uffd_handler_in(binary_dir, "on_demand"),
            binary_dir.join("examples/uffd_on_demand_handler")
        );
        assert!(uffd_handler("malicious").ends_with("examples/uffd_malicious_handler"));
    }
}
