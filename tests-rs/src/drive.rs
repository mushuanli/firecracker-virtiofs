// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! vhost-user block backends, ported from `tests/framework/utils_drive.py`.
//!
//! Python models the backends as an `ABC` plus one subclass per backend type.
//! The port keeps a trait with one struct per backend and a [`backend_for`]
//! factory. Command construction lives in [`VhostUserBlkBackend::spawn_cmd`] so
//! argv shapes can be asserted without ever spawning a backend.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::utils;

/// One mebibyte, matching `MB` in the python module.
pub const MB: u64 = 1024 * 1024;

/// Extra space appended to the rootfs copy so the partition table fits.
const DISK_SLACK_MIB: u64 = 50;

/// Number of socket probes before giving up (50 * 100 ms = 5 s).
const SOCKET_WAIT_ATTEMPTS: u32 = 50;

/// Delay between two backend socket probes.
const SOCKET_WAIT_INTERVAL: Duration = Duration::from_millis(100);

/// Quotes `path` for use inside a `/bin/sh -c` command line.
///
/// The python module interpolates paths into shell strings unquoted; the port
/// keeps the same command lines but makes them safe for paths with spaces.
fn shell_quote(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let safe = !raw.is_empty()
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._/:=@,+".contains(&byte));
    if safe {
        return raw.into_owned();
    }
    format!("'{}'", raw.replace('\'', r"'\''"))
}

/// The `sfdisk` command creating a single type-83 partition table.
fn sfdisk_command(disk_path: &Path) -> String {
    format!(
        "echo type=83 | sfdisk --no-tell-kernel {}",
        shell_quote(disk_path)
    )
}

/// The `dd` command copying the rootfs into the new disk.
fn dd_command(rootfs: &Path, disk_path: &Path) -> String {
    format!(
        "dd bs=1M seek=1 if={} of={}",
        shell_quote(rootfs),
        shell_quote(disk_path)
    )
}

/// The `blkid` command retrieving the partition table UUID.
fn blkid_command(disk_path: &Path) -> String {
    format!("blkid -s PTUUID -o value {}", shell_quote(disk_path))
}

/// Builds the PARTUUID of `partition` on an msdos partition table.
///
/// For msdos tables the PARTUUID is `PTUUID-<PART NUMBER>` with a two digit,
/// zero padded partition number, e.g. `abcd-1234-01`.
pub fn partuuid_for_partition(ptuuid: &str, partition: u32) -> String {
    format!("{ptuuid}-{partition:02}")
}

/// Runs `run` with every command of the partitioning recipe and returns the
/// resulting `(partuuid, disk_path)` pair.
///
/// Split out from [`partuuid_and_disk_path`] so the recipe can be unit tested
/// with a recording runner instead of real `sfdisk`/`dd`/`blkid`.
fn partuuid_and_disk_path_with(
    rootfs: &Path,
    disk_path: &Path,
    run: &dyn Fn(&str) -> Result<String>,
) -> Result<(String, PathBuf)> {
    let rootfs_size = std::fs::metadata(rootfs)
        .with_context(|| format!("stat {}", rootfs.display()))?
        .len();
    let initial_size = rootfs_size + DISK_SLACK_MIB * MB;

    // `disk_path.touch()`: create the file without truncating it if present.
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(disk_path)
        .with_context(|| format!("creating {}", disk_path.display()))?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(disk_path)
        .with_context(|| format!("opening {}", disk_path.display()))?
        .set_len(initial_size)
        .with_context(|| format!("truncating {} to {initial_size}", disk_path.display()))?;

    run(&sfdisk_command(disk_path))?;
    run(&dd_command(rootfs, disk_path))?;
    let ptuuid = run(&blkid_command(disk_path))?.trim().to_string();
    if ptuuid.is_empty() {
        bail!("blkid returned an empty PTUUID for {}", disk_path.display());
    }

    Ok((partuuid_for_partition(&ptuuid, 1), disk_path.to_path_buf()))
}

/// Creates `disk_path` as a partitioned copy of `rootfs` and returns its PARTUUID.
pub fn partuuid_and_disk_path(rootfs: &Path, disk_path: &Path) -> Result<(String, PathBuf)> {
    partuuid_and_disk_path_with(rootfs, disk_path, &|cmd| {
        Ok(utils::check_output(cmd)?.stdout)
    })
}

/// Backend kinds available for vhost-user block devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhostUserBlkBackendType {
    /// Qemu's standalone `vhost-user-blk` helper.
    Qemu,
    /// A `crosvm devices` process running in vhost-user mode.
    Crosvm,
}

impl VhostUserBlkBackendType {
    /// The name as spelled in the python enum (`Qemu` / `Crosvm`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Qemu => "Qemu",
            Self::Crosvm => "Crosvm",
        }
    }

    /// Parses the python enum spelling, case-insensitively.
    pub fn from_name(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "qemu" => Ok(Self::Qemu),
            "crosvm" => Ok(Self::Crosvm),
            other => bail!("unknown vhost-user-blk backend type: {other}"),
        }
    }

    /// Instantiates the backend of this kind (python `with_backend`).
    pub fn with_backend(
        &self,
        host_mem_path: impl Into<PathBuf>,
        chroot: &Path,
        backend_id: &str,
        readonly: bool,
    ) -> Box<dyn VhostUserBlkBackend> {
        match self {
            Self::Qemu => Box::new(QemuVhostUserBlkBackend::new(
                host_mem_path,
                chroot,
                backend_id,
                readonly,
            )),
            Self::Crosvm => Box::new(CrosvmVhostUserBlkBackend::new(
                host_mem_path,
                chroot,
                backend_id,
                readonly,
            )),
        }
    }
}

/// Instantiates a backend of `kind` (free function form of `with_backend`).
pub fn backend_for(
    kind: VhostUserBlkBackendType,
    host_mem_path: impl Into<PathBuf>,
    chroot: &Path,
    backend_id: &str,
    readonly: bool,
) -> Box<dyn VhostUserBlkBackend> {
    kind.with_backend(host_mem_path, chroot, backend_id, readonly)
}

/// Interface shared by every vhost-user block backend.
///
/// Mirrors the abstract base class in the python module, including the
/// `Qemu` backend's refusal to resize.
pub trait VhostUserBlkBackend {
    /// argv used to launch the backend, without spawning it.
    fn spawn_cmd(&self) -> Vec<OsString>;

    /// Spawns the backend and returns its socket path as seen inside the jail.
    fn spawn(&mut self, uid: u32, gid: u32) -> Result<String>;

    /// Resizes the exported drive to `new_size_mb` mebibytes.
    fn resize(&mut self, new_size_mb: u64) -> Result<()>;

    /// Pins the backend process to a single host CPU.
    fn pin(&self, cpu_id: usize) -> Result<()>;

    /// Terminates the backend and removes its sockets.
    fn kill(&mut self) -> Result<()>;

    /// Waits up to five seconds for the backend socket to appear.
    fn wait_for_socket(&self) -> Result<()>;
}

/// Process and path state shared by the two backend implementations.
#[derive(Debug)]
struct BackendState {
    host_mem_path: PathBuf,
    socket_path: PathBuf,
    readonly: bool,
    proc: Option<Child>,
}

impl BackendState {
    fn new(host_mem_path: PathBuf, chroot: &Path, backend_id: &str, readonly: bool) -> Self {
        Self {
            host_mem_path,
            socket_path: chroot.join(format!("{backend_id}_vhost_user.sock")),
            readonly,
            proc: None,
        }
    }

    /// Opens the shared block file read-only when the backend asked for it.
    fn readonly_suffix(&self) -> &'static str {
        if self.readonly {
            ",ro"
        } else {
            ""
        }
    }

    /// Spawns `cmd`, checks it stayed up, waits for the socket and chowns it.
    fn spawn(&mut self, cmd: Vec<OsString>, uid: u32, gid: u32) -> Result<String> {
        if self.proc.is_some() {
            bail!("backend already spawned");
        }
        let (program, rest) = cmd
            .split_first()
            .ok_or_else(|| anyhow!("empty backend command"))?;
        let mut child = Command::new(program)
            .args(rest)
            .spawn()
            .with_context(|| format!("spawning backend {}", program.to_string_lossy()))?;

        // `proc is not None and proc.poll() is None`.
        if let Some(status) = child.try_wait()? {
            bail!("backend is not up: exited with {status}");
        }

        self.wait_for_socket()?;

        std::os::unix::fs::chown(&self.socket_path, Some(uid), Some(gid))
            .with_context(|| format!("chown {}", self.socket_path.display()))?;

        self.proc = Some(child);

        let base = self
            .socket_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| {
                anyhow!(
                    "socket path {} has no file name",
                    self.socket_path.display()
                )
            })?;
        Ok(format!("/{base}"))
    }

    /// Waits for the backend socket to appear (up to 5 s).
    fn wait_for_socket(&self) -> Result<()> {
        let socket_path = &self.socket_path;
        utils::retry_attempts(SOCKET_WAIT_ATTEMPTS, SOCKET_WAIT_INTERVAL, || {
            if socket_path.exists() {
                Ok(())
            } else {
                bail!("socket {} not ready", socket_path.display())
            }
        })
    }

    /// Pins the backend process to a single host CPU.
    fn pin(&self, cpu_id: usize) -> Result<()> {
        let child = self
            .proc
            .as_ref()
            .ok_or_else(|| anyhow!("backend is not spawned"))?;
        utils::set_cpu_affinity(child.id() as i32, &[cpu_id])?;
        Ok(())
    }

    /// Terminates the backend and removes its vhost-user socket.
    fn kill(&mut self) -> Result<()> {
        if let Some(child) = self.proc.as_mut() {
            if child.try_wait()?.is_none() {
                terminate(child)?;
                child.wait()?;
                remove_socket(&self.socket_path)?;
            }
        }
        if self.socket_path.exists() {
            bail!(
                "socket {} still exists after kill",
                self.socket_path.display()
            );
        }
        Ok(())
    }
}

/// Sends `SIGTERM` to a child process (python `Popen.terminate`).
fn terminate(child: &mut Child) -> Result<()> {
    let pid = child.id() as i32;
    // SAFETY: `kill` only sends a signal to `pid`; no memory is touched.
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("SIGTERM to {pid}"));
    }
    Ok(())
}

/// Removes `path`, tolerating an already missing file (`os.remove` strictness is
/// relaxed only for the "already gone" case).
fn remove_socket(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("removing {}", path.display())),
    }
}

/// vhost-user-blk backend implemented with Qemu's `vhost-user-blk` helper.
#[derive(Debug)]
pub struct QemuVhostUserBlkBackend {
    state: BackendState,
}

impl QemuVhostUserBlkBackend {
    /// Creates the backend for the block file at `host_mem_path`.
    pub fn new(
        host_mem_path: impl Into<PathBuf>,
        chroot: &Path,
        backend_id: &str,
        readonly: bool,
    ) -> Self {
        Self {
            state: BackendState::new(host_mem_path.into(), chroot, backend_id, readonly),
        }
    }

    /// Path of the vhost-user socket exported by the backend.
    pub fn socket_path(&self) -> &Path {
        &self.state.socket_path
    }
}

impl VhostUserBlkBackend for QemuVhostUserBlkBackend {
    fn spawn_cmd(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![
            "vhost-user-blk".into(),
            "--socket-path".into(),
            self.state.socket_path.as_os_str().to_os_string(),
            "--blk-file".into(),
            self.state.host_mem_path.as_os_str().to_os_string(),
        ];
        if self.state.readonly {
            args.push("--read-only".into());
        }
        args
    }

    fn spawn(&mut self, uid: u32, gid: u32) -> Result<String> {
        let cmd = self.spawn_cmd();
        self.state.spawn(cmd, uid, gid)
    }

    fn resize(&mut self, _new_size_mb: u64) -> Result<()> {
        bail!("resize not supported for Qemu backend")
    }

    fn pin(&self, cpu_id: usize) -> Result<()> {
        self.state.pin(cpu_id)
    }

    fn kill(&mut self) -> Result<()> {
        self.state.kill()
    }

    fn wait_for_socket(&self) -> Result<()> {
        self.state.wait_for_socket()
    }
}

/// vhost-user-blk backend implemented with a `crosvm devices` process.
#[derive(Debug)]
pub struct CrosvmVhostUserBlkBackend {
    state: BackendState,
    ctr_socket_path: PathBuf,
}

impl CrosvmVhostUserBlkBackend {
    /// Creates the backend for the block file at `host_mem_path`.
    pub fn new(
        host_mem_path: impl Into<PathBuf>,
        chroot: &Path,
        backend_id: &str,
        readonly: bool,
    ) -> Self {
        Self {
            state: BackendState::new(host_mem_path.into(), chroot, backend_id, readonly),
            ctr_socket_path: chroot.join(format!("{backend_id}_ctr.sock")),
        }
    }

    /// Path of the vhost-user socket exported by the backend.
    pub fn socket_path(&self) -> &Path {
        &self.state.socket_path
    }

    /// Path of the crosvm control socket used by `crosvm disk resize`.
    pub fn ctr_socket_path(&self) -> &Path {
        &self.ctr_socket_path
    }
}

impl VhostUserBlkBackend for CrosvmVhostUserBlkBackend {
    fn spawn_cmd(&self) -> Vec<OsString> {
        vec![
            "crosvm".into(),
            "--log-level".into(),
            "off".into(),
            "devices".into(),
            "--disable-sandbox".into(),
            "--control-socket".into(),
            self.ctr_socket_path.as_os_str().to_os_string(),
            "--block".into(),
            format!(
                "vhost={},path={}{}",
                self.state.socket_path.display(),
                self.state.host_mem_path.display(),
                self.state.readonly_suffix()
            )
            .into(),
        ]
    }

    fn spawn(&mut self, uid: u32, gid: u32) -> Result<String> {
        let cmd = self.spawn_cmd();
        self.state.spawn(cmd, uid, gid)
    }

    fn resize(&mut self, new_size_mb: u64) -> Result<()> {
        if self.state.proc.is_none() {
            bail!("backend is not spawned");
        }
        if !self.ctr_socket_path.exists() {
            bail!(
                "control socket {} does not exist",
                self.ctr_socket_path.display()
            );
        }
        let cmd = format!(
            "crosvm disk resize 0 {} {}",
            new_size_mb * MB,
            shell_quote(&self.ctr_socket_path)
        );
        utils::check_output(&cmd)?;
        Ok(())
    }

    fn pin(&self, cpu_id: usize) -> Result<()> {
        self.state.pin(cpu_id)
    }

    fn kill(&mut self) -> Result<()> {
        self.state.kill()?;
        if let Some(child) = self.state.proc.as_mut() {
            if child.try_wait()?.is_none() {
                bail!("crosvm backend is still running");
            }
        }
        remove_socket(&self.ctr_socket_path)?;
        if self.ctr_socket_path.exists() {
            bail!(
                "control socket {} still exists after kill",
                self.ctr_socket_path.display()
            );
        }
        Ok(())
    }

    fn wait_for_socket(&self) -> Result<()> {
        self.state.wait_for_socket()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fc-drive-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn partuuid_appends_zero_padded_partition() {
        assert_eq!(partuuid_for_partition("abcd-1234", 1), "abcd-1234-01");
        assert_eq!(partuuid_for_partition("abcd-1234", 12), "abcd-1234-12");
    }

    #[test]
    fn shell_quote_only_quotes_when_needed() {
        assert_eq!(shell_quote(Path::new("/tmp/a-b.img")), "/tmp/a-b.img");
        assert_eq!(shell_quote(Path::new("/tmp/a b.img")), "'/tmp/a b.img'");
        assert_eq!(shell_quote(Path::new("/tmp/a'b.img")), r"'/tmp/a'\''b.img'");
    }

    #[test]
    fn recipe_commands_match_python() {
        assert_eq!(
            sfdisk_command(Path::new("/tmp/d.img")),
            "echo type=83 | sfdisk --no-tell-kernel /tmp/d.img"
        );
        assert_eq!(
            dd_command(Path::new("/tmp/r.ext4"), Path::new("/tmp/d.img")),
            "dd bs=1M seek=1 if=/tmp/r.ext4 of=/tmp/d.img"
        );
        assert_eq!(
            blkid_command(Path::new("/tmp/d.img")),
            "blkid -s PTUUID -o value /tmp/d.img"
        );
    }

    #[test]
    fn partuuid_and_disk_path_returns_partuuid_and_path() {
        let dir = temp_dir("partuuid");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, vec![0u8; 2 * 1024 * 1024]).expect("write rootfs");
        let disk = dir.join("disk.img");

        let commands: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let (partuuid, path) = partuuid_and_disk_path_with(&rootfs, &disk, &|cmd| {
            commands.borrow_mut().push(cmd.to_string());
            if cmd.starts_with("blkid") {
                Ok("d34d-b33f\n".to_string())
            } else {
                Ok(String::new())
            }
        })
        .expect("recipe succeeds");

        assert_eq!(partuuid, "d34d-b33f-01");
        assert_eq!(path, disk);
        assert_eq!(
            std::fs::metadata(&disk).expect("disk exists").len(),
            2 * 1024 * 1024 + 50 * MB
        );
        let recorded = commands.into_inner();
        assert_eq!(recorded.len(), 3);
        assert!(recorded[0].starts_with("echo type=83 | sfdisk --no-tell-kernel"));
        assert!(recorded[1].starts_with("dd bs=1M seek=1"));
        assert!(recorded[2].starts_with("blkid -s PTUUID -o value"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partuuid_rejects_empty_ptuuid() {
        let dir = temp_dir("empty-ptuuid");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, b"x").expect("write rootfs");
        let disk = dir.join("disk.img");
        let err = partuuid_and_disk_path_with(&rootfs, &disk, &|_| Ok("  \n".to_string()))
            .expect_err("empty ptuuid must fail");
        assert!(err.to_string().contains("empty PTUUID"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn qemu_spawn_cmd_builds_expected_argv() {
        let backend =
            QemuVhostUserBlkBackend::new("/tmp/mem.img", Path::new("/srv/jail"), "vhost", false);
        assert_eq!(
            strings(backend.spawn_cmd()),
            vec![
                "vhost-user-blk",
                "--socket-path",
                "/srv/jail/vhost_vhost_user.sock",
                "--blk-file",
                "/tmp/mem.img",
            ]
        );
    }

    #[test]
    fn qemu_spawn_cmd_adds_readonly_flag() {
        let backend =
            QemuVhostUserBlkBackend::new("/tmp/mem.img", Path::new("/srv/jail"), "vhost", true);
        let argv = strings(backend.spawn_cmd());
        assert_eq!(argv.last().map(String::as_str), Some("--read-only"));
    }

    #[test]
    fn crosvm_spawn_cmd_builds_expected_argv() {
        let backend =
            CrosvmVhostUserBlkBackend::new("/tmp/mem.img", Path::new("/srv/jail"), "vhost", false);
        assert_eq!(
            strings(backend.spawn_cmd()),
            vec![
                "crosvm",
                "--log-level",
                "off",
                "devices",
                "--disable-sandbox",
                "--control-socket",
                "/srv/jail/vhost_ctr.sock",
                "--block",
                "vhost=/srv/jail/vhost_vhost_user.sock,path=/tmp/mem.img",
            ]
        );
    }

    #[test]
    fn crosvm_spawn_cmd_marks_readonly_drive() {
        let backend =
            CrosvmVhostUserBlkBackend::new("/tmp/mem.img", Path::new("/srv/jail"), "vhost", true);
        let argv = strings(backend.spawn_cmd());
        assert_eq!(
            argv.last().map(String::as_str),
            Some("vhost=/srv/jail/vhost_vhost_user.sock,path=/tmp/mem.img,ro")
        );
    }

    #[test]
    fn backend_kind_names_round_trip() {
        for kind in [
            VhostUserBlkBackendType::Qemu,
            VhostUserBlkBackendType::Crosvm,
        ] {
            assert_eq!(
                VhostUserBlkBackendType::from_name(kind.as_str()).expect("parse kind"),
                kind
            );
        }
        assert!(VhostUserBlkBackendType::from_name("firecracker").is_err());
    }

    #[test]
    fn qemu_backend_refuses_resize() {
        let mut backend =
            QemuVhostUserBlkBackend::new("/tmp/mem.img", Path::new("/srv/jail"), "vhost", false);
        assert!(backend.resize(128).is_err());
    }

    #[test]
    fn pin_requires_a_spawned_backend() {
        let backend =
            QemuVhostUserBlkBackend::new("/tmp/mem.img", Path::new("/srv/jail"), "vhost", false);
        let err = backend.pin(1).expect_err("pin before spawn must fail");
        assert!(err.to_string().contains("not spawned"));
    }
}
