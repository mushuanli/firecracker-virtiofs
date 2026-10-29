// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Jailer configuration and helpers, ported from `tests/framework/jailer.py`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::defs;
use crate::network::NetNs;
use crate::utils;

/// Default name for the socket used for API calls.
pub const DEFAULT_USOCKET_NAME: &str = "run/firecracker.socket";

/// Default location for the chroot.
pub fn default_chroot_path() -> PathBuf {
    Path::new(defs::DEFAULT_TEST_SESSION_ROOT_PATH).join("jailer")
}

/// Represents jailer configuration and contains jailer helper functions.
#[derive(Debug, Clone)]
pub struct JailerContext {
    pub jailer_id: String,
    pub exec_file: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub chroot_base: PathBuf,
    pub netns: Option<NetNs>,
    pub daemonize: bool,
    pub new_pid_ns: bool,
    /// Firecracker arguments forwarded after `--`, order-preserving.
    pub extra_args: Vec<(String, Option<String>)>,
    pub api_socket_name: String,
    pub cgroups: Vec<String>,
    pub resource_limits: Option<Vec<String>>,
    pub cgroup_ver: Option<String>,
    pub parent_cgroup: Option<String>,
}

impl JailerContext {
    /// Creates a context with the harness defaults (uid/gid 1234, daemonized).
    pub fn new(jailer_id: impl Into<String>, exec_file: impl Into<PathBuf>) -> Self {
        Self {
            jailer_id: jailer_id.into(),
            exec_file: exec_file.into(),
            uid: 1234,
            gid: 1234,
            chroot_base: default_chroot_path(),
            netns: None,
            daemonize: true,
            new_pid_ns: false,
            extra_args: Vec::new(),
            api_socket_name: DEFAULT_USOCKET_NAME.to_string(),
            cgroups: Vec::new(),
            resource_limits: None,
            cgroup_ver: None,
            parent_cgroup: None,
        }
    }

    /// Sets (or overrides) a Firecracker argument forwarded after `--`.
    pub fn set_extra_arg(&mut self, key: impl Into<String>, value: Option<impl Into<String>>) {
        let key = key.into();
        let value = value.map(Into::into);
        if let Some(slot) = self.extra_args.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.extra_args.push((key, value));
        }
    }

    /// Whether an extra argument was set.
    pub fn has_extra_arg(&self, key: &str) -> bool {
        self.extra_args.iter().any(|(k, _)| k == key)
    }

    /// Creates the jailer parameter list, in the same order as the jailer
    /// parses them.
    pub fn construct_param_list(&mut self) -> Vec<String> {
        let mut params = Vec::new();
        push_pair(&mut params, "--id", Some(self.jailer_id.clone()));
        push_pair(
            &mut params,
            "--exec-file",
            Some(self.exec_file.to_string_lossy().into_owned()),
        );
        push_pair(&mut params, "--uid", Some(self.uid.to_string()));
        push_pair(&mut params, "--gid", Some(self.gid.to_string()));
        push_pair(
            &mut params,
            "--chroot-base-dir",
            Some(self.chroot_base.to_string_lossy().into_owned()),
        );
        if let Some(netns) = &self.netns {
            push_pair(
                &mut params,
                "--netns",
                Some(netns.path().to_string_lossy().into_owned()),
            );
        }
        if self.daemonize {
            params.push("--daemonize".to_string());
        }
        if self.new_pid_ns {
            params.push("--new-pid-ns".to_string());
        }
        if let Some(parent) = &self.parent_cgroup {
            push_pair(&mut params, "--parent-cgroup", Some(parent.clone()));
        }
        if let Some(version) = &self.cgroup_ver {
            push_pair(&mut params, "--cgroup-version", Some(version.clone()));
        }
        for cgroup in &self.cgroups {
            push_pair(&mut params, "--cgroup", Some(cgroup.clone()));
        }
        if let Some(limits) = &self.resource_limits {
            for limit in limits {
                push_pair(&mut params, "--resource-limit", Some(limit.clone()));
            }
        }
        if !self.extra_args.is_empty() {
            params.push("--".to_string());
            for (key, value) in &self.extra_args {
                params.push(format!("--{key}"));
                if let Some(value) = value {
                    params.push(value.clone());
                    if key == "api-sock" {
                        self.api_socket_name = value.clone();
                    }
                }
            }
        }
        params
    }

    /// MicroVM chroot base + MicroVM id.
    pub fn chroot_base_with_id(&self) -> PathBuf {
        let exec_name = self
            .exec_file
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(defs::FC_BINARY_NAME));
        self.chroot_base.join(exec_name).join(&self.jailer_id)
    }

    /// Path of the MicroVM API socket.
    pub fn api_socket_path(&self) -> PathBuf {
        self.chroot_path().join(&self.api_socket_name)
    }

    /// Path of the MicroVM chroot.
    pub fn chroot_path(&self) -> PathBuf {
        self.chroot_base_with_id().join("root")
    }

    /// Hard-links (or copies) `file_path` into the jail and returns the path
    /// that is valid *inside* the jail.
    pub fn jailed_path(&self, file_path: &Path, create: bool, subdir: &str) -> Result<PathBuf> {
        let chroot_path = self.chroot_path();
        let global_path = chroot_path.join(subdir).join(
            file_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("{} has no file name", file_path.display()))?,
        );
        if let Some(parent) = global_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let jailed_path = Path::new("/")
            .join(subdir)
            .join(file_path.file_name().expect("checked above"));

        if create {
            let metadata = std::fs::metadata(file_path)
                .with_context(|| format!("stat {}", file_path.display()))?;
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            if metadata.file_type().is_block_device() {
                create_block_device(&global_path, metadata.rdev())?;
            } else {
                let chroot_meta = std::fs::metadata(&chroot_path)
                    .with_context(|| format!("stat {}", chroot_path.display()))?;
                if metadata.dev() == chroot_meta.dev() {
                    // Same device: hardlink.
                    if global_path.exists() {
                        std::fs::remove_file(&global_path)?;
                    }
                    std::fs::hard_link(file_path, &global_path).with_context(|| {
                        format!(
                            "hardlink {} -> {}",
                            file_path.display(),
                            global_path.display()
                        )
                    })?;
                } else {
                    std::fs::copy(file_path, &global_path).with_context(|| {
                        format!("copy {} -> {}", file_path.display(), global_path.display())
                    })?;
                }
            }
            chown(&global_path, self.uid, self.gid)?;
        }
        Ok(jailed_path)
    }

    /// Creates the chroot base directory.
    pub fn setup(&self) -> Result<()> {
        std::fs::create_dir_all(&self.chroot_base)
            .with_context(|| format!("creating {}", self.chroot_base.display()))?;
        Ok(())
    }

    /// Removes the cgroups created for this microVM.
    pub fn cleanup(&self) -> Result<()> {
        if self.cgroups.is_empty() {
            return Ok(());
        }
        let mut controllers: Vec<&str> = self
            .cgroups
            .iter()
            .map(|cgroup| cgroup.split('.').next().unwrap_or(cgroup))
            .collect();
        controllers.sort_unstable();
        controllers.dedup();

        for controller in controllers {
            let _ = utils::retry_for(Duration::from_secs(5), Duration::from_millis(50), || {
                self.kill_cgroup_tasks(controller)
            });
            // Remove cgroups and sub cgroups; failures are ignorable because
            // we are cleaning up resources created by the jailer itself.
            let _ = utils::run_cmd(&format!(
                "find /sys/fs/cgroup/{controller}/{}/{}/ -depth -type d -exec rmdir {{}} \\;",
                defs::FC_BINARY_NAME,
                self.jailer_id
            ));
        }
        Ok(())
    }

    /// Waits until every task in the controller cgroup is gone.
    pub fn kill_cgroup_tasks(&self, controller: &str) -> Result<()> {
        let tasks_file = format!(
            "/sys/fs/cgroup/{controller}/{}/{}/tasks",
            defs::FC_BINARY_NAME,
            self.jailer_id
        );
        // If the tests do not start the machine, the cgroup is not created.
        if !Path::new(&tasks_file).exists() {
            return Ok(());
        }
        let stdout = std::fs::read_to_string(&tasks_file)?;
        for task in stdout.lines() {
            if Path::new(&format!("/proc/{}", task.trim())).exists() {
                bail!("task {} still alive in {}", task.trim(), tasks_file);
            }
        }
        Ok(())
    }

    /// PID file written by the jailer.
    pub fn pid_file(&self) -> PathBuf {
        self.chroot_path().join(format!(
            "{}.pid",
            self.exec_file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| defs::FC_BINARY_NAME.to_string())
        ))
    }
}

fn push_pair(params: &mut Vec<String>, flag: &str, value: Option<String>) {
    if let Some(value) = value {
        params.push(flag.to_string());
        params.push(value);
    }
}

fn create_block_device(path: &Path, device: u64) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let c_path = CString::new(path.to_string_lossy().as_bytes())?;
    // SAFETY: `c_path` is a valid NUL-terminated path and `device` is the
    // rdev reported by `stat(2)` for the source block device.
    let rc = unsafe {
        libc::mknod(
            c_path.as_ptr(),
            libc::S_IFBLK | (0o600),
            device as libc::dev_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mknod {}", path.display()));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_string_lossy().as_bytes())?;
    // SAFETY: `c_path` is a valid NUL-terminated path.
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("chown {} to {uid}:{gid}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> JailerContext {
        JailerContext::new("test-vm", "/usr/bin/firecracker")
    }

    #[test]
    fn default_param_order_matches_jailer() {
        let mut jailer = context();
        jailer.uid = 1234;
        jailer.gid = 1234;
        jailer.chroot_base = PathBuf::from("/srv/jailer");
        assert_eq!(
            jailer.construct_param_list(),
            vec![
                "--id",
                "test-vm",
                "--exec-file",
                "/usr/bin/firecracker",
                "--uid",
                "1234",
                "--gid",
                "1234",
                "--chroot-base-dir",
                "/srv/jailer",
                "--daemonize",
            ]
        );
    }

    #[test]
    fn extra_args_are_forwarded_after_separator() {
        let mut jailer = context();
        jailer.set_extra_arg("log-path", Some("fc.log"));
        jailer.set_extra_arg("show-level", None::<String>);
        let params = jailer.construct_param_list();
        let position = params.iter().position(|p| p == "--").unwrap();
        assert_eq!(
            &params[position..],
            ["--", "--log-path", "fc.log", "--show-level"]
        );
    }

    #[test]
    fn api_sock_extra_arg_updates_socket_name() {
        let mut jailer = context();
        jailer.set_extra_arg("api-sock", Some("custom.socket"));
        jailer.construct_param_list();
        assert_eq!(jailer.api_socket_name, "custom.socket");
        assert!(jailer.api_socket_path().ends_with("root/custom.socket"));
    }

    #[test]
    fn chroot_paths_follow_exec_name_and_id() {
        let mut jailer = context();
        jailer.chroot_base = PathBuf::from("/srv/jailer");
        assert_eq!(
            jailer.chroot_base_with_id(),
            PathBuf::from("/srv/jailer/firecracker/test-vm")
        );
        assert_eq!(
            jailer.chroot_path(),
            PathBuf::from("/srv/jailer/firecracker/test-vm/root")
        );
        assert_eq!(
            jailer.api_socket_path(),
            PathBuf::from("/srv/jailer/firecracker/test-vm/root/run/firecracker.socket")
        );
        assert_eq!(
            jailer.pid_file(),
            PathBuf::from("/srv/jailer/firecracker/test-vm/root/firecracker.pid")
        );
    }

    #[test]
    fn cgroup_and_limit_flags_are_repeated() {
        let mut jailer = context();
        jailer.cgroups = vec!["cpu.weight".into(), "memory.max".into()];
        jailer.resource_limits = Some(vec!["no-file=1024".into()]);
        jailer.cgroup_ver = Some("v2".into());
        jailer.parent_cgroup = Some("pytest".into());
        let params = jailer.construct_param_list();
        let joined = params.join(" ");
        assert!(joined.contains("--parent-cgroup pytest"));
        assert!(joined.contains("--cgroup-version v2"));
        assert!(joined.contains("--cgroup cpu.weight --cgroup memory.max"));
        assert!(joined.contains("--resource-limit no-file=1024"));
    }

    #[test]
    fn extra_arg_override_keeps_single_entry() {
        let mut jailer = context();
        jailer.set_extra_arg("level", Some("Debug"));
        jailer.set_extra_arg("level", Some("Info"));
        assert_eq!(jailer.extra_args.len(), 1);
        assert_eq!(jailer.extra_args[0].1.as_deref(), Some("Info"));
        assert!(jailer.has_extra_arg("level"));
        assert!(!jailer.has_extra_arg("log-path"));
    }
}
