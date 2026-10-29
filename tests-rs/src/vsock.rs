// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! vsock device test helpers, ported from `tests/framework/utils_vsock.py`.
//!
//! Mapping notes:
//!
//! * `HostEchoWorker` stays a `std::thread` based worker: [`HostEchoWorker::new`]
//!   connects (python `__init__`), [`HostEchoWorker::start`] spawns the thread and
//!   [`HostEchoWorker::join`] collects the result.
//! * `host_echo_server` is no longer a `socat` subprocess but an in-process
//!   [`HostEchoServer`] built on `std::os::unix::net::UnixListener`, with the same
//!   backlog and one echo thread per connection.
//! * The python helpers take the whole `MicroVm`; the port takes the narrow
//!   pieces they actually use: the `SshConnection`, the jail root (`vm.chroot()`)
//!   and the jail base dir (`vm.path`), plus a closure standing in for
//!   `vm.create_jailed_resource()`.
//! * `hashlib.md5` has no dependency in this crate, so the module carries a small
//!   streaming MD5 ([`md5_hex`]) and compares against `md5sum` output in the guest.

use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore;

use crate::network::SshConnection;
use crate::utils::retry_attempts;

/// Guest vsock port the echo servers listen on (`ECHO_SERVER_PORT`).
pub const ECHO_SERVER_PORT: u32 = 5252;

/// Accept backlog of the host echo server (`SERVER_ACCEPT_BACKLOG`).
pub const SERVER_ACCEPT_BACKLOG: usize = 128;

/// Number of concurrent echo workers used by the connection checks.
pub const TEST_CONNECTION_COUNT: usize = 50;

/// Default size of the blob exchanged over vsock (`BLOB_SIZE`).
pub const BLOB_SIZE: usize = 1024 * 1024;

/// Size of a single read/write chunk (`BUF_SIZE`).
pub const BUF_SIZE: usize = 64 * 1024;

/// File name of the host UDS backing the vsock device (`VSOCK_UDS_PATH`).
pub const VSOCK_UDS_PATH: &str = "v.sock";

/// Name of the blob file inside the session root.
pub const BLOB_FILE_NAME: &str = "vsock-test.blob";

/// Directory created inside the guest for the blob (`/tmp/vsock`).
pub const GUEST_VSOCK_DIR: &str = "/tmp/vsock";

/// Blob path inside the guest (`/tmp/vsock/test.blob`).
pub const GUEST_BLOB_PATH: &str = "/tmp/vsock/test.blob";

/// Path the `vsock_helper` binary is copied to inside the guest.
pub const GUEST_VSOCK_HELPER: &str = "/tmp/vsock_helper";

/// `pids.max` value written for the ssh service, so guest workers can fork.
pub const SSH_SERVICE_PIDS_MAX: u32 = 1024;

/// Timeout used for guest commands over SSH.
pub const SSH_TIMEOUT: Duration = Duration::from_secs(100);

/// Builds the path of the host Unix socket backing guest vsock `port`
/// (python `make_host_port_path`).
pub fn make_host_port_path(uds_path: &Path, port: u32) -> PathBuf {
    let mut path = uds_path.as_os_str().to_os_string();
    path.push(format!("_{port}"));
    PathBuf::from(path)
}

/// Generates a random [`BLOB_SIZE`] blob and its MD5, i.e. python
/// `make_blob(dst_dir)` with the default `size=BLOB_SIZE`.
pub fn make_blob_default(dst_dir: &Path) -> Result<(PathBuf, String)> {
    make_blob(dst_dir, BLOB_SIZE)
}

/// Generates a random blob of `size` bytes and its MD5 (python `make_blob`).
pub fn make_blob(dst_dir: &Path, size: usize) -> Result<(PathBuf, String)> {
    let blob_path = dst_dir.join(BLOB_FILE_NAME);
    let mut blob_file = File::create(&blob_path)
        .with_context(|| format!("creating vsock blob {}", blob_path.display()))?;

    let mut left = size;
    let mut md5 = Md5::new();
    let mut rng = rand::rngs::OsRng;
    let mut buffer = vec![0u8; 4096];
    while left > 0 {
        let count = left.min(buffer.len());
        rng.fill_bytes(&mut buffer[..count]);
        md5.update(&buffer[..count]);
        blob_file
            .write_all(&buffer[..count])
            .with_context(|| format!("writing vsock blob {}", blob_path.display()))?;
        left -= count;
    }
    blob_file
        .flush()
        .with_context(|| format!("flushing vsock blob {}", blob_path.display()))?;

    Ok((blob_path, md5.hexdigest()))
}

/// MD5 hex digest, standing in for python's `hashlib.md5().hexdigest()`.
pub fn md5_hex(data: &[u8]) -> String {
    let mut md5 = Md5::new();
    md5.update(data);
    md5.hexdigest()
}

/// Returns true when `ack` matches the connect acknowledgement `OK <port>`.
pub fn is_connect_ack(ack: &str) -> bool {
    static ACK: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = ACK.get_or_init(|| {
        regex::Regex::new(r"^OK [0-9]+\n$").expect("static vsock ACK regex is valid")
    });
    pattern.is_match(ack)
}

/// Connects to guest vsock `port` through the UDS at `uds_path`
/// (python `vsock_connect_to_guest`).
///
/// The returned socket is an ordinary [`UnixStream`]; on any failure during the
/// CONNECT/ACK handshake it is dropped before the error is returned.
pub fn vsock_connect_to_guest(uds_path: &Path, port: u32) -> Result<UnixStream> {
    let mut stream = UnixStream::connect(uds_path)
        .with_context(|| format!("connecting to vsock UDS {}", uds_path.display()))?;

    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .context("sending vsock CONNECT")?;

    let mut ack_buffer = [0u8; 32];
    let read = stream.read(&mut ack_buffer).context("reading vsock ACK")?;
    let ack = String::from_utf8_lossy(&ack_buffer[..read]).into_owned();
    if !is_connect_ack(&ack) {
        bail!("unexpected vsock ACK {ack:?} for port {port}");
    }

    Ok(stream)
}

/// Starts `socat` as a guest-side vsock echo server and returns its UDS path
/// (python `start_guest_echo_server`).
///
/// `chroot` is python `vm.jailer.chroot_path()` (`vm.chroot()`).
pub fn start_guest_echo_server(ssh: &SshConnection, chroot: &Path) -> Result<PathBuf> {
    let cmd = format!(
        "nohup socat VSOCK-LISTEN:{ECHO_SERVER_PORT},backlog={SERVER_ACCEPT_BACKLOG},\
reuseaddr,fork EXEC:'/bin/cat' > /dev/null 2>&1 &"
    );
    ssh.check_output(&cmd, SSH_TIMEOUT)?;

    // Give the server time to initialise.
    thread::sleep(Duration::from_secs(1));

    Ok(chroot.join(VSOCK_UDS_PATH))
}

/// Copies the blob and the vsock helper into the guest
/// (python `_copy_vsock_data_to_guest`).
pub fn copy_vsock_data_to_guest(
    ssh: &SshConnection,
    blob_path: &Path,
    vm_blob_path: &str,
    vsock_helper: &Path,
) -> Result<()> {
    let result = ssh.run(&format!("mkdir -p {GUEST_VSOCK_DIR}"), SSH_TIMEOUT)?;
    if !result.success() {
        bail!(
            "Failed to set up tmpfs drive on the guest: {}",
            result.describe("mkdir -p")
        );
    }
    ssh.scp_put(vsock_helper, GUEST_VSOCK_HELPER, false)?;
    ssh.scp_put(blob_path, vm_blob_path, false)?;
    Ok(())
}

/// A vsock echo worker that sends a blob through the guest echo server and
/// hashes everything echoed back (python `HostEchoWorker`).
#[derive(Debug)]
pub struct HostEchoWorker {
    uds_path: PathBuf,
    blob_path: PathBuf,
    sock: Option<UnixStream>,
    shutdown: Option<UnixStream>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<String>>>,
    hash: Option<String>,
    error: Option<String>,
}

impl HostEchoWorker {
    /// Connects to the guest echo server, like the python constructor does.
    pub fn new(uds_path: &Path, blob_path: &Path) -> Result<Self> {
        let sock = vsock_connect_to_guest(uds_path, ECHO_SERVER_PORT)?;
        Ok(Self {
            uds_path: uds_path.to_path_buf(),
            blob_path: blob_path.to_path_buf(),
            sock: Some(sock),
            shutdown: None,
            stop: Arc::new(AtomicBool::new(false)),
            handle: None,
            hash: None,
            error: None,
        })
    }

    /// UDS path the worker is connected to.
    pub fn uds_path(&self) -> &Path {
        &self.uds_path
    }

    /// Blob the worker sends.
    pub fn blob_path(&self) -> &Path {
        &self.blob_path
    }

    /// Hash of the echoed data, once the worker finished.
    pub fn hash(&self) -> Option<&str> {
        self.hash.as_deref()
    }

    /// Error captured by the worker thread, if any.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Whether the worker thread is still running.
    pub fn is_alive(&self) -> bool {
        self.handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }

    /// Spawns the worker thread (python `Thread.start`).
    pub fn start(&mut self) -> Result<()> {
        if self.handle.is_some() {
            bail!(
                "host echo worker for {} is already running",
                self.uds_path.display()
            );
        }
        let mut sock = self
            .sock
            .take()
            .ok_or_else(|| anyhow!("host echo worker socket is closed"))?;
        // `shutdown` acts on the socket itself, not on this descriptor, so it
        // also unblocks the worker thread holding the duplicate.
        self.shutdown = Some(
            sock.try_clone()
                .context("duplicating host echo worker socket")?,
        );
        let blob_path = self.blob_path.clone();
        let stop = Arc::clone(&self.stop);
        self.handle = Some(thread::spawn(move || {
            echo_blob(&mut sock, &blob_path, &stop)
        }));
        Ok(())
    }

    /// Runs the transfer synchronously (python `_run`) and stores the hash.
    pub fn run(&mut self) -> Result<String> {
        let mut sock = self
            .sock
            .take()
            .ok_or_else(|| anyhow!("host echo worker socket is closed"))?;
        let hash = echo_blob(&mut sock, &self.blob_path, &self.stop)?;
        self.hash = Some(hash.clone());
        Ok(hash)
    }

    /// Waits for the worker thread to finish (python `Thread.join`).
    pub fn join(&mut self) -> Result<()> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        match handle.join() {
            Ok(Ok(hash)) => {
                self.hash = Some(hash);
                Ok(())
            }
            Ok(Err(err)) => {
                self.error = Some(format!("{err:#}"));
                Err(err)
            }
            Err(_) => {
                let message = "host echo worker thread panicked".to_string();
                self.error = Some(message.clone());
                Err(anyhow!(message))
            }
        }
    }

    /// Closes the UDS connection, unblocking a running worker.
    pub fn close_uds(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        let stream = self.shutdown.take().or_else(|| self.sock.take());
        if let Some(stream) = stream {
            match stream.shutdown(Shutdown::Both) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotConnected => {}
                Err(err) => return Err(err).context("closing vsock UDS connection"),
            }
        }
        Ok(())
    }
}

impl Drop for HostEchoWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if self.handle.is_some() {
            let _ = self.join();
        }
        let _ = self.close_uds();
    }
}

/// Streams the blob to `sock` and hashes the echo, returning the MD5 digest.
fn echo_blob(sock: &mut UnixStream, blob_path: &Path, stop: &AtomicBool) -> Result<String> {
    let mut blob_file = File::open(blob_path)
        .with_context(|| format!("opening vsock blob {}", blob_path.display()))?;
    let mut md5 = Md5::new();
    let mut buffer = vec![0u8; BUF_SIZE];
    let mut echoed = vec![0u8; BUF_SIZE];

    loop {
        if stop.load(Ordering::SeqCst) {
            bail!("host echo worker stopped before the blob was fully echoed");
        }
        let sent = blob_file
            .read(&mut buffer)
            .with_context(|| format!("reading vsock blob {}", blob_path.display()))?;
        if sent == 0 {
            break;
        }
        sock.write_all(&buffer[..sent])
            .context("sending data to the guest echo server")?;
        sock.read_exact(&mut echoed[..sent])
            .context("receiving echoed data from the guest")?;
        md5.update(&echoed[..sent]);
    }

    Ok(md5.hexdigest())
}

/// Host-side Unix socket echo server, replacing the python `socat` process
/// (`UNIX-LISTEN:...,fork,backlog=128 exec:'/bin/cat'`).
#[derive(Debug)]
pub struct HostEchoServer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl HostEchoServer {
    /// Binds `path` and starts accepting connections on a background thread.
    ///
    /// The listener uses the standard library backlog of
    /// [`SERVER_ACCEPT_BACKLOG`] and echoes every connection back like
    /// `/bin/cat` does under `socat ... fork`.
    pub fn start(path: &Path) -> Result<Self> {
        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("removing stale echo socket {}", path.display()))?;
        }
        let listener = UnixListener::bind(path)
            .with_context(|| format!("binding echo socket {}", path.display()))?;
        listener
            .set_nonblocking(true)
            .context("making echo socket non-blocking")?;

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || serve(listener, thread_stop));

        Ok(Self {
            path: path.to_path_buf(),
            stop,
            handle: Some(handle),
        })
    }

    /// Path of the echo socket.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the accept loop is still running.
    pub fn is_running(&self) -> bool {
        self.handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }

    /// Stops the accept loop, joins it and removes the socket file.
    pub fn stop(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| anyhow!("host echo server thread panicked"))?;
        }
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("removing {}", self.path.display())),
        }
    }
}

impl Drop for HostEchoServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Accept loop of [`HostEchoServer`], one echo thread per connection.
fn serve(listener: UnixListener, stop: Arc<AtomicBool>) {
    let mut connections = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let thread_stop = Arc::clone(&stop);
                connections.push(thread::spawn(move || {
                    let _ = echo_connection(stream, thread_stop);
                }));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    for connection in connections {
        let _ = connection.join();
    }
}

/// Echoes one connection until the peer closes it or the server stops.
fn echo_connection(mut stream: UnixStream, stop: Arc<AtomicBool>) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .context("setting echo socket read timeout")?;
    let mut buffer = vec![0u8; BUF_SIZE];
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => stream
                .write_all(&buffer[..read])
                .context("echoing data back to the peer")?,
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(err).context("reading from the echo peer"),
        }
    }
}

/// Runs [`TEST_CONNECTION_COUNT`] host-initiated echo workers
/// (python `check_host_connections`).
pub fn check_host_connections(uds_path: &Path, blob_path: &Path, blob_hash: &str) -> Result<()> {
    let mut workers = (0..TEST_CONNECTION_COUNT)
        .map(|_| HostEchoWorker::new(uds_path, blob_path))
        .collect::<Result<Vec<_>>>()?;

    for worker in &mut workers {
        worker.start()?;
    }
    for worker in &mut workers {
        worker.join()?;
    }

    for (index, worker) in workers.iter().enumerate() {
        let hash = worker
            .hash()
            .ok_or_else(|| anyhow!("host echo worker {index} produced no hash"))?;
        if hash != blob_hash {
            bail!("host echo worker {index} echoed hash {hash}, expected {blob_hash}");
        }
    }
    Ok(())
}

/// Builds the guest worker sub-command used by `check_guest_connections`.
///
/// `vsock_helper` reads the blob from STDIN, sends it through the host echo
/// server and writes the response to STDOUT; the md5 comparison decides the exit
/// status of the worker.
pub fn guest_worker_command(vm_blob_path: &str, blob_hash: &str) -> String {
    let mut worker_cmd = String::from("hash=$(");
    worker_cmd.push_str(&format!("cat {vm_blob_path}"));
    worker_cmd.push_str(&format!(
        " | {GUEST_VSOCK_HELPER} echo 2 {ECHO_SERVER_PORT}"
    ));
    worker_cmd.push_str(" | md5sum | cut -f1 -d\\ ");
    worker_cmd.push(')');
    worker_cmd.push_str(&format!(" && [[ \"$hash\" = \"{blob_hash}\" ]]"));
    worker_cmd
}

/// Wraps `worker_cmd` into `count` concurrent guest workers and waits for them.
pub fn guest_workers_command(count: usize, worker_cmd: &str) -> String {
    let mut cmd = String::from("workers=\"\";");
    cmd.push_str(&format!("for i in $(seq 1 {count}); do"));
    cmd.push_str(&format!("  ({worker_cmd})& "));
    cmd.push_str("  workers=\"$workers $!\";");
    cmd.push_str("done;");
    cmd.push_str("for w in $workers; do wait $w || (wait; exit 1); done");
    cmd
}

/// Raises the ssh service `pids.max` so guest workers can fork
/// (python does this inside `host_echo_server`).
pub fn raise_ssh_service_pids_max(ssh: &SshConnection, ssh_service: &str) -> Result<()> {
    let cmd =
        format!("echo {SSH_SERVICE_PIDS_MAX} > /sys/fs/cgroup/system.slice/{ssh_service}/pids.max");
    ssh.check_output(&cmd, SSH_TIMEOUT)?;
    Ok(())
}

/// Runs `TEST_CONNECTION_COUNT` guest-initiated echo workers against a host echo
/// server (python `check_guest_connections`).
///
/// `link_into_jail` replaces `vm.create_jailed_resource(server_port_path)`: it
/// must hard-link the host socket into the microVM jail so Firecracker can reach
/// it. `ssh_service` is python `vm.distro.ssh_service`.
pub fn check_guest_connections<F>(
    ssh: &SshConnection,
    ssh_service: &str,
    server_port_path: &Path,
    vm_blob_path: &str,
    blob_hash: &str,
    link_into_jail: F,
) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    let mut server = HostEchoServer::start(server_port_path)?;
    let result = (move || -> Result<()> {
        // Give the server a bit of time to create the socket.
        retry_attempts(3, Duration::from_millis(200), || {
            if server_port_path.exists() {
                Ok(())
            } else {
                bail!("echo socket {} was not created", server_port_path.display());
            }
        })?;

        // Link the listening Unix socket into the VM's jail, so that
        // Firecracker can connect to it.
        link_into_jail(server_port_path)?;

        // Needed to execute the bash script that tests for concurrent vsock
        // guest initiated connections.
        raise_ssh_service_pids_max(ssh, ssh_service)?;

        let worker_cmd = guest_worker_command(vm_blob_path, blob_hash);
        let cmd = guest_workers_command(TEST_CONNECTION_COUNT, &worker_cmd);
        ssh.check_output(&cmd, SSH_TIMEOUT)?;
        Ok(())
    })();

    let stopped = server.stop();
    result?;
    stopped?;
    Ok(())
}

/// Creates a blob and tests host- and guest-initiated vsock connections
/// (python `check_vsock_device`).
///
/// `jail_base` is python `vm.path` (`jailer.chroot_base_with_id()`), `chroot` is
/// python `vm.chroot()` and `ssh` is python `vm.ssh` / `ssh_connection`.
pub fn check_vsock_device<F>(
    ssh: &SshConnection,
    jail_base: &Path,
    chroot: &Path,
    test_fc_session_root_path: &Path,
    bin_vsock_path: &Path,
    ssh_service: &str,
    link_into_jail: F,
) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    // Generate a random data file for vsock.
    let (blob_path, blob_hash) = make_blob(test_fc_session_root_path, BLOB_SIZE)?;

    // Copy the data file and a vsock helper to the guest.
    copy_vsock_data_to_guest(ssh, &blob_path, GUEST_BLOB_PATH, bin_vsock_path)?;

    // Test vsock guest-initiated connections.
    let host_port_path = jail_base.join(make_host_port_path(
        Path::new(VSOCK_UDS_PATH),
        ECHO_SERVER_PORT,
    ));
    check_guest_connections(
        ssh,
        ssh_service,
        &host_port_path,
        GUEST_BLOB_PATH,
        &blob_hash,
        link_into_jail,
    )?;

    // Test vsock host-initiated connections.
    let uds_path = start_guest_echo_server(ssh, chroot)?;
    check_host_connections(&uds_path, &blob_path, &blob_hash)
}

/// Minimal streaming MD5, standing in for python's `hashlib.md5`.
#[derive(Debug, Clone)]
struct Md5 {
    state: [u32; 4],
    buffer: Vec<u8>,
    length: u64,
}

impl Md5 {
    /// Creates a fresh hash state.
    fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            buffer: Vec::new(),
            length: 0,
        }
    }

    /// Feeds `data` into the hash state.
    fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        self.buffer.extend_from_slice(data);

        let mut offset = 0;
        while self.buffer.len() - offset >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&self.buffer[offset..offset + 64]);
            self.process(&block);
            offset += 64;
        }
        if offset > 0 {
            self.buffer.drain(..offset);
        }
    }

    /// Finishes a copy of the current state and returns the hex digest.
    fn hexdigest(&self) -> String {
        let mut finished = self.clone();
        finished.finish();
        finished
            .state
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Applies the padding and processes the remaining blocks.
    fn finish(&mut self) {
        let bit_length = self.length.wrapping_mul(8);
        self.buffer.push(0x80);
        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0);
        }
        self.buffer.extend_from_slice(&bit_length.to_le_bytes());

        let mut offset = 0;
        while offset < self.buffer.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&self.buffer[offset..offset + 64]);
            self.process(&block);
            offset += 64;
        }
        self.buffer.clear();
    }

    /// Processes a single 64 byte block.
    fn process(&mut self, block: &[u8; 64]) {
        const SHIFTS: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        const TABLE: [u32; 64] = [
            0xd76a_a478,
            0xe8c7_b756,
            0x2420_70db,
            0xc1bd_ceee,
            0xf57c_0faf,
            0x4787_c62a,
            0xa830_4613,
            0xfd46_9501,
            0x6980_98d8,
            0x8b44_f7af,
            0xffff_5bb1,
            0x895c_d7be,
            0x6b90_1122,
            0xfd98_7193,
            0xa679_438e,
            0x49b4_0821,
            0xf61e_2562,
            0xc040_b340,
            0x265e_5a51,
            0xe9b6_c7aa,
            0xd62f_105d,
            0x0244_1453,
            0xd8a1_e681,
            0xe7d3_fbc8,
            0x21e1_cde6,
            0xc337_07d6,
            0xf4d5_0d87,
            0x455a_14ed,
            0xa9e3_e905,
            0xfcef_a3f8,
            0x676f_02d9,
            0x8d2a_4c8a,
            0xfffa_3942,
            0x8771_f681,
            0x6d9d_6122,
            0xfde5_380c,
            0xa4be_ea44,
            0x4bde_cfa9,
            0xf6bb_4b60,
            0xbebf_bc70,
            0x289b_7ec6,
            0xeaa1_27fa,
            0xd4ef_3085,
            0x0488_1d05,
            0xd9d4_d039,
            0xe6db_99e5,
            0x1fa2_7cf8,
            0xc4ac_5665,
            0xf429_2244,
            0x432a_ff97,
            0xab94_23a7,
            0xfc93_a039,
            0x655b_59c3,
            0x8f0c_cc92,
            0xffef_f47d,
            0x8584_5dd1,
            0x6fa8_7e4f,
            0xfe2c_e6e0,
            0xa301_4314,
            0x4e08_11a1,
            0xf753_7e82,
            0xbd3a_f235,
            0x2ad7_d2bb,
            0xeb86_d391,
        ];

        let mut words = [0u32; 16];
        for (index, chunk) in block.chunks(4).enumerate() {
            words[index] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let [mut a, mut b, mut c, mut d] = self.state;
        for index in 0..64 {
            let (f, g) = match index {
                0..=15 => ((b & c) | (!b & d), index),
                16..=31 => ((d & b) | (!d & c), (5 * index + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * index + 5) % 16),
                _ => (c ^ (b | !d), (7 * index) % 16),
            };
            let rotated = a
                .wrapping_add(f)
                .wrapping_add(TABLE[index])
                .wrapping_add(words[g])
                .rotate_left(SHIFTS[index]);
            let previous_d = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
            a = previous_d;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    static UNIQUE: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let unique = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "fc-harness-vsock-{}-{}-{tag}",
            std::process::id(),
            unique
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn constants_match_python_module() {
        assert_eq!(ECHO_SERVER_PORT, 5252);
        assert_eq!(SERVER_ACCEPT_BACKLOG, 128);
        assert_eq!(TEST_CONNECTION_COUNT, 50);
        assert_eq!(BLOB_SIZE, 1 << 20);
        assert_eq!(BUF_SIZE, 64 << 10);
        assert_eq!(VSOCK_UDS_PATH, "v.sock");
        assert_eq!(GUEST_BLOB_PATH, "/tmp/vsock/test.blob");
    }

    #[test]
    fn host_port_path_appends_the_port() {
        assert_eq!(
            make_host_port_path(Path::new(VSOCK_UDS_PATH), ECHO_SERVER_PORT),
            PathBuf::from("v.sock_5252")
        );
        assert_eq!(
            make_host_port_path(Path::new("/srv/jail/v.sock"), 5300),
            PathBuf::from("/srv/jail/v.sock_5300")
        );
    }

    #[test]
    fn md5_matches_reference_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(b"message digest"),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            md5_hex(b"The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        assert_eq!(
            md5_hex(&vec![b'a'; 1_000_000]),
            "7707d6ae4e027c70eea2a935c2296f21"
        );
    }

    #[test]
    fn md5_is_chunk_independent() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let mut streamed = Md5::new();
        for chunk in data.chunks(7) {
            streamed.update(chunk);
        }
        assert_eq!(streamed.hexdigest(), md5_hex(data));
    }

    #[test]
    fn make_blob_writes_requested_size_and_hashes_content() {
        let dir = temp_dir("blob");
        let (path, hash) = make_blob(&dir, 8192).expect("blob");
        assert_eq!(path, dir.join(BLOB_FILE_NAME));
        let contents = fs::read(&path).expect("read blob");
        assert_eq!(contents.len(), 8192);
        assert_eq!(hash, md5_hex(&contents));

        let (_, other_hash) = make_blob(&dir, 8192).expect("blob");
        assert_ne!(hash, other_hash, "blob content must be random");

        let (default_path, default_hash) = make_blob_default(&dir).expect("default blob");
        assert_eq!(
            fs::metadata(&default_path).expect("stat blob").len(),
            BLOB_SIZE as u64
        );
        assert_eq!(default_hash.len(), 32);
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn connect_ack_validation() {
        assert!(is_connect_ack("OK 5252\n"));
        assert!(is_connect_ack("OK 0\n"));
        assert!(!is_connect_ack("OK 5252"));
        assert!(!is_connect_ack("OK\n"));
        assert!(!is_connect_ack("NOPE 5252\n"));
    }

    #[test]
    fn host_echo_server_echoes_each_connection() {
        let dir = temp_dir("echo-server");
        let socket = dir.join("echo.sock");
        let mut server = HostEchoServer::start(&socket).expect("start echo server");
        assert!(server.is_running());

        let mut client = UnixStream::connect(&socket).expect("connect");
        client.write_all(b"hello vsock").expect("write");
        let mut echoed = [0u8; 11];
        client.read_exact(&mut echoed).expect("read echo");
        assert_eq!(&echoed, b"hello vsock");

        assert_eq!(server.path(), socket.as_path());
        server.stop().expect("stop echo server");
        assert!(!server.is_running());
        assert!(!socket.exists());
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn echo_worker_round_trips_through_a_guest_echo_server() {
        let dir = temp_dir("echo-worker");
        let socket = dir.join("v.sock_5252");
        let blob = dir.join("blob.bin");
        let payload: Vec<u8> = (0..64 * 1024 + 123).map(|i| (i % 251) as u8).collect();
        fs::write(&blob, &payload).expect("write blob");

        // Stand-in for Firecracker + the guest echo server: acknowledge the
        // CONNECT handshake and then echo every byte back.
        let listener = UnixListener::bind(&socket).expect("bind fake guest");
        let guest = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut buffer = [0u8; 32];
            let read = stream.read(&mut buffer)?;
            let connect = String::from_utf8_lossy(&buffer[..read]).into_owned();
            if !connect.starts_with("CONNECT 5252") {
                bail!("unexpected CONNECT request {connect:?}");
            }
            stream.write_all(b"OK 5252\n")?;
            loop {
                let read = stream.read(&mut buffer)?;
                if read == 0 {
                    return Ok(());
                }
                stream.write_all(&buffer[..read])?;
            }
        });

        let mut worker = HostEchoWorker::new(&socket, &blob).expect("connect worker");
        assert_eq!(worker.blob_path(), blob.as_path());
        assert_eq!(worker.uds_path(), socket.as_path());
        worker.start().expect("start worker");
        worker.join().expect("join worker");

        let expected = md5_hex(&payload);
        assert_eq!(worker.hash(), Some(expected.as_str()));
        assert!(worker.error().is_none());
        assert!(!worker.is_alive());

        drop(worker);
        guest.join().expect("join fake guest").expect("fake guest");
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn vsock_connect_performs_the_connect_handshake() {
        let dir = temp_dir("handshake");
        let socket = dir.join("guest.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let (sender, receiver) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buffer = [0u8; 32];
            let read = stream.read(&mut buffer).expect("read CONNECT");
            let line = String::from_utf8_lossy(&buffer[..read]).into_owned();
            sender.send(line).expect("send CONNECT");
            stream.write_all(b"OK 5252\n").expect("write ACK");
        });

        let stream = vsock_connect_to_guest(&socket, ECHO_SERVER_PORT).expect("connect");
        drop(stream);
        server.join().expect("join fake guest");
        assert_eq!(
            receiver.try_recv().expect("CONNECT was sent"),
            "CONNECT 5252\n"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn vsock_connect_rejects_a_bad_ack() {
        let dir = temp_dir("bad-ack");
        let socket = dir.join("guest.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buffer = [0u8; 32];
            stream.read(&mut buffer).expect("read CONNECT");
            stream.write_all(b"ERR 1\n").expect("write ACK");
        });

        let error =
            vsock_connect_to_guest(&socket, ECHO_SERVER_PORT).expect_err("bad ACK must fail");
        server.join().expect("join fake guest");
        assert!(format!("{error:#}").contains("ERR 1"), "{error:#}");
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn guest_commands_match_python_output() {
        let worker_cmd = guest_worker_command("/tmp/vsock/test.blob", "deadbeef");
        assert_eq!(
            worker_cmd,
            "hash=$(cat /tmp/vsock/test.blob | /tmp/vsock_helper echo 2 5252 \
| md5sum | cut -f1 -d\\ ) && [[ \"$hash\" = \"deadbeef\" ]]"
        );

        let cmd = guest_workers_command(2, "true");
        assert_eq!(
            cmd,
            "workers=\"\";for i in $(seq 1 2); do  (true)&   workers=\"$workers $!\";done;\
for w in $workers; do wait $w || (wait; exit 1); done"
        );
    }
}
