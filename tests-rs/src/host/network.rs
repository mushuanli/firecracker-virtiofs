// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side network helpers, ported from `tests/host_tools/network.py` and
//! `tests/host_tools/udp_offload.py`.
//!
//! The python-side host helpers (`SSHConnection`, `mac_from_ip`, `get_guest_net_if_name`,
//! `random_str`, `Tap`, `NetIfaceConfig`, `NetNs`) are already ported into [`crate::network`] and
//! are re-exported here so call sites can keep python's `host_tools.network` layout.
//!
//! New in this module: [`UdpEchoServer`], a host-side UDP echo peer, and
//! [`send_udp_with_offload`], the port of `udp_offload.py`'s message sender. Python drives the
//! offload check against a `socat UDP4-LISTEN` peer inside the guest
//! (`integration_tests/functional/test_net.py::test_tap_offload`); the echo server lets host-only
//! tests exercise the same path.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

/// Protocol number of UDP, used as the `setsockopt` level for UDP options (`SOL_UDP`).
pub const SOL_UDP: i32 = 17;
/// `UDP_SEGMENT` socket option, which enables UDP segmentation offload.
pub const UDP_SEGMENT: i32 = 103;
/// Segment size `udp_offload.py` configures (`OPTVAL`).
pub const UDP_SEGMENT_SIZE: usize = 1400;
/// Payload `udp_offload.py` sends (`MESSAGE`).
pub const UDP_OFFLOAD_MESSAGE: &[u8] = b"x";

pub use crate::network::{
    get_guest_net_if_name, mac_from_ip, random_str, NetIfaceConfig, NetNs, SshConnection, Tap,
};

/// Sends one UDP datagram with segmentation offload enabled (python `udp_offload.py`).
pub fn send_udp_with_offload(
    ip: &str,
    port: u16,
    message: &[u8],
    segment_size: usize,
) -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).context("creating the offload UDP socket")?;
    set_udp_segment(&socket, segment_size)?;
    socket
        .send_to(message, (ip, port))
        .with_context(|| format!("sending an offloaded UDP datagram to {ip}:{port}"))?;
    Ok(())
}

/// Enables `UDP_SEGMENT` on `socket` with `segment_size` bytes.
pub fn set_udp_segment(socket: &UdpSocket, segment_size: usize) -> Result<()> {
    let Ok(optval) = i32::try_from(segment_size) else {
        bail!("segment size {segment_size} does not fit in a c_int");
    };
    // SAFETY: `socket` owns a live fd and `optval` is a `c_int` of the advertised length.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_UDP,
            UDP_SEGMENT,
            &optval as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        return Err(err).context("setsockopt(SOL_UDP, UDP_SEGMENT)");
    }
    Ok(())
}

/// Background UDP echo server used as a stand-in for an in-guest UDP listener.
pub struct UdpEchoServer {
    socket: Arc<UdpSocket>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    should_stop: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl UdpEchoServer {
    /// How long a blocked `recv_from` waits before re-checking the stop flag.
    pub const READ_TIMEOUT: Duration = Duration::from_millis(100);
    /// Largest datagram the echo server accepts.
    pub const MAX_DATAGRAM: usize = 65535;

    /// Binds to `addr` (e.g. `127.0.0.1:0`) and starts echoing in the background.
    pub fn bind(addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(addr)
            .with_context(|| format!("binding the UDP echo server to {addr}"))?;
        Self::from_socket(socket)
    }

    /// Binds to an already resolved address and starts echoing in the background.
    pub fn bind_addr(addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(addr)
            .with_context(|| format!("binding the UDP echo server to {addr}"))?;
        Self::from_socket(socket)
    }

    /// Wraps a bound socket and starts the echo thread.
    pub fn from_socket(socket: UdpSocket) -> Result<Self> {
        socket
            .set_read_timeout(Some(Self::READ_TIMEOUT))
            .context("setting the UDP echo server read timeout")?;
        let server = Self {
            socket: Arc::new(socket),
            received: Arc::new(Mutex::new(Vec::new())),
            should_stop: Arc::new(AtomicBool::new(false)),
            handle: Mutex::new(None),
        };
        let worker = Arc::clone(&server.socket);
        let received = Arc::clone(&server.received);
        let should_stop = Arc::clone(&server.should_stop);
        let handle = thread::spawn(move || serve_udp_echo(&worker, &received, &should_stop));
        *server
            .handle
            .lock()
            .map_err(|_| anyhow!("UDP echo server handle mutex is poisoned"))? = Some(handle);
        Ok(server)
    }

    /// Returns the local address the server listens on.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .context("reading the UDP echo server address")
    }

    /// Returns every datagram received so far, in arrival order.
    pub fn received(&self) -> Vec<Vec<u8>> {
        self.received
            .lock()
            .map(|received| received.clone())
            .unwrap_or_default()
    }

    /// Returns how many datagrams have been received so far.
    pub fn received_count(&self) -> usize {
        self.received
            .lock()
            .map(|received| received.len())
            .unwrap_or_default()
    }

    /// Returns `true` while the echo thread is alive.
    pub fn is_alive(&self) -> bool {
        match self.handle.lock() {
            Ok(handle) => handle.as_ref().is_some_and(|h| !h.is_finished()),
            Err(_) => false,
        }
    }

    /// Stops the echo thread and waits for it to exit.
    pub fn stop(&self) -> Result<()> {
        self.should_stop.store(true, Ordering::SeqCst);
        let handle = self
            .handle
            .lock()
            .map_err(|_| anyhow!("UDP echo server handle mutex is poisoned"))?
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
        Ok(())
    }
}

impl Drop for UdpEchoServer {
    /// Stops the echo thread when the server goes out of scope.
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Echo loop body: records each datagram and sends it back to the sender.
fn serve_udp_echo(socket: &UdpSocket, received: &Mutex<Vec<Vec<u8>>>, should_stop: &AtomicBool) {
    let mut buf = vec![0u8; UdpEchoServer::MAX_DATAGRAM];
    while !should_stop.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                let payload = buf[..len].to_vec();
                if let Ok(mut received) = received.lock() {
                    received.push(payload.clone());
                }
                let _ = socket.send_to(&payload, peer);
            }
            // Read timeout: loop around so the stop flag is re-checked.
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_size_rejects_out_of_range_values() {
        let socket = match UdpSocket::bind(("127.0.0.1", 0)) {
            Ok(socket) => socket,
            // No loopback support in this sandbox: nothing to assert.
            Err(_) => return,
        };
        let err = set_udp_segment(&socket, usize::MAX).expect_err("must fail");
        assert!(err.to_string().contains("does not fit in a c_int"), "{err}");
        set_udp_segment(&socket, UDP_SEGMENT_SIZE).expect("1400 byte segments are accepted");
    }

    #[test]
    fn echo_server_round_trips_a_datagram() {
        let server = match UdpEchoServer::bind("127.0.0.1:0") {
            Ok(server) => server,
            Err(_) => return,
        };
        let addr = server.local_addr().expect("local addr");
        let client = UdpSocket::bind(("127.0.0.1", 0)).expect("client socket");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        client.send_to(b"ping", addr).expect("send datagram");

        let mut buf = [0u8; 16];
        let (len, _) = client.recv_from(&mut buf).expect("echo reply");
        assert_eq!(&buf[..len], b"ping");
        assert_eq!(server.received(), vec![b"ping".to_vec()]);
        assert_eq!(server.received_count(), 1);
        server.stop().expect("stop server");
        assert!(!server.is_alive());
    }

    #[test]
    fn offloaded_datagram_reaches_a_plain_udp_peer() {
        let peer = match UdpSocket::bind("127.0.0.1:0") {
            Ok(peer) => peer,
            Err(_) => return,
        };
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let addr = peer.local_addr().expect("local addr");
        if set_udp_segment(
            &UdpSocket::bind(("127.0.0.1", 0)).expect("probe socket"),
            UDP_SEGMENT_SIZE,
        )
        .is_err()
        {
            // Kernels without UDP_SEGMENT support: nothing to assert.
            return;
        }
        send_udp_with_offload(
            "127.0.0.1",
            addr.port(),
            UDP_OFFLOAD_MESSAGE,
            UDP_SEGMENT_SIZE,
        )
        .expect("send offloaded datagram");

        let mut buf = [0u8; 16];
        let (len, _) = peer.recv_from(&mut buf).expect("received datagram");
        assert_eq!(&buf[..len], UDP_OFFLOAD_MESSAGE);
    }
}
