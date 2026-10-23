// SPDX-License-Identifier: Apache-2.0
//! Minimal vhost-user virtio-fs frontend: one hiprio and one request queue, no DAX.
use std::sync::Arc;
use std::time::Instant;
use vmm_sys_util::epoll::EventSet;

use event_manager::{EventOps, Events, MutEventSubscriber};
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vmm_sys_util::eventfd::EventFd;

use super::ActivateError;
use super::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use super::queue::Queue;
use super::transport::VirtioInterrupt;
use super::vhost_user::VhostUserHandle;
use crate::impl_device_type;
use crate::logger::{error, info};
use crate::vmm_config::fs::{FsConfig, FsError};
use crate::vstate::memory::GuestMemoryMmap;

const PROTOCOL: u64 = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
const VERSION_1: u64 = 1 << 32;

/// File system requests are serviced by the external Rust virtiofsd process.
#[derive(Debug)]
pub struct Fs {
    /// Validated boot configuration.
    pub config: FsConfig,
    handle: VhostUserHandle,
    features: u64,
    acked: u64,
    bytes: [u8; 40],
    queues: Vec<Queue>,
    events: [EventFd; 2],
    state: DeviceState,
    exit_evt: EventFd,
    failed: bool,
}

impl Fs {
    /// Connect and negotiate the minimal supported backend features.
    pub fn new(config: FsConfig, exit_evt: EventFd) -> Result<Self, FsError> {
        config.validate()?;
        let start = Instant::now();
        let mut handle = VhostUserHandle::new(&config.socket, 2).inspect_err(|err| {
            error!(
                "virtio-fs id={} stage=connect result=error elapsed_us={} cause={err}",
                config.fs_id,
                start.elapsed().as_micros()
            );
        })?;
        let (features, _) = handle.negotiate_features(
            VERSION_1 | PROTOCOL | (1 << 28) | (1 << 29),
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::REPLY_ACK,
        )?;
        if features & (VERSION_1 | PROTOCOL) != VERSION_1 | PROTOCOL {
            return Err(FsError::Invalid(
                "backend requires VERSION_1 and PROTOCOL_FEATURES".into(),
            ));
        }
        let mut bytes = [0; 40];
        bytes[..config.tag.len()].copy_from_slice(config.tag.as_bytes());
        bytes[36..].copy_from_slice(&1u32.to_le_bytes());
        info!(
            "virtio-fs id={} stage=connect result=ok elapsed_us={}",
            config.fs_id,
            start.elapsed().as_micros()
        );
        Ok(Self {
            config,
            handle,
            features: features & !PROTOCOL,
            acked: 0,
            bytes,
            queues: vec![Queue::new(256), Queue::new(256)],
            events: [
                EventFd::new(libc::EFD_NONBLOCK)?,
                EventFd::new(libc::EFD_NONBLOCK)?,
            ],
            state: DeviceState::Inactive,
            exit_evt,
            failed: false,
        })
    }
}

impl MutEventSubscriber for Fs {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        if event
            .event_set()
            .intersects(EventSet::HANG_UP | EventSet::READ_HANG_UP | EventSet::ERROR)
        {
            error!(
                "virtio-fs id={} stage=backend result=error category=disconnected action=stop_vm",
                self.id()
            );
            let _ = ops.remove(Events::new(&self.handle.vu, EventSet::READ_HANG_UP));
            self.failed = true;
            self.exit_evt.write(1).expect("cannot signal VM shutdown");
        }
    }
    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.handle.vu, EventSet::READ_HANG_UP)) {
            error!(
                "virtio-fs id={} stage=monitor result=error cause={err} action=stop_vm",
                self.id()
            );
            self.failed = true;
            self.exit_evt.write(1).expect("cannot signal VM shutdown");
        }
    }
}

impl VirtioDevice for Fs {
    impl_device_type!(VirtioDeviceType::Fs);
    fn id(&self) -> &str {
        &self.config.fs_id
    }
    fn avail_features(&self) -> u64 {
        self.features
    }
    fn acked_features(&self) -> u64 {
        self.acked
    }
    fn set_acked_features(&mut self, value: u64) {
        self.acked = value;
    }
    fn queues(&self) -> &[Queue] {
        &self.queues
    }
    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }
    fn queue_events(&self) -> &[EventFd] {
        &self.events
    }
    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.state
            .active_state()
            .expect("inactive virtio-fs")
            .interrupt
            .as_ref()
    }
    fn config_as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn write_config(&mut self, _: u64, _: &[u8]) {}
    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        let start = Instant::now();
        for queue in &mut self.queues {
            queue
                .initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }
        self.handle
            .set_features(self.acked | PROTOCOL)
            .and_then(|()| {
                self.handle.setup_backend(
                    &mem,
                    &[
                        (0, &self.queues[0], &self.events[0]),
                        (1, &self.queues[1], &self.events[1]),
                    ],
                    interrupt.clone(),
                )
            })
            .map_err(|err| {
                error!(
                    "virtio-fs id={} stage=activate result=error elapsed_us={} cause={err}",
                    self.id(),
                    start.elapsed().as_micros()
                );
                ActivateError::VhostUser(err)
            })?;
        self.state = DeviceState::Activated(ActiveState { mem, interrupt });
        info!(
            "virtio-fs id={} stage=activate result=ok elapsed_us={}",
            self.id(),
            start.elapsed().as_micros()
        );
        Ok(())
    }
    fn is_failed(&self) -> bool {
        self.failed
    }
    fn is_activated(&self) -> bool {
        self.state.is_activated()
    }
    fn deactivate(&mut self) {
        self.state = DeviceState::Inactive;
    }
    fn _reset(&mut self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use super::*;
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt};
    use crate::devices::virtio::vhost_user::tests::create_mem;
    use crate::vstate::memory::GuestAddress;
    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    type BackendCalls = thread::JoinHandle<Vec<(u32, Vec<u8>)>>;

    fn mock_backend(listener: UnixListener, features: u64) -> BackendCalls {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut calls = Vec::new();
            loop {
                let mut header = [0u8; 12];
                if stream.read_exact(&mut header).is_err() {
                    break;
                }
                let request = u32::from_le_bytes(header[..4].try_into().unwrap());
                let flags = u32::from_le_bytes(header[4..8].try_into().unwrap());
                let size = u32::from_le_bytes(header[8..].try_into().unwrap());
                let mut payload = vec![0; size as usize];
                stream.read_exact(&mut payload).unwrap();
                calls.push((request, payload));
                let reply = match request {
                    1 => Some(features),
                    15 => Some(
                        (VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::REPLY_ACK)
                            .bits(),
                    ),
                    _ if flags & 8 != 0 => Some(0),
                    _ => None,
                };
                if let Some(value) = reply {
                    header[4..8].copy_from_slice(&5u32.to_le_bytes());
                    header[8..].copy_from_slice(&8u32.to_le_bytes());
                    stream.write_all(&header).unwrap();
                    stream.write_all(&value.to_le_bytes()).unwrap();
                }
            }
            calls
        })
    }

    fn backend(features: u64) -> (TempDir, FsConfig, BackendCalls) {
        let dir = TempDir::new().unwrap();
        let path = dir.as_path().join("fs.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let config = FsConfig {
            fs_id: "project".into(),
            tag: "workspace".into(),
            socket: path.to_str().unwrap().into(),
        };
        (dir, config, mock_backend(listener, features))
    }

    #[test]
    fn test_fs_activation_config_and_two_queues() {
        let (_dir, config, backend) = backend(VERSION_1 | PROTOCOL | (1 << 28) | (1 << 29));
        let mut fs = Fs::new(config, EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap();
        assert_eq!(fs.device_type(), VirtioDeviceType::Fs);
        assert_eq!(&fs.bytes[..9], b"workspace");
        assert_eq!(&fs.bytes[36..], &1u32.to_le_bytes());
        assert_eq!(fs.avail_features() & PROTOCOL, 0);
        assert_eq!(fs.queues().len(), 2);
        let file = TempFile::new().unwrap().into_file();
        file.set_len(0x10000).unwrap();
        let mem = create_mem(file, &[(GuestAddress(0), 0x10000)]);
        fs.queues[0] = VirtQueue::new(GuestAddress(0), &mem, 16).create_queue();
        fs.queues[1] = VirtQueue::new(GuestAddress(0x4000), &mem, 16).create_queue();
        fs.set_acked_features(fs.avail_features());
        fs.activate(mem, default_interrupt()).unwrap();
        assert!(fs.is_activated());
        drop(fs);
        let calls = backend.join().unwrap();
        assert_eq!(calls.iter().filter(|(req, _)| *req == 5).count(), 1); // Memory table.
        let enabled: Vec<_> = calls
            .iter()
            .filter(|(req, _)| *req == 18)
            .map(|(_, body)| u32::from_le_bytes(body[..4].try_into().unwrap()))
            .collect();
        assert_eq!(enabled, vec![0, 1]);
    }

    #[test]
    fn test_fs_reject_legacy_backend() {
        let (_dir, config, backend) = backend(0);
        Fs::new(config, EventFd::new(0).unwrap()).unwrap_err();
        backend.join().unwrap();
    }
}
