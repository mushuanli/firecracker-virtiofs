// SPDX-License-Identifier: Apache-2.0
//! Configuration for a single-directory, non-DAX virtio-fs export.
use serde::{Deserialize, Serialize};

/// A trusted vhost-user socket; directory authorization belongs to its supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsConfig {
    /// Device identifier.
    pub fs_id: String,
    /// Guest mount tag, at most 36 ASCII bytes.
    pub tag: String,
    /// Unix socket visible inside the VMM jail.
    pub socket: String,
}

/// Configuration or backend initialization failure.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum FsError {
    /// Invalid virtio-fs configuration: {0}
    Invalid(String),
    /// virtio-fs backend: {0}
    Backend(#[from] crate::devices::virtio::vhost_user::VhostUserError),
    /// virtio-fs eventfd: {0}
    EventFd(#[from] std::io::Error),
}

impl FsConfig {
    /// Validate before connecting to any backend.
    pub fn validate(&self) -> Result<(), FsError> {
        let safe = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        };
        if !safe(&self.fs_id) || !safe(&self.tag) || self.tag.len() > 36 {
            return Err(FsError::Invalid("id and tag must be nonempty ASCII alphanumeric, '_' or '-'; tag maximum is 36 bytes".into()));
        }
        if self.socket.is_empty() || self.socket.as_bytes().contains(&0) {
            return Err(FsError::Invalid(
                "socket must be a nonempty Unix socket path".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::VmResources;

    #[test]
    fn test_fs_config_validation_and_single_export() {
        let config = FsConfig {
            fs_id: "project".into(),
            tag: "workspace".into(),
            socket: "/fs.sock".into(),
        };
        let mut resources = VmResources::default();
        resources.set_fs(config.clone()).unwrap();
        resources.set_fs(config.clone()).unwrap();
        assert_eq!(resources.fs.len(), 1);
        let mut invalid = config.clone();
        invalid.fs_id = "other".into();
        resources.set_fs(invalid).unwrap_err();
        for tag in [
            "".into(),
            "a".repeat(37),
            "has space".into(),
            "../escape".into(),
            "nul\0".into(),
        ] {
            let mut invalid = config.clone();
            invalid.tag = tag;
            invalid.validate().unwrap_err();
        }
        let mut max = config;
        max.tag = "a".repeat(36);
        max.validate().unwrap();
    }
}
