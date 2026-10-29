// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A simple HTTP client for the Firecracker API, ported from
//! `tests/framework/http_api.py`.
//!
//! The python client stacks `requests` on `requests_unixsocket`. This port
//! speaks HTTP/1.1 over `std::os::unix::net::UnixStream` directly: the
//! Firecracker API server only serves that protocol, and a hand-rolled client
//! keeps the test harness dependency-free while still exposing the response
//! duration that the API-timing assertions need.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::swagger::SwaggerValidator;

/// An HTTP response from the Firecracker API.
#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub status: u16,
    pub body: String,
    pub duration: Duration,
}

impl ApiResponse {
    /// Parses the body as JSON.
    pub fn json(&self) -> Result<Value> {
        serde_json::from_str(&self.body)
            .with_context(|| format!("parsing {} response body: {}", self.status, self.body))
    }

    /// `fault_message`, falling back to `error`, falling back to the raw body.
    pub fn fault_message(&self) -> String {
        match self.json() {
            Ok(json) => json
                .get("fault_message")
                .or_else(|| json.get("error"))
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| self.body.clone()),
            Err(_) => self.body.clone(),
        }
    }
}

/// One recorded API call, used by the API-timing assertions.
#[derive(Debug, Clone)]
pub struct ApiCallRecord {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration: Duration,
}

/// Shared API client state.
pub struct ApiInner {
    pub socket: PathBuf,
    pub validate: bool,
    /// Called with `(method, path, error)` when a request fails at the
    /// transport level, mirroring python's `on_error` hook.
    pub on_error: Option<Box<dyn Fn(&str, &str, &str) + Send + Sync>>,
    pub calls: Mutex<Vec<ApiCallRecord>>,
}

impl std::fmt::Debug for ApiInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiInner")
            .field("socket", &self.socket)
            .field("validate", &self.validate)
            .field("calls", &self.calls.lock().map(|c| c.len()).unwrap_or(0))
            .finish()
    }
}

/// An abstraction over a REST path.
#[derive(Clone, Debug)]
pub struct Resource {
    inner: Arc<ApiInner>,
    resource: String,
    id_field: Option<&'static str>,
}

impl Resource {
    /// GET the resource, asserting a 200 and validating the response body.
    pub fn get(&self) -> Result<ApiResponse> {
        let response = self.request("GET", &self.resource, None)?;
        if response.status != 200 {
            bail!(
                "GET {}: unexpected status {}",
                self.resource,
                response.status
            );
        }
        if let Some(validator) = self.validator() {
            let body = response.json().unwrap_or(Value::Null);
            validator
                .validate_response("GET", &self.resource, 200, &body)
                .with_context(|| format!("response validation failed for GET {}", self.resource))?;
        }
        Ok(response)
    }

    /// DELETE a child resource identified by `resource_id`.
    pub fn delete(&self, resource_id: &str) -> Result<ApiResponse> {
        let path = format!("{}/{resource_id}", self.resource);
        let response = self.request("DELETE", &path, None)?;
        if response.status != 204 {
            let message = response.fault_message();
            bail!("DELETE {path}: {message}");
        }
        Ok(response)
    }

    /// PUT the resource, optionally appending the configured id field.
    pub fn put(&self, mut body: Value) -> Result<ApiResponse> {
        let path = self.path_with_id(&mut body)?;
        self.write("PUT", &path, Some(body))
    }

    /// PATCH the resource, optionally appending the configured id field.
    pub fn patch(&self, mut body: Value) -> Result<ApiResponse> {
        let path = self.path_with_id(&mut body)?;
        self.write("PATCH", &path, Some(body))
    }

    fn path_with_id(&self, body: &mut Value) -> Result<String> {
        match self.id_field {
            None => Ok(self.resource.clone()),
            Some(field) => {
                let id = body
                    .get(field)
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| anyhow!("{}: missing id field {field}", self.resource))?
                    .to_string();
                Ok(format!("{}/{id}", self.resource))
            }
        }
    }

    fn write(&self, method: &str, path: &str, body: Option<Value>) -> Result<ApiResponse> {
        let response = self.request(method, path, body.clone())?;
        if response.status != 204 {
            let message = response.fault_message();
            bail!("{method} {path}: {message}");
        }
        if let Some(validator) = self.validator() {
            if let Some(body) = &body {
                validator
                    .validate_request(method, path, body)
                    .with_context(|| format!("request validation failed for {method} {path}"))?;
            }
            if response.status == 200 {
                let parsed = response.json().unwrap_or(Value::Null);
                validator
                    .validate_response(method, path, 200, &parsed)
                    .with_context(|| format!("response validation failed for {method} {path}"))?;
            }
        }
        Ok(response)
    }

    /// Makes an arbitrary request against the resource path.
    pub fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<ApiResponse> {
        self.inner.request(method, path, body)
    }

    fn validator(&self) -> Option<&'static SwaggerValidator> {
        if self.inner.validate {
            SwaggerValidator::shared()
        } else {
            None
        }
    }
}

impl ApiInner {
    /// The socket path spelled as a pseudo-URL prefix, kept for parity with
    /// python's `self.endpoint`.
    fn socket_prefix(&self) -> String {
        format!("unix://{}:", self.socket.display())
    }

    fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<ApiResponse> {
        let started = Instant::now();
        let result = send_request(&self.socket, method, path, body.as_ref());
        let duration = started.elapsed();
        match result {
            Ok(mut response) => {
                response.duration = duration;
                if let Ok(mut calls) = self.calls.lock() {
                    calls.push(ApiCallRecord {
                        method: method.to_string(),
                        path: path.to_string(),
                        status: response.status,
                        duration,
                    });
                }
                Ok(response)
            }
            Err(err) => {
                if let Some(callback) = &self.on_error {
                    callback(method, path, &err.to_string());
                }
                Err(err)
            }
        }
    }
}

/// The Firecracker API client, mirroring `http_api.Api`.
#[derive(Clone, Debug)]
pub struct Api {
    pub inner: Arc<ApiInner>,
    pub describe: Resource,
    pub vm: Resource,
    pub vm_config: Resource,
    pub actions: Resource,
    pub boot: Resource,
    pub drive: Resource,
    pub version: Resource,
    pub logger: Resource,
    pub machine_config: Resource,
    pub metrics: Resource,
    pub network: Resource,
    pub mmds: Resource,
    pub mmds_config: Resource,
    pub balloon: Resource,
    pub balloon_stats: Resource,
    pub balloon_hinting_start: Resource,
    pub balloon_hinting_status: Resource,
    pub balloon_hinting_stop: Resource,
    pub vsock: Resource,
    pub snapshot_create: Resource,
    pub snapshot_load: Resource,
    pub cpu_config: Resource,
    pub entropy: Resource,
    pub pmem: Resource,
    pub serial: Resource,
    pub memory_hotplug: Resource,
    pub fs: Resource,
}

impl Api {
    /// Builds a client for the API socket at `api_usocket_full_name`.
    pub fn new(api_usocket_full_name: impl Into<PathBuf>, validate: bool) -> Self {
        Self::with_error_callback(api_usocket_full_name, validate, None)
    }

    /// Builds a client with a transport error callback.
    pub fn with_error_callback(
        api_usocket_full_name: impl Into<PathBuf>,
        validate: bool,
        on_error: Option<Box<dyn Fn(&str, &str, &str) + Send + Sync>>,
    ) -> Self {
        let inner = Arc::new(ApiInner {
            socket: api_usocket_full_name.into(),
            validate,
            on_error,
            calls: Mutex::new(Vec::new()),
        });
        let resource = |path: &str, id_field: Option<&'static str>| Resource {
            inner: inner.clone(),
            resource: path.to_string(),
            id_field,
        };

        Self {
            describe: resource("/", None),
            vm: resource("/vm", None),
            vm_config: resource("/vm/config", None),
            actions: resource("/actions", None),
            boot: resource("/boot-source", None),
            drive: resource("/drives", Some("drive_id")),
            version: resource("/version", None),
            logger: resource("/logger", None),
            machine_config: resource("/machine-config", None),
            metrics: resource("/metrics", None),
            network: resource("/network-interfaces", Some("iface_id")),
            mmds: resource("/mmds", None),
            mmds_config: resource("/mmds/config", None),
            balloon: resource("/balloon", None),
            balloon_stats: resource("/balloon/statistics", None),
            balloon_hinting_start: resource("/balloon/hinting/start", None),
            balloon_hinting_status: resource("/balloon/hinting/status", None),
            balloon_hinting_stop: resource("/balloon/hinting/stop", None),
            vsock: resource("/vsock", None),
            snapshot_create: resource("/snapshot/create", None),
            snapshot_load: resource("/snapshot/load", None),
            cpu_config: resource("/cpu-config", None),
            entropy: resource("/entropy", None),
            pmem: resource("/pmem", Some("id")),
            serial: resource("/serial", None),
            memory_hotplug: resource("/hotplug/memory", None),
            fs: resource("/fs", Some("fs_id")),
            inner,
        }
    }

    /// Socket path this client talks to.
    pub fn socket(&self) -> &Path {
        &self.inner.socket
    }

    /// Pseudo-URL form of the API endpoint (`unix://<socket>:`), kept for
    /// parity with python's `Api.endpoint`.
    pub fn endpoint(&self) -> String {
        self.inner.socket_prefix()
    }

    /// Waits until the API socket accepts connections.
    pub fn wait_for_socket(&self, timeout: Duration) -> Result<()> {
        crate::utils::retry_for(timeout, Duration::from_millis(10), || {
            UnixStream::connect(&self.inner.socket)
                .map(|_| ())
                .with_context(|| format!("connecting to {}", self.inner.socket.display()))
        })
    }

    /// Firecracker version reported by `GET /version`.
    pub fn firecracker_version(&self) -> Result<String> {
        let body = self.version.get()?.json()?;
        body.get("firecracker_version")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("GET /version returned {}", body))
    }

    /// All API calls recorded by this client, in order.
    pub fn calls(&self) -> Vec<ApiCallRecord> {
        self.inner
            .calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
}

/// Builds a JSON object dropping `None` values, matching python's
/// `{k: v for k, v in kwargs.items() if v is not None}`.
pub fn json_body(pairs: Vec<(&str, Option<Value>)>) -> Value {
    let mut map = serde_json::Map::new();
    for (key, value) in pairs {
        if let Some(value) = value {
            map.insert(key.to_string(), value);
        }
    }
    Value::Object(map)
}

fn send_request(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<ApiResponse> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to {}", socket.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let payload = match body {
        Some(value) => serde_json::to_vec(value)?,
        None => Vec::new(),
    };
    let mut request = format!("{method} {path} HTTP/1.1\r\n");
    request.push_str("Host: localhost\r\n");
    request.push_str("Accept: application/json\r\n");
    request.push_str("Accept-Encoding: identity\r\n");
    if !payload.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
    }
    request.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    request.push_str("Connection: close\r\n\r\n");

    stream.write_all(request.as_bytes())?;
    if !payload.is_empty() {
        stream.write_all(&payload)?;
    }
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let raw = String::from_utf8_lossy(&raw).into_owned();
    parse_response(&raw)
}

fn parse_response(raw: &str) -> Result<ApiResponse> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response: {raw}"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| anyhow!("empty HTTP response"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("malformed status line: {status_line}"))?
        .parse::<u16>()
        .with_context(|| format!("malformed status line: {status_line}"))?;

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_lowercase(), value.trim().to_string());
        }
    }

    let body = if headers
        .get("transfer-encoding")
        .map(|value| value.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
    {
        decode_chunked(body)?
    } else if let Some(length) = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    {
        // The server may not close the connection, so honour Content-Length.
        let bytes = body.as_bytes();
        let end = length.min(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    } else {
        body.to_string()
    };

    Ok(ApiResponse {
        status,
        body,
        duration: Duration::ZERO,
    })
}

fn decode_chunked(body: &str) -> Result<String> {
    let mut decoded = Vec::new();
    let mut rest = body;
    loop {
        let (size_line, after) = rest
            .split_once("\r\n")
            .ok_or_else(|| anyhow!("malformed chunked body"))?;
        let size = usize::from_str_radix(size_line.trim(), 16)
            .with_context(|| format!("malformed chunk size {size_line:?}"))?;
        if size == 0 {
            return Ok(String::from_utf8_lossy(&decoded).into_owned());
        }
        let chunk = after
            .as_bytes()
            .get(..size)
            .ok_or_else(|| anyhow!("truncated chunk"))?;
        decoded.extend_from_slice(chunk);
        rest = after
            .get(size + 2..)
            .ok_or_else(|| anyhow!("truncated chunk terminator"))?;
    }
}

/// Builds a JSON object helper used by the microVM configuration layer.
pub fn obj(pairs: Vec<(&str, Option<Value>)>) -> Value {
    json_body(pairs)
}

/// Convenience wrapper turning a `serde_json::Value` into `Option`.
pub fn some(value: Value) -> Option<Value> {
    Some(value)
}

/// Convenience wrapper for `Option<&str>` values in request bodies.
pub fn opt_str(value: Option<&str>) -> Option<Value> {
    value.map(|v| json!(v))
}

/// Serialises a probe response for logging.
pub fn describe_response(response: &ApiResponse) -> String {
    format!("{} {}B", response.status, response.body.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_response() {
        let raw = "HTTP/1.1 204 No Content\r\nServer: Firecracker\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 204);
        assert_eq!(response.body, "");
    }

    #[test]
    fn parses_json_body_with_content_length() {
        let body = "{\"firecracker_version\":\"1.10.0\"}";
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = parse_response(&raw).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            response.json().unwrap()["firecracker_version"],
            json!("1.10.0")
        );
    }

    #[test]
    fn parses_chunked_body() {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.json().unwrap(), json!({"a": 1}));
    }

    #[test]
    fn fault_message_prefers_fault_message() {
        let response = ApiResponse {
            status: 400,
            body: r#"{"fault_message":"bad","error":"also bad"}"#.to_string(),
            duration: Duration::ZERO,
        };
        assert_eq!(response.fault_message(), "bad");
        let response = ApiResponse {
            status: 400,
            body: r#"{"error":"only"}"#.to_string(),
            duration: Duration::ZERO,
        };
        assert_eq!(response.fault_message(), "only");
        let response = ApiResponse {
            status: 400,
            body: "plain".to_string(),
            duration: Duration::ZERO,
        };
        assert_eq!(response.fault_message(), "plain");
    }

    #[test]
    fn json_body_drops_nones() {
        let body = json_body(vec![
            ("vcpu_count", Some(json!(2))),
            ("smt", None),
            ("mem_size_mib", Some(json!(256))),
        ]);
        assert_eq!(body, json!({"vcpu_count": 2, "mem_size_mib": 256}));
    }

    #[test]
    fn resources_are_wired_to_the_same_socket() {
        let api = Api::new("/tmp/fc.socket", false);
        assert_eq!(api.socket(), Path::new("/tmp/fc.socket"));
        assert_eq!(api.drive.resource, "/drives");
        assert_eq!(api.drive.id_field, Some("drive_id"));
        assert_eq!(api.memory_hotplug.resource, "/hotplug/memory");
    }
}
