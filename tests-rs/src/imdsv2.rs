// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A minimal IMDSv2 client, ported from `tests/framework/utils_imdsv2.py`.
//!
//! Python leans on `requests`; the port speaks plain HTTP/1.1 over
//! `std::net::TcpStream` because the crate carries no HTTP client dependency.
//! Request construction is kept in [`Imdsv2Client::token_request`] /
//! [`Imdsv2Client::metadata_request`] and
//! [`http_request_text`] so the wire format is unit-testable offline.
//!
//! For the client to work from inside a container, the instance needs a hop
//! limit of at least 2 (`ec2:MetadataHttpPutResponseHopLimit`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};

/// Header carrying the token lifetime, in seconds.
pub const IMDSV2_HDR_TOKEN_TTL: &str = "X-aws-ec2-metadata-token-ttl-seconds";

/// Header carrying the session token on metadata requests.
pub const IMDSV2_HDR_TOKEN: &str = "X-aws-ec2-metadata-token";

/// Default IMDS endpoint.
pub const DEFAULT_ENDPOINT: &str = "http://169.254.169.254";

/// Default API version path segment.
pub const DEFAULT_VERSION: &str = "latest";

/// Default token lifetime requested from IMDSv2 (six hours).
pub const DEFAULT_TTL_SECS: u64 = 21600;

/// Timeout applied to every IMDS request, matching `timeout=2`.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// A raw HTTP response: status code plus decoded body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Numeric status code, e.g. `200`.
    pub status: u16,
    /// Response body decoded as UTF-8 (lossily, like `requests.text`).
    pub body: String,
}

/// Seconds since the unix epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_secs())
        .unwrap_or(0)
}

/// Splits an `http://host[:port]/path` URL into `(host, port, path)`.
pub fn parse_http_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("only plain http URLs are supported: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        bail!("missing host in {url}");
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().with_context(|| format!("bad port in {url}"))?;
            Ok((host.to_string(), port, path))
        }
        None => Ok((authority.to_string(), 80, path)),
    }
}

/// Renders the HTTP/1.1 request head for `method` on `host:path`.
pub fn http_request_text(
    method: &str,
    host: &str,
    path: &str,
    headers: &[(String, String)],
) -> String {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    request
}

/// Performs one HTTP request and returns the status code and body.
pub fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    timeout: Duration,
) -> Result<HttpResponse> {
    let (host, port, path) = parse_http_url(url)?;
    let mut stream = match host.parse::<IpAddr>() {
        Ok(ip) => TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout)
            .with_context(|| format!("connecting to {host}:{port}"))?,
        Err(_) => TcpStream::connect((host.as_str(), port))
            .with_context(|| format!("connecting to {host}:{port}"))?,
    };
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let request = http_request_text(method, &host, &path, headers);
    stream
        .write_all(request.as_bytes())
        .with_context(|| format!("writing request for {url}"))?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .with_context(|| format!("reading status line for {url}"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| anyhow!("malformed status line for {url}: {status_line:?}"))?;

    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
            }
        }
    }

    let mut body = Vec::new();
    match content_length {
        Some(length) => {
            reader
                .take(length as u64)
                .read_to_end(&mut body)
                .with_context(|| format!("reading body for {url}"))?;
        }
        None => {
            reader
                .read_to_end(&mut body)
                .with_context(|| format!("reading body for {url}"))?;
        }
    }

    Ok(HttpResponse {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// A simple IMDSv2 client caching its session token.
#[derive(Debug, Clone)]
pub struct Imdsv2Client {
    endpoint: String,
    version: String,
    ttl: u64,
    token: Option<String>,
    token_expiry_time: u64,
}

impl Imdsv2Client {
    /// Creates a client for `endpoint` and API `version`.
    pub fn new(endpoint: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            version: version.into(),
            ttl: DEFAULT_TTL_SECS,
            token: None,
            token_expiry_time: 0,
        }
    }

    /// Creates a client for the default endpoint and version.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_ENDPOINT, DEFAULT_VERSION)
    }

    /// The configured endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The configured API version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The requested token lifetime, in seconds.
    pub fn ttl(&self) -> u64 {
        self.ttl
    }

    /// Overrides the requested token lifetime.
    pub fn set_ttl(&mut self, ttl: u64) {
        self.ttl = ttl;
    }

    /// The cached token, if any.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Absolute expiry time of the cached token, in unix seconds.
    pub fn token_expiry_time(&self) -> u64 {
        self.token_expiry_time
    }

    /// Whether the cached token is missing or expired at `now` (unix seconds).
    pub fn token_expired(&self, now: u64) -> bool {
        self.token_expiry_time < now
    }

    /// Token request URL; tokens are always fetched from `latest`.
    pub fn token_url(&self) -> String {
        format!("{}/latest/api/token", self.endpoint)
    }

    /// Metadata request URL for `path`, e.g. `/meta-data/instance-type`.
    pub fn metadata_url(&self, path: &str) -> String {
        format!("{}/{}{}", self.endpoint, self.version, path)
    }

    /// Headers of the token request (TTL only).
    pub fn token_headers(&self) -> Vec<(String, String)> {
        vec![(IMDSV2_HDR_TOKEN_TTL.to_string(), self.ttl.to_string())]
    }

    /// Headers of a metadata request (token only).
    pub fn metadata_headers(&self, token: &str) -> Vec<(String, String)> {
        vec![(IMDSV2_HDR_TOKEN.to_string(), token.to_string())]
    }

    /// Fully rendered `PUT` request head asking for a token.
    pub fn token_request(&self) -> Result<String> {
        let url = self.token_url();
        let (host, _, path) = parse_http_url(&url)?;
        Ok(http_request_text(
            "PUT",
            &host,
            &path,
            &self.token_headers(),
        ))
    }

    /// Fully rendered `GET` request head for `path`.
    pub fn metadata_request(&self, path: &str, token: &str) -> Result<String> {
        let url = self.metadata_url(path);
        let (host, _, wire_path) = parse_http_url(&url)?;
        Ok(http_request_text(
            "GET",
            &host,
            &wire_path,
            &self.metadata_headers(token),
        ))
    }

    /// Fetches (and caches) an IMDSv2 session token.
    pub fn get_token(&mut self) -> Result<String> {
        if let Some(token) = self.token.as_ref() {
            if !self.token_expired(now_secs()) {
                return Ok(token.clone());
            }
        }

        let url = self.token_url();
        let response = http_request("PUT", &url, &self.token_headers(), REQUEST_TIMEOUT)
            .with_context(|| format!("requesting IMDSv2 token from {url}"))?;
        if response.status != 200 {
            bail!("IMDSv2 returned {} for {url}", response.status);
        }
        if response.body.is_empty() {
            bail!("IMDSv2 returned an empty token for {url}");
        }

        self.token = Some(response.body.clone());
        self.token_expiry_time = now_secs() + self.ttl;
        Ok(response.body)
    }

    /// Fetches a metadata `path`, authenticating with the cached token.
    pub fn get(&mut self, path: &str) -> Result<String> {
        let token = self.get_token()?;
        let url = self.metadata_url(path);
        let response = http_request("GET", &url, &self.metadata_headers(&token), REQUEST_TIMEOUT)
            .with_context(|| format!("reading IMDSv2 metadata from {url}"))?;
        if response.status != 200 {
            bail!("IMDSv2 returned {} for {url}", response.status);
        }
        Ok(response.body)
    }
}

impl Default for Imdsv2Client {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Process wide client shared by [`imdsv2_get`], mirroring `IMDS_V2`.
fn global_client() -> &'static Mutex<Imdsv2Client> {
    static CLIENT: OnceLock<Mutex<Imdsv2Client>> = OnceLock::new();
    CLIENT.get_or_init(|| Mutex::new(Imdsv2Client::with_defaults()))
}

fn lock_global() -> MutexGuard<'static, Imdsv2Client> {
    // A poisoned lock only means some other caller panicked; the client state is
    // still usable, so recover it instead of propagating the panic.
    global_client()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Reads an IMDSv2 metadata path with the shared client (python `imdsv2_get`).
pub fn imdsv2_get(path: &str) -> Result<String> {
    lock_global().get(path)
}

/// Reads the session token with the shared client.
pub fn imdsv2_get_token() -> Result<String> {
    lock_global().get_token()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_built_like_python() {
        let client = Imdsv2Client::with_defaults();
        assert_eq!(
            client.token_url(),
            "http://169.254.169.254/latest/api/token"
        );
        assert_eq!(
            client.metadata_url("/meta-data/instance-type"),
            "http://169.254.169.254/latest/meta-data/instance-type"
        );

        let custom = Imdsv2Client::new("http://10.0.0.1:8080", "2021-07-15");
        assert_eq!(custom.token_url(), "http://10.0.0.1:8080/latest/api/token");
        assert_eq!(
            custom.metadata_url("/meta-data/ami-id"),
            "http://10.0.0.1:8080/2021-07-15/meta-data/ami-id"
        );
    }

    #[test]
    fn token_request_uses_ttl_header_only() {
        let mut client = Imdsv2Client::with_defaults();
        client.set_ttl(600);
        assert_eq!(client.ttl(), 600);
        assert_eq!(
            client.token_headers(),
            vec![(
                "X-aws-ec2-metadata-token-ttl-seconds".to_string(),
                "600".to_string()
            )]
        );
        assert_eq!(
            client.token_request().expect("request renders"),
            "PUT /latest/api/token HTTP/1.1\r\n\
             Host: 169.254.169.254\r\n\
             X-aws-ec2-metadata-token-ttl-seconds: 600\r\n\
             Connection: close\r\n\r\n"
        );
    }

    #[test]
    fn metadata_request_carries_token_header() {
        let client = Imdsv2Client::with_defaults();
        assert_eq!(
            client.metadata_headers("t0k3n"),
            vec![("X-aws-ec2-metadata-token".to_string(), "t0k3n".to_string())]
        );
        let request = client
            .metadata_request("/meta-data/instance-id", "t0k3n")
            .expect("request renders");
        assert_eq!(
            request,
            "GET /latest/meta-data/instance-id HTTP/1.1\r\n\
             Host: 169.254.169.254\r\n\
             X-aws-ec2-metadata-token: t0k3n\r\n\
             Connection: close\r\n\r\n"
        );
        assert!(client
            .metadata_request("/meta-data/instance-id", "t0k3n")
            .expect("request renders")
            .starts_with("GET /latest/meta-data/instance-id "));
    }

    #[test]
    fn token_expiry_follows_python_semantics() {
        let mut client = Imdsv2Client::with_defaults();
        assert!(client.token_expired(1), "missing token is always expired");
        client.token = Some("t".to_string());
        client.token_expiry_time = 100;
        assert!(client.token_expired(101));
        assert!(!client.token_expired(100), "expiry is exclusive at ttl");
        assert_eq!(client.token(), Some("t"));
    }

    #[test]
    fn url_parsing_handles_ports_and_paths() {
        assert_eq!(
            parse_http_url("http://169.254.169.254/latest/api/token").expect("parse"),
            (
                "169.254.169.254".to_string(),
                80,
                "/latest/api/token".to_string()
            )
        );
        assert_eq!(
            parse_http_url("http://127.0.0.1:8080/x").expect("parse"),
            ("127.0.0.1".to_string(), 8080, "/x".to_string())
        );
        assert_eq!(
            parse_http_url("http://host").expect("parse"),
            ("host".to_string(), 80, "/".to_string())
        );
        assert!(parse_http_url("https://host/x").is_err());
        assert!(parse_http_url("http:///x").is_err());
        assert!(parse_http_url("http://host:not-a-port/x").is_err());
    }

    #[test]
    fn request_text_is_well_formed() {
        let headers = vec![("A".to_string(), "1".to_string())];
        assert_eq!(
            http_request_text("GET", "h", "/p", &headers),
            "GET /p HTTP/1.1\r\nHost: h\r\nA: 1\r\nConnection: close\r\n\r\n"
        );
    }
}
