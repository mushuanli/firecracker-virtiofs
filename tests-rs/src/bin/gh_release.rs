// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust port of `tools/gh_release.py`.
//!
//! Drafts a release in GitHub by calling into its API. The python script uses
//! PyGithub; this port drives the API through the small [`ReleaseApi`] trait,
//! with [`GhCliApi`] as the default implementation (it shells out to `gh api`).
//!
//! Assumes all the release directories are in the current path.
//!
//! The release tarballs are produced by a minimal ustar writer plus a stored
//! block (uncompressed) gzip encoder, so no external crate is needed.

use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use fc_harness::utils;
use regex::Regex;

/// Files that are not shipped in the GitHub release, because we are not making
/// the signing keys public.
const EXCLUDE_FILES: [&str; 2] = ["RELEASE_NOTES", "SHA256SUMS.sig"];

/// Architectures published in every release.
const ARCHITECTURES: [&str; 2] = ["x86_64", "aarch64"];

/// Size of one tar block, in bytes.
const BLOCK_SIZE: usize = 512;

/// Size of a ustar header block, in bytes.
const HEADER_SIZE: usize = 512;

/// Largest payload carried by a single stored deflate block.
const MAX_STORED_BLOCK: usize = 65535;

/// Fixed gzip member header: no file name, no mtime, OS = unknown.
const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];

/// Command line arguments. `--version`, `--repository` and `--github-token`
/// mirror the python script; `--work-dir` is an addition that makes the
/// directory walking testable.
#[derive(Debug, Parser)]
#[command(
    name = "fc-gh-release",
    about = "Draft a Firecracker release on GitHub"
)]
struct Cli {
    /// Firecracker version, e.g. `v1.7.0`.
    #[arg(long = "version", value_name = "vX.Y.Z", value_parser = validate_version)]
    version: String,

    /// GitHub repository in `owner/name` form.
    #[arg(
        long = "repository",
        value_name = "OWNER/NAME",
        default_value = "firecracker-microvm/firecracker"
    )]
    repository: String,

    /// GitHub token. Required for CLI parity; the `gh` CLI backed API
    /// authenticates with the token `gh` is already logged in with.
    #[arg(long = "github-token", value_name = "TOKEN")]
    github_token: String,

    /// Directory holding the `release-*` directories and the created archives.
    #[arg(long = "work-dir", value_name = "DIR", default_value = ".")]
    work_dir: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    // The token is unused by `GhCliApi`, but `gh` reads it from its own config;
    // keep the flag required so existing invocations keep working.
    let _ = &cli.github_token;

    if let Err(err) = github_release(
        &GhCliApi,
        &cli.version,
        &cli.repository,
        &cli.work_dir,
        false,
    ) {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}

/// Validates a `vX.Y.Z` version string, like the python `version` type.
pub fn validate_version(version: &str) -> std::result::Result<String, String> {
    let pattern = Regex::new(r"^v\d+\.\d+\.\d+$").map_err(|err| err.to_string())?;
    if !pattern.is_match(version) {
        return Err("version does not match vX.Y.Z".to_string());
    }
    Ok(version.to_string())
}

// ---------------------------------------------------------------------------
// CRC-32 / gzip (stored blocks only)
// ---------------------------------------------------------------------------

/// Folds `data` into a running CRC-32 (IEEE 802.3) accumulator.
fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    crc
}

/// CRC-32 (IEEE 802.3) of `data`, the checksum stored in a gzip trailer.
pub fn crc32(data: &[u8]) -> u32 {
    !crc32_update(0xffff_ffff, data)
}

/// Header of one stored deflate block: final flag, length and one's complement.
fn stored_block_header(length: usize, last: bool) -> [u8; 5] {
    let length = length as u16;
    let mut header = [0u8; 5];
    header[0] = u8::from(last);
    header[1..3].copy_from_slice(&length.to_le_bytes());
    header[3..5].copy_from_slice(&(!length).to_le_bytes());
    header
}

/// Encodes `data` as a single-member gzip stream of stored (uncompressed) blocks.
pub fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + BLOCK_SIZE);
    out.extend_from_slice(&GZIP_HEADER);

    let mut remaining = data;
    loop {
        let take = remaining.len().min(MAX_STORED_BLOCK);
        let (chunk, rest) = remaining.split_at(take);
        let last = rest.is_empty();
        out.extend_from_slice(&stored_block_header(chunk.len(), last));
        out.extend_from_slice(chunk);
        remaining = rest;
        if last {
            break;
        }
    }

    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// Streaming gzip encoder that emits stored (uncompressed) deflate blocks.
pub struct GzipStoredWriter<W: Write> {
    inner: W,
    crc: u32,
    isize: u32,
    buffer: Vec<u8>,
    header_written: bool,
}

impl<W: Write> GzipStoredWriter<W> {
    /// Wraps `inner`; the gzip header is emitted with the first write.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            crc: 0xffff_ffff,
            isize: 0,
            buffer: Vec::with_capacity(MAX_STORED_BLOCK),
            header_written: false,
        }
    }

    /// Writes the 10 byte gzip header once.
    fn ensure_header(&mut self) -> io::Result<()> {
        if !self.header_written {
            self.inner.write_all(&GZIP_HEADER)?;
            self.header_written = true;
        }
        Ok(())
    }

    /// Emits the buffered bytes as one stored block.
    fn emit_block(&mut self, last: bool) -> io::Result<()> {
        let header = stored_block_header(self.buffer.len(), last);
        self.inner.write_all(&header)?;
        self.inner.write_all(&self.buffer)?;
        self.buffer.clear();
        Ok(())
    }

    /// Feeds `data` into the encoder, emitting a block whenever 64 KiB is full.
    pub fn write_body(&mut self, data: &[u8]) -> io::Result<()> {
        self.ensure_header()?;
        self.crc = crc32_update(self.crc, data);
        self.isize = self.isize.wrapping_add(data.len() as u32);

        let mut remaining = data;
        while !remaining.is_empty() {
            let space = MAX_STORED_BLOCK - self.buffer.len();
            let take = space.min(remaining.len());
            self.buffer.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.buffer.len() == MAX_STORED_BLOCK {
                self.emit_block(false)?;
            }
        }
        Ok(())
    }

    /// Writes the final block plus the CRC/ISIZE trailer and returns `inner`.
    pub fn finish(mut self) -> io::Result<W> {
        self.ensure_header()?;
        self.emit_block(true)?;
        self.inner.write_all(&(!self.crc).to_le_bytes())?;
        self.inner.write_all(&self.isize.to_le_bytes())?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for GzipStoredWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_body(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// ustar writer
// ---------------------------------------------------------------------------

/// Writes `value` as a NUL terminated, zero padded octal field.
fn write_octal(field: &mut [u8], value: u64) -> Result<()> {
    let digits = field.len() - 1;
    let text = format!("{value:0>width$o}", width = digits);
    if text.len() > digits {
        bail!("value {value} does not fit into {digits} octal digits");
    }
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
    Ok(())
}

/// Writes the tar checksum field (`6` octal digits, NUL, space).
fn write_checksum(field: &mut [u8], value: u64) -> Result<()> {
    let text = format!("{value:06o}");
    if text.len() > 6 {
        bail!("checksum {value} does not fit into 6 octal digits");
    }
    field[..6].copy_from_slice(text.as_bytes());
    field[6] = 0;
    field[7] = b' ';
    Ok(())
}

/// Splits an archive path into the ustar `(prefix, name)` pair.
///
/// Both fields are fixed size (155 and 100 bytes); names that do not fit in
/// `name` are split at a `/` boundary.
pub fn split_name(path: &str) -> Result<(String, String)> {
    if path.len() <= 100 {
        return Ok((String::new(), path.to_string()));
    }
    if path.len() > 100 + 155 + 1 {
        bail!("archive path too long for ustar: {path}");
    }

    let bytes = path.as_bytes();
    let mut split_at = None;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'/' {
            continue;
        }
        let (prefix, name) = path.split_at(index);
        if prefix.len() <= 155 && name.len() - 1 <= 100 {
            split_at = Some(index);
        }
    }

    match split_at {
        Some(index) => {
            let (prefix, name) = path.split_at(index);
            Ok((prefix.to_string(), name[1..].to_string()))
        }
        None => bail!("cannot split archive path into ustar prefix/name: {path}"),
    }
}

/// Builds one 512 byte ustar header block.
pub fn ustar_header(name: &str, size: u64, mode: u32, mtime: u64) -> Result<[u8; HEADER_SIZE]> {
    let (prefix, base) = split_name(name)?;
    if base.len() > 100 {
        bail!("ustar name too long: {base}");
    }

    let mut header = [0u8; HEADER_SIZE];
    header[..base.len()].copy_from_slice(base.as_bytes());
    write_octal(&mut header[100..108], u64::from(mode))?;
    write_octal(&mut header[108..116], 0)?;
    write_octal(&mut header[116..124], 0)?;
    write_octal(&mut header[124..136], size)?;
    write_octal(&mut header[136..148], mtime)?;
    // The checksum is computed with the field filled with spaces.
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..269].copy_from_slice(b"root");
    header[297..301].copy_from_slice(b"root");
    header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());

    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    write_checksum(&mut header[148..156], checksum)?;

    Ok(header)
}

/// One file stored inside the release tarball.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarEntry {
    /// Path recorded in the archive.
    pub name: String,
    /// File contents.
    pub data: Vec<u8>,
    /// Unix mode, e.g. `0o644`.
    pub mode: u32,
    /// Modification time in seconds since the epoch.
    pub mtime: u64,
}

/// Zero padding needed to align `length` to the next tar block.
pub fn block_padding(length: u64) -> usize {
    let remainder = (length % BLOCK_SIZE as u64) as usize;
    if remainder == 0 {
        0
    } else {
        BLOCK_SIZE - remainder
    }
}

/// Appends one entry (header, payload, padding) to `writer`.
pub fn write_tar_entry<W: Write>(writer: &mut W, entry: &TarEntry) -> Result<()> {
    let header = ustar_header(
        &entry.name,
        entry.data.len() as u64,
        entry.mode,
        entry.mtime,
    )?;
    writer.write_all(&header)?;
    writer.write_all(&entry.data)?;
    let padding = block_padding(entry.data.len() as u64);
    if padding > 0 {
        writer.write_all(&vec![0u8; padding])?;
    }
    Ok(())
}

/// Builds a complete `.tar.gz` archive from `entries` in memory.
pub fn build_tar_gz(entries: &[TarEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut writer = GzipStoredWriter::new(&mut out);
        for entry in entries {
            write_tar_entry(&mut writer, entry)?;
        }
        // Two zero blocks terminate a tar stream.
        writer.write_all(&[0u8; BLOCK_SIZE * 2])?;
        writer.finish()?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Release tarball
// ---------------------------------------------------------------------------

/// Reads `path` into a tar entry stored under `name`.
pub fn tar_entry_from_file(path: &Path, name: String) -> Result<TarEntry> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    let data = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;

    Ok(TarEntry {
        name,
        data,
        mode: metadata.mode() & 0o777,
        mtime: metadata.mtime().max(0) as u64,
    })
}

/// Archive path of `asset`, relative to the parent of `release_dir`.
///
/// This matches `tarfile.add(asset)` on a `release-<version>-<arch>/...` path.
pub fn archive_name(release_dir: &Path, asset: &Path) -> String {
    let relative = asset.strip_prefix(release_dir).unwrap_or(asset);
    match release_dir.file_name() {
        Some(dir_name) => format!("{}/{}", dir_name.to_string_lossy(), relative.display()),
        None => relative.display().to_string(),
    }
}

/// Lists the files of `release_dir` in a deterministic order.
pub fn release_files(release_dir: &Path) -> Result<Vec<PathBuf>> {
    if !release_dir.is_dir() {
        bail!("release directory {} does not exist", release_dir.display());
    }

    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(release_dir).sort_by_file_name() {
        let entry = entry.with_context(|| format!("failed to walk {}", release_dir.display()))?;
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
}

/// Builds a release tarball with the local assets.
///
/// `RELEASE_NOTES` and `SHA256SUMS.sig` are skipped, assets whose name ends with
/// `arch` get the executable bit, and every file is appended to the archive.
/// Returns the assets that were added, in archive order.
pub fn build_tarball(release_dir: &Path, release_tgz: &Path, arch: &str) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    let mut added = Vec::new();

    for asset in release_files(release_dir)? {
        let file_name = asset
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();

        if EXCLUDE_FILES.contains(&file_name.as_str()) {
            println!("Skipping file {}", asset.display());
            continue;
        }

        if file_name.ends_with(arch) {
            println!("Setting +x bit for {}", asset.display());
            std::fs::set_permissions(&asset, std::fs::Permissions::from_mode(0o755))
                .with_context(|| format!("failed to chmod {}", asset.display()))?;
        }

        println!("Adding {} to {}", asset.display(), release_tgz.display());
        entries.push(tar_entry_from_file(
            &asset,
            archive_name(release_dir, &asset),
        )?);
        added.push(asset);
    }

    let bytes = build_tar_gz(&entries)?;
    if let Some(parent) = release_tgz.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    std::fs::write(release_tgz, bytes)
        .with_context(|| format!("failed to write {}", release_tgz.display()))?;

    Ok(added)
}

/// `sha256sum`-formatted digest line for `path`.
pub fn sha256sum_line(path: &Path) -> Result<String> {
    let data = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(format!(
        "{}  {}\n",
        utils::sha256_hex(&data),
        path.display()
    ))
}

/// The `<archive>.sha256.txt` sibling of a release archive.
pub fn checksum_path(release_tgz: &Path) -> PathBuf {
    let mut name = release_tgz
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.push_str(".sha256.txt");
    release_tgz.with_file_name(name)
}

/// Content type used when uploading `asset` to GitHub.
pub fn content_type_for(asset: &Path) -> &'static str {
    match asset.extension().and_then(|extension| extension.to_str()) {
        Some("txt") => "text/plain",
        Some("tgz") | Some("gz") => "application/gzip",
        _ => "application/octet-stream",
    }
}

// ---------------------------------------------------------------------------
// GitHub API
// ---------------------------------------------------------------------------

/// A release created on GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseHandle {
    /// GitHub release id, used to address the asset upload endpoint.
    pub id: u64,
    /// HTML url of the created release.
    pub html_url: String,
}

/// The minimal part of the GitHub release API this tool needs.
pub trait ReleaseApi {
    /// Creates a draft release for `tag` and returns its handle.
    fn create_draft_release(
        &self,
        repo: &str,
        tag: &str,
        name: &str,
        body: &str,
        prerelease: bool,
    ) -> Result<ReleaseHandle>;

    /// Uploads one asset to an existing release.
    fn upload_asset(
        &self,
        repo: &str,
        release: &ReleaseHandle,
        asset: &Path,
        label: &str,
        content_type: &str,
    ) -> Result<()>;
}

/// Default [`ReleaseApi`] that drives the GitHub API through the `gh` CLI.
#[derive(Debug, Default, Clone, Copy)]
pub struct GhCliApi;

/// `gh api` argv creating a draft release.
pub fn create_release_args(
    repo: &str,
    tag: &str,
    name: &str,
    body: &str,
    prerelease: bool,
) -> Vec<String> {
    vec![
        "gh".to_string(),
        "api".to_string(),
        "-X".to_string(),
        "POST".to_string(),
        format!("repos/{repo}/releases"),
        "-f".to_string(),
        format!("tag_name={tag}"),
        "-f".to_string(),
        format!("name={name}"),
        "-f".to_string(),
        format!("body={body}"),
        "-F".to_string(),
        "draft=true".to_string(),
        "-F".to_string(),
        format!("prerelease={prerelease}"),
    ]
}

/// `gh api` argv uploading one asset to the GitHub uploads host.
pub fn upload_asset_args(
    repo: &str,
    release_id: u64,
    asset: &Path,
    label: &str,
    content_type: &str,
) -> Vec<String> {
    vec![
        "gh".to_string(),
        "api".to_string(),
        "--hostname".to_string(),
        "uploads.github.com".to_string(),
        "-X".to_string(),
        "POST".to_string(),
        format!("repos/{repo}/releases/{release_id}/assets?name={label}"),
        "-H".to_string(),
        format!("Content-Type: {content_type}"),
        "--input".to_string(),
        asset.display().to_string(),
    ]
}

/// Extracts the release id and HTML url from a `gh api` response body.
pub fn parse_release_response(stdout: &str) -> Result<ReleaseHandle> {
    let document: serde_json::Value =
        serde_json::from_str(stdout).context("gh api did not return valid JSON")?;
    let id = document
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow!("gh api response has no integer 'id'"))?;
    let html_url = document
        .get("html_url")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();

    Ok(ReleaseHandle { id, html_url })
}

/// Runs `gh api` with `args` and returns its stdout, failing on a non-zero exit.
pub fn gh_api(args: &[String]) -> Result<String> {
    let printable = args.join(" ");
    let output =
        utils::run_cmd_args(args).with_context(|| format!("failed to run: {printable}"))?;
    if !output.success() {
        bail!("{}", output.describe(&printable));
    }
    Ok(output.stdout)
}

impl ReleaseApi for GhCliApi {
    fn create_draft_release(
        &self,
        repo: &str,
        tag: &str,
        name: &str,
        body: &str,
        prerelease: bool,
    ) -> Result<ReleaseHandle> {
        let args = create_release_args(repo, tag, name, body, prerelease);
        let stdout =
            gh_api(&args).with_context(|| format!("failed to create release {tag} in {repo}"))?;
        parse_release_response(&stdout)
    }

    fn upload_asset(
        &self,
        repo: &str,
        release: &ReleaseHandle,
        asset: &Path,
        label: &str,
        content_type: &str,
    ) -> Result<()> {
        let args = upload_asset_args(repo, release.id, asset, label, content_type);
        gh_api(&args).with_context(|| format!("failed to upload {}", asset.display()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Release driver
// ---------------------------------------------------------------------------

/// Builds the archives, computes their checksums and drafts the GitHub release.
pub fn github_release(
    api: &dyn ReleaseApi,
    tag_version: &str,
    repo: &str,
    base: &Path,
    prerelease: bool,
) -> Result<()> {
    let mut assets: Vec<PathBuf> = Vec::new();

    for arch in ARCHITECTURES {
        let release_dir = base.join(format!("release-{tag_version}-{arch}"));
        let release_tgz = base.join(format!("firecracker-{tag_version}-{arch}.tgz"));

        println!("Creating release archive {} ...", release_tgz.display());
        build_tarball(&release_dir, &release_tgz, arch)?;
        println!("Done. Archive successfully created. sha256sum result:");

        let checksum = checksum_path(&release_tgz);
        std::fs::write(&checksum, sha256sum_line(&release_tgz)?)
            .with_context(|| format!("failed to write {}", checksum.display()))?;
        let printed = std::fs::read_to_string(&checksum)
            .with_context(|| format!("failed to read {}", checksum.display()))?;
        print!("{printed}");

        assets.push(release_tgz);
        assets.push(checksum);
    }

    assets.push(base.join("test_results.tar.gz"));

    let message_file = base
        .join(format!("release-{tag_version}-x86_64"))
        .join("RELEASE_NOTES");
    let message = std::fs::read_to_string(&message_file)
        .with_context(|| format!("failed to read {}", message_file.display()))?;

    println!("Creating GitHub release draft");
    let release = api.create_draft_release(
        repo,
        tag_version,
        &format!("Firecracker {tag_version}"),
        &message,
        prerelease,
    )?;

    for asset in &assets {
        let content_type = content_type_for(asset);
        let label = asset
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        println!(
            "Uploading asset {} with content-type={content_type}",
            asset.display()
        );
        api.upload_asset(repo, &release, asset, &label, content_type)?;
    }

    println!(
        "Draft release created successful. Check it out at {}",
        release.html_url
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads an octal header field, ignoring the NUL terminator.
    fn octal_field(header: &[u8], range: std::ops::Range<usize>) -> u64 {
        let text = String::from_utf8_lossy(&header[range])
            .trim_end_matches('\0')
            .trim()
            .to_string();
        u64::from_str_radix(&text, 8).expect("field is octal")
    }

    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b"firecracker"), crc32(b"firecracker"));
    }

    #[test]
    fn gzip_header_and_magic() {
        let encoded = gzip_stored(b"hello firecracker");
        assert_eq!(&encoded[..2], &[0x1f, 0x8b], "gzip magic");
        assert_eq!(encoded[2], 0x08, "deflate compression method");
        assert_eq!(encoded[3], 0x00, "no optional flags");

        // Trailer: CRC-32 then ISIZE, both little endian.
        let trailer = &encoded[encoded.len() - 8..];
        assert_eq!(
            u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]),
            crc32(b"hello firecracker")
        );
        assert_eq!(
            u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]),
            17
        );

        // Stored block: final flag set, LEN/NLEN pair, then the raw payload.
        assert_eq!(encoded[10], 0x01, "single final stored block");
        assert_eq!(&encoded[15..15 + 17], b"hello firecracker");
    }

    #[test]
    fn gzip_empty_input_has_one_empty_final_block() {
        let encoded = gzip_stored(b"");
        assert_eq!(encoded.len(), 10 + 5 + 8);
        assert_eq!(encoded[10], 0x01);
        assert_eq!(&encoded[11..13], &[0x00, 0x00]);
        assert_eq!(&encoded[13..15], &[0xff, 0xff]);
    }

    #[test]
    fn gzip_streams_identical_bytes_to_the_oneshot_encoder() {
        let payload: Vec<u8> = (0..200_000u32).map(|value| (value % 251) as u8).collect();
        let mut streamed = Vec::new();
        {
            let mut writer = GzipStoredWriter::new(&mut streamed);
            for chunk in payload.chunks(7_919) {
                writer.write_all(chunk).expect("writes");
            }
            writer.finish().expect("finishes");
        }

        let oneshot = gzip_stored(&payload);
        assert_eq!(streamed.len(), oneshot.len());
        assert_eq!(streamed, oneshot);
        assert!(streamed.len() > payload.len(), "stored blocks add framing");
    }

    #[test]
    fn ustar_header_fields() {
        let header = ustar_header("firecracker", 0o1744, 0o644, 1_700_000_000).expect("header");

        assert_eq!(&header[0..11], b"firecracker");
        assert_eq!(&header[100..107], b"0000644");
        assert_eq!(header[107], 0);
        assert_eq!(octal_field(&header, 108..116), 0, "uid");
        assert_eq!(octal_field(&header, 116..124), 0, "gid");
        assert_eq!(octal_field(&header, 124..136), 0o1744, "size");
        assert_eq!(octal_field(&header, 136..148), 1_700_000_000, "mtime");
        assert_eq!(header[156], b'0', "regular file type flag");
        assert_eq!(&header[257..263], b"ustar\0");
        assert_eq!(&header[263..265], b"00");
        assert_eq!(&header[500..512], &[0u8; 12][..], "block padding");

        // 6 octal digits, NUL, space.
        assert_eq!(header[154], 0);
        assert_eq!(header[155], b' ');
        let checksum = octal_field(&header, 148..154);

        // Recompute with the checksum field reverted to spaces.
        let mut copy = header;
        copy[148..156].copy_from_slice(b"        ");
        let expected: u64 = copy.iter().map(|byte| u64::from(*byte)).sum();
        assert_eq!(checksum, expected);
    }

    #[test]
    fn ustar_header_splits_long_names() {
        let long = format!("release-1.7.0-x86_64/{}", "a".repeat(100));
        let header = ustar_header(&long, 0, 0o644, 0).expect("long names are split");
        assert_eq!(&header[0..100], "a".repeat(100).as_bytes());
        assert_eq!(&header[345..365], b"release-1.7.0-x86_64");

        let too_long = format!("{}/{}", "b".repeat(160), "c".repeat(120));
        assert!(ustar_header(&too_long, 0, 0o644, 0).is_err());
    }

    #[test]
    fn block_padding_aligns_to_tar_blocks() {
        assert_eq!(block_padding(0), 0);
        assert_eq!(block_padding(512), 0);
        assert_eq!(block_padding(1), 511);
        assert_eq!(block_padding(513), 511);
    }

    #[test]
    fn tar_gz_contains_the_entries_in_order() {
        let entries = vec![
            TarEntry {
                name: "release-1.7.0-x86_64/firecracker".to_string(),
                data: b"binary-one".to_vec(),
                mode: 0o755,
                mtime: 0,
            },
            TarEntry {
                name: "release-1.7.0-x86_64/jailer".to_string(),
                data: b"binary-two".to_vec(),
                mode: 0o644,
                mtime: 0,
            },
        ];
        let archive = build_tar_gz(&entries).expect("archive");

        assert_eq!(&archive[..2], &[0x1f, 0x8b]);
        // 10 byte gzip header, 5 byte stored block header, then the tar stream.
        let tar = &archive[15..];
        assert!(tar.starts_with(b"release-1.7.0-x86_64/firecracker\0"));
        assert_eq!(octal_field(tar, 124..136), 10);
        assert_eq!(octal_field(tar, 100..108), 0o755);

        let second = BLOCK_SIZE + BLOCK_SIZE; // header 512 + one full data block
        assert!(tar[second..].starts_with(b"release-1.7.0-x86_64/jailer\0"));
        assert_eq!(octal_field(&tar[second..], 124..136), 10);

        // The payload is stored uncompressed, so it appears verbatim.
        assert!(archive
            .windows(b"binary-one".len())
            .any(|window| window == b"binary-one"));
    }

    #[test]
    fn archive_name_is_relative_to_the_release_parent() {
        assert_eq!(
            archive_name(
                Path::new("/tmp/out/release-1.7.0-x86_64"),
                Path::new("/tmp/out/release-1.7.0-x86_64/firecracker")
            ),
            "release-1.7.0-x86_64/firecracker"
        );
        assert_eq!(
            archive_name(
                Path::new("release-1.7.0-x86_64"),
                Path::new("release-1.7.0-x86_64/firecracker")
            ),
            "release-1.7.0-x86_64/firecracker"
        );
    }

    #[test]
    fn build_tarball_skips_signatures_and_marks_arch_assets_executable() {
        let root = std::env::temp_dir().join(format!("fc-gh-release-{}", std::process::id()));
        let release_dir = root.join("release-1.7.0-x86_64");
        std::fs::create_dir_all(&release_dir).expect("creates release dir");
        for (name, mode) in [
            ("firecracker-x86_64", 0o644u32),
            ("jailer-x86_64", 0o644),
            ("RELEASE_NOTES", 0o644),
            ("SHA256SUMS.sig", 0o644),
            ("SHA256SUMS", 0o644),
        ] {
            let path = release_dir.join(name);
            std::fs::write(&path, name.as_bytes()).expect("writes asset");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        }

        let archive = root.join("firecracker-1.7.0-x86_64.tgz");
        let added = build_tarball(&release_dir, &archive, "x86_64").expect("builds the tarball");

        let names: Vec<String> = added
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["SHA256SUMS", "firecracker-x86_64", "jailer-x86_64"]
        );

        for asset in ["firecracker-x86_64", "jailer-x86_64"] {
            let mode = std::fs::metadata(release_dir.join(asset))
                .expect("stat")
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755, "{asset} must be executable");
        }

        let bytes = std::fs::read(&archive).expect("archive exists");
        assert_eq!(&bytes[..2], &[0x1f, 0x8b]);
        assert!(!String::from_utf8_lossy(&bytes).contains("SHA256SUMS.sig"));
        assert!(!String::from_utf8_lossy(&bytes).contains("RELEASE_NOTES"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn checksum_path_appends_the_expected_suffix() {
        assert_eq!(
            checksum_path(Path::new("/tmp/firecracker-1.7.0-x86_64.tgz")),
            PathBuf::from("/tmp/firecracker-1.7.0-x86_64.tgz.sha256.txt")
        );
    }

    #[test]
    fn content_types_match_the_python_rules() {
        assert_eq!(content_type_for(Path::new("a.sha256.txt")), "text/plain");
        assert_eq!(content_type_for(Path::new("a.tgz")), "application/gzip");
        assert_eq!(content_type_for(Path::new("a.gz")), "application/gzip");
        assert_eq!(
            content_type_for(Path::new("firecracker")),
            "application/octet-stream"
        );
    }

    #[test]
    fn version_validation_mirrors_the_python_regex() {
        assert_eq!(validate_version("v1.7.0"), Ok("v1.7.0".to_string()));
        assert_eq!(
            validate_version("1.7.0"),
            Err("version does not match vX.Y.Z".to_string())
        );
        assert!(validate_version("v1.7").is_err());
        assert!(validate_version("v1.7.0-rc").is_err());
    }

    #[test]
    fn gh_api_argvs() {
        let args = create_release_args("owner/repo", "v1.7.0", "Firecracker v1.7.0", "body", false);
        assert_eq!(args[0], "gh");
        assert_eq!(args[1], "api");
        assert_eq!(args[4], "repos/owner/repo/releases");
        assert!(args.contains(&"tag_name=v1.7.0".to_string()));
        assert!(args.contains(&"body=body".to_string()));
        assert!(args.contains(&"draft=true".to_string()));
        assert!(args.contains(&"prerelease=false".to_string()));

        let upload = upload_asset_args(
            "owner/repo",
            42,
            Path::new("/tmp/firecracker.tgz"),
            "firecracker.tgz",
            "application/gzip",
        );
        assert!(upload.contains(&"uploads.github.com".to_string()));
        assert!(upload
            .contains(&"repos/owner/repo/releases/42/assets?name=firecracker.tgz".to_string()));
        assert!(upload.contains(&"Content-Type: application/gzip".to_string()));
        assert!(upload.contains(&"/tmp/firecracker.tgz".to_string()));
    }

    #[test]
    fn gh_api_wraps_the_exit_code() {
        assert_eq!(gh_api(&["true".to_string()]).expect("true succeeds"), "");
        let err = gh_api(&["false".to_string()]).expect_err("false fails");
        assert!(
            err.to_string().contains("Returned error code"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parses_the_gh_api_response() {
        let handle = parse_release_response(r#"{"id": 12, "html_url": "https://x/1"}"#)
            .expect("valid response");
        assert_eq!(
            handle,
            ReleaseHandle {
                id: 12,
                html_url: "https://x/1".to_string()
            }
        );

        assert!(parse_release_response("not json").is_err());
        assert!(parse_release_response(r#"{"html_url": "https://x/1"}"#).is_err());
    }

    /// Records the calls made by [`github_release`] so it can be tested offline.
    struct RecordingApi {
        uploaded: std::cell::RefCell<Vec<(String, String)>>,
    }

    impl ReleaseApi for RecordingApi {
        fn create_draft_release(
            &self,
            repo: &str,
            tag: &str,
            name: &str,
            body: &str,
            prerelease: bool,
        ) -> Result<ReleaseHandle> {
            assert_eq!(repo, "owner/repo");
            assert_eq!(tag, "v1.7.0");
            assert_eq!(name, "Firecracker v1.7.0");
            assert_eq!(body, "release notes body");
            assert!(!prerelease);
            Ok(ReleaseHandle {
                id: 7,
                html_url: "https://example.invalid/release".to_string(),
            })
        }

        fn upload_asset(
            &self,
            repo: &str,
            release: &ReleaseHandle,
            asset: &Path,
            label: &str,
            content_type: &str,
        ) -> Result<()> {
            assert_eq!(repo, "owner/repo");
            assert_eq!(release.id, 7);
            assert!(
                asset.exists(),
                "{} must exist before upload",
                asset.display()
            );
            self.uploaded
                .borrow_mut()
                .push((label.to_string(), content_type.to_string()));
            Ok(())
        }
    }

    #[test]
    fn github_release_builds_and_uploads_every_asset() {
        let root = std::env::temp_dir().join(format!("fc-gh-driver-{}", std::process::id()));

        for arch in ARCHITECTURES {
            let release_dir = root.join(format!("release-v1.7.0-{arch}"));
            std::fs::create_dir_all(&release_dir).expect("creates release dir");
            std::fs::write(release_dir.join(format!("firecracker-{arch}")), b"elf").expect("asset");
            std::fs::write(release_dir.join("SHA256SUMS.sig"), b"sig").expect("asset");
            std::fs::write(release_dir.join("RELEASE_NOTES"), b"release notes body")
                .expect("notes");
        }
        std::fs::write(root.join("test_results.tar.gz"), b"results").expect("results");

        let api = RecordingApi {
            uploaded: std::cell::RefCell::new(Vec::new()),
        };
        github_release(&api, "v1.7.0", "owner/repo", &root, false).expect("drafts the release");

        let uploaded = api.uploaded.borrow();
        assert_eq!(uploaded.len(), 5);
        assert_eq!(
            uploaded
                .iter()
                .map(|(label, _)| label.as_str())
                .collect::<Vec<_>>(),
            vec![
                "firecracker-v1.7.0-x86_64.tgz",
                "firecracker-v1.7.0-x86_64.tgz.sha256.txt",
                "firecracker-v1.7.0-aarch64.tgz",
                "firecracker-v1.7.0-aarch64.tgz.sha256.txt",
                "test_results.tar.gz",
            ]
        );
        assert_eq!(uploaded[0].1, "application/gzip");
        assert_eq!(uploaded[1].1, "text/plain");
        assert_eq!(uploaded[4].1, "application/gzip");

        let checksum =
            std::fs::read_to_string(root.join("firecracker-v1.7.0-x86_64.tgz.sha256.txt"))
                .expect("checksum file");
        assert!(checksum.ends_with("firecracker-v1.7.0-x86_64.tgz\n"));

        let _ = std::fs::remove_dir_all(&root);
    }
}
