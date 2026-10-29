// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Git repository helpers, ported from `tests/framework/utils_repo.py`, with
//! the `with_filelock.py` decorator folded in as [`FileLock`].
//!
//! Python's `git_repo_files` is a generator over `git ls-files` output; the port
//! returns the collected vector. `fnmatch` is reimplemented here because the
//! matching rules (including `*` crossing `/`) differ from the `glob` crate and
//! the crate has no extra dependency to spend on it.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::utils;

/// Matches `name` against `pattern` with python `fnmatch` semantics.
///
/// Supported syntax: `*` (any run of characters, `/` included), `?` (one
/// character), `[seq]` (character class), `[!seq]` (negated class) and `[a-z]`
/// ranges. Matching is case sensitive, like `fnmatch` on Linux.
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    match_from(&name, 0, &pattern, 0)
}

/// Backtracking matcher: `star` remembers the last `*` so it can swallow one
/// more character whenever the rest of the pattern fails.
fn match_from(name: &[char], mut n: usize, pattern: &[char], mut p: usize) -> bool {
    let mut star: Option<(usize, usize)> = None;
    loop {
        if p == pattern.len() && n == name.len() {
            return true;
        }
        if p < pattern.len() {
            match pattern[p] {
                '*' => {
                    star = Some((p + 1, n));
                    p += 1;
                    continue;
                }
                '?' if n < name.len() => {
                    p += 1;
                    n += 1;
                    continue;
                }
                '[' if n < name.len() => match match_class(name[n], pattern, p) {
                    Some((true, next)) => {
                        p = next;
                        n += 1;
                        continue;
                    }
                    Some((false, _)) => {}
                    // Unterminated class: python treats `[` literally.
                    None if name[n] == '[' => {
                        p += 1;
                        n += 1;
                        continue;
                    }
                    None => {}
                },
                literal if n < name.len() && literal == name[n] => {
                    p += 1;
                    n += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((star_pattern, star_name)) if star_name < name.len() => {
                star = Some((star_pattern, star_name + 1));
                p = star_pattern;
                n = star_name + 1;
            }
            _ => return false,
        }
    }
}

/// Matches one character against the `[...]` class starting at `start`.
///
/// Returns the match result plus the index just past the class, or `None` when
/// the class is unterminated.
fn match_class(ch: char, pattern: &[char], start: usize) -> Option<(bool, usize)> {
    let mut idx = start + 1;
    let negated = idx < pattern.len() && (pattern[idx] == '!' || pattern[idx] == '^');
    if negated {
        idx += 1;
    }
    let mut matched = false;
    let mut first = true;
    while idx < pattern.len() {
        if pattern[idx] == ']' && !first {
            return Some((matched != negated, idx + 1));
        }
        first = false;
        if idx + 2 < pattern.len() && pattern[idx + 1] == '-' && pattern[idx + 2] != ']' {
            let low = pattern[idx];
            let high = pattern[idx + 2];
            if low <= ch && ch <= high {
                matched = true;
            }
            idx += 3;
        } else {
            if pattern[idx] == ch {
                matched = true;
            }
            idx += 1;
        }
    }
    None
}

/// Returns the repository files under `root` whose path matches `glob`.
///
/// `root` is passed straight to `git ls-files`, and `glob` is applied to the
/// repo relative path, exactly like the python helper.
pub fn git_repo_files(root: &str, glob: &str) -> Result<Vec<PathBuf>> {
    git_repo_files_with(Path::new("git"), root, glob)
}

/// Same as [`git_repo_files`] but with an explicit `git` executable, so the
/// listing can be exercised against a stub without touching `PATH`.
fn git_repo_files_with(git: &Path, root: &str, glob: &str) -> Result<Vec<PathBuf>> {
    let args: Vec<OsString> = vec![
        git.as_os_str().to_os_string(),
        OsString::from("ls-files"),
        OsString::from(root),
    ];
    let stdout = utils::check_output_args(&args)?.stdout;
    Ok(stdout
        .lines()
        .filter(|file| !file.is_empty())
        .filter(|file| fnmatch(file, glob))
        .map(PathBuf::from)
        .collect())
}

/// An exclusive advisory lock on a file, replacing `filelock.FileLock`.
///
/// The lock lives as long as the guard and is released on drop (and therefore
/// also when the process dies, since `flock` locks die with their file).
#[derive(Debug)]
pub struct FileLock {
    path: PathBuf,
    file: File,
}

impl FileLock {
    /// Takes the exclusive lock on `path`, creating the file if needed.
    ///
    /// Blocks until the lock is free, matching `FileLock(path)`'s default
    /// timeout behaviour.
    pub fn acquire(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = open_and_lock(&path, false)?
            .ok_or_else(|| anyhow!("lock on {} is unavailable", path.display()))?;
        Ok(Self { path, file })
    }

    /// Takes the exclusive lock on `path` if it is free right now.
    pub fn try_acquire(path: impl Into<PathBuf>) -> Result<Option<Self>> {
        let path = path.into();
        match open_and_lock(&path, true)? {
            Some(file) => Ok(Some(Self { path, file })),
            None => Ok(None),
        }
    }

    /// Takes the lock the python decorator would use for `func_name`.
    ///
    /// Two functions sharing a name share a lock: the lock file is
    /// `<tmp>/<func_name>` with its suffix replaced by `.lock`.
    pub fn for_function(func_name: &str) -> Result<Self> {
        Self::acquire(lock_path_for(func_name))
    }

    /// Path of the lock file.
    pub fn lock_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // SAFETY: the fd is owned by `self.file` and still open here.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Lock file path for a decorated function name.
pub fn lock_path_for(func_name: &str) -> PathBuf {
    let mut path = std::env::temp_dir().join(func_name);
    // `Path.with_suffix(".lock")` semantics: an existing suffix is replaced.
    path.set_extension("lock");
    path
}

/// Runs `op` while holding the lock of `func_name` (python `with_filelock`).
pub fn with_file_lock<T>(func_name: &str, op: impl FnOnce() -> Result<T>) -> Result<T> {
    let _lock = FileLock::for_function(func_name)?;
    op()
}

/// Opens `path` and takes an exclusive `flock` on it.
fn open_and_lock(path: &Path, non_blocking: bool) -> Result<Option<File>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;

    let mut operation = libc::LOCK_EX;
    if non_blocking {
        operation |= libc::LOCK_NB;
    }
    // SAFETY: the fd stays valid for the duration of the call.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
        let err = io::Error::last_os_error();
        if non_blocking && err.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(err).with_context(|| format!("flock {}", path.display()));
    }
    Ok(Some(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fc-repo-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn fnmatch_follows_python_semantics() {
        assert!(fnmatch("src/lib.rs", "*"));
        assert!(fnmatch("src/lib.rs", "*.rs"));
        assert!(!fnmatch("README.md", "*.rs"));
        assert!(fnmatch("a", "?"));
        assert!(!fnmatch("ab", "?"));
        assert!(fnmatch("src/lib.rs", "src/*"));
        assert!(fnmatch("src/lib.rs", "s?c/l?b.rs"));
        assert!(fnmatch("b", "[abc]"));
        assert!(!fnmatch("d", "[abc]"));
        assert!(fnmatch("d", "[!abc]"));
        assert!(!fnmatch("b", "[!abc]"));
        assert!(fnmatch("c", "[a-f]"));
        assert!(!fnmatch("z", "[a-f]"));
        assert!(fnmatch("[", "["));
        assert!(fnmatch("a/b", "a?b"), "? matches any character, / included");
    }

    #[test]
    fn git_repo_files_filters_with_a_stub_git() {
        let dir = temp_dir("git");
        let stub = dir.join("git");
        std::fs::write(
            &stub,
            "#!/bin/sh\nprintf 'src/lib.rs\\nREADME.md\\ntests/framework/utils.py\\n'\n",
        )
        .expect("write stub");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&stub).expect("stat stub").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&stub, perms).expect("chmod stub");

        let rust_files = git_repo_files_with(&stub, ".", "*.rs").expect("list files");
        assert_eq!(rust_files, vec![PathBuf::from("src/lib.rs")]);

        let all = git_repo_files_with(&stub, ".", "*").expect("list files");
        assert_eq!(all.len(), 3);
        assert!(all.contains(&PathBuf::from("tests/framework/utils.py")));

        let none = git_repo_files_with(&stub, ".", "*.json").expect("list files");
        assert!(none.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_path_matches_with_suffix() {
        let plain = lock_path_for("test_run_concurrency");
        assert_eq!(
            plain.file_name().expect("name").to_string_lossy(),
            "test_run_concurrency.lock"
        );
        let suffixed = lock_path_for("test_foo.bar");
        assert_eq!(
            suffixed.file_name().expect("name").to_string_lossy(),
            "test_foo.lock"
        );
    }

    #[test]
    fn file_lock_is_exclusive_and_released_on_drop() {
        let dir = temp_dir("lock");
        let path = dir.join("acquire.lock");

        let first = FileLock::acquire(&path).expect("first acquire");
        assert_eq!(first.lock_path(), path);
        assert!(
            FileLock::try_acquire(&path).expect("try acquire").is_none(),
            "second acquire must fail while the lock is held"
        );

        drop(first);
        let second = FileLock::try_acquire(&path).expect("try acquire after drop");
        assert!(second.is_some(), "lock must be free after the guard drops");
        drop(second);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_file_lock_runs_the_closure_under_the_lock() {
        let value = with_file_lock("test_with_file_lock_helper", || Ok(7)).expect("run closure");
        assert_eq!(value, 7);
        let err = with_file_lock("test_with_file_lock_helper", || -> Result<()> {
            anyhow::bail!("inner failure")
        })
        .expect_err("closure error propagates");
        assert!(err.to_string().contains("inner failure"));
    }
}
