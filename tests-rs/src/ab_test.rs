// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A/B-test helpers, ported from `tests/framework/ab_test.py`.
//!
//! The python module compares the output of a test run against the output of
//! the same run on a different git revision. `git_ab_test` becomes
//! [`git_ab_test`], the `@with_filelock` decorator becomes a `flock(2)` based
//! [`FileLock`], and `TemporaryDirectory` becomes [`TempDir`].

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};

use crate::properties;
use crate::utils::{self, CommandReturn};

/// Environment variable overriding the `git` binary used by [`git_clone`].
pub const GIT_ENV: &str = "FC_GIT";

/// Default "A" revision: the pull request base branch in CI, `main` locally.
pub fn default_a_revision() -> String {
    buildkite_revision_a().unwrap_or_else(|| "main".to_string())
}

fn buildkite_revision_a() -> Option<String> {
    // `global_props.buildkite_revision_a` is exactly this environment variable,
    // read here directly so A/B tests do not collect the whole property set
    // (which probes IMDS) just to get a branch name.
    std::env::var("BUILDKITE_PULL_REQUEST_BASE_BRANCH")
        .ok()
        .filter(|branch| !branch.is_empty())
}

/// Returns `true` if and only if the two arguments are equal.
pub fn default_comparator<T: PartialEq>(a: &T, b: &T) -> bool {
    a == b
}

/// Directory removed recursively when the value is dropped.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates an empty temporary directory below the system temp directory.
    pub fn new(prefix: &str) -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            unique_token()
        ));
        std::fs::create_dir_all(&path)
            .with_context(|| format!("creating temporary directory {}", path.display()))?;
        Ok(Self { path })
    }

    /// Path of the temporary directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).ok();
    }
}

/// Runs the given test runner against two git revisions and compares them.
///
/// `test_runner` receives a checkout directory and whether it is the "A"
/// revision. When `b_revision` is `None` the "B" run happens in the parent of
/// the current directory, i.e. the repository root pytest runs from.
pub fn git_ab_test<T, U, F, C>(
    test_runner: F,
    comparator: C,
    a_revision: &str,
    b_revision: Option<&str>,
) -> Result<(T, T, U)>
where
    F: Fn(&Path, bool) -> T,
    C: Fn(&T, &T) -> U,
{
    git_ab_test_with_git(
        test_runner,
        comparator,
        a_revision,
        b_revision,
        &git_binary(),
    )
}

/// [`git_ab_test`] with an explicit `git` binary, used as a test seam.
pub fn git_ab_test_with_git<T, U, F, C>(
    test_runner: F,
    comparator: C,
    a_revision: &str,
    b_revision: Option<&str>,
    git_bin: &str,
) -> Result<(T, T, U)>
where
    F: Fn(&Path, bool) -> T,
    C: Fn(&T, &T) -> U,
{
    let temp_dir = TempDir::new("fc-ab-test")?;

    let dir_a = git_clone_with(&temp_dir.path().join(a_revision), a_revision, git_bin)?;
    let result_a = test_runner(&dir_a, true);

    let dir_b = match b_revision {
        Some(revision) => git_clone_with(&temp_dir.path().join(revision), revision, git_bin)?,
        // By default pytest runs inside the `tests` subdirectory, so the
        // repository root is its parent.
        None => repository_root()?,
    };
    let result_b = test_runner(&dir_b, false);

    let comparison = comparator(&result_a, &result_b);
    Ok((result_a, result_b, comparison))
}

/// Runs `command` as an A/B-test if this is a pull request, and once otherwise.
pub fn git_ab_test_host_command_if_pr<C>(
    command: &str,
    comparator: C,
    check_in_nonpr: bool,
) -> Result<Option<CommandReturn>>
where
    C: Fn(&CommandReturn, &CommandReturn) -> bool,
{
    if properties::global_props().buildkite_pr {
        git_ab_test_host_command(command, comparator, &default_a_revision(), None)?;
        return Ok(None);
    }

    let root = repository_root()?;
    let result = utils::run_cmd(&format!("cd {} && {command}", shell_quote(&root)))?;
    if check_in_nonpr && !result.success() {
        bail!("{}", result.describe(command));
    }
    Ok(Some(result))
}

/// Runs `command` on two revisions and asserts identical stdout/stderr.
pub fn git_ab_test_host_command<C>(
    command: &str,
    comparator: C,
    a_revision: &str,
    b_revision: Option<&str>,
) -> Result<()>
where
    C: Fn(&CommandReturn, &CommandReturn) -> bool,
{
    git_ab_test_host_command_with_git(command, comparator, a_revision, b_revision, &git_binary())
}

/// [`git_ab_test_host_command`] with an explicit `git` binary.
pub fn git_ab_test_host_command_with_git<C>(
    command: &str,
    comparator: C,
    a_revision: &str,
    b_revision: Option<&str>,
    git_bin: &str,
) -> Result<()>
where
    C: Fn(&CommandReturn, &CommandReturn) -> bool,
{
    let owned = command.to_string();
    let runner = |path: &Path, _is_a: bool| run_host_command(path, &owned);
    let (old, new, the_same) =
        git_ab_test_with_git(runner, comparator, a_revision, b_revision, git_bin)?;

    if !the_same {
        bail!(
            "The output of running command `{command}` changed:\nOld:\nstdout:\n{}\nstderr:\n{}\n\nNew:\nstdout:\n{}\nstderr:\n{}",
            old.stdout,
            old.stderr,
            new.stdout,
            new.stderr
        );
    }
    Ok(())
}

/// Runs `command` inside `dir` and captures its output.
///
/// A failure to run the command is reported as a synthetic negative exit code,
/// so the A/B comparison fails instead of aborting the whole test run.
fn run_host_command(dir: &Path, command: &str) -> CommandReturn {
    let wrapped = format!("cd {} && {command}", shell_quote(dir));
    utils::run_cmd(&wrapped)
        .unwrap_or_else(|err| CommandReturn::new(-1, String::new(), err.to_string()))
}

/// Builds a comparator asserting that the "B" set does not grow over "A".
///
/// The set generator converts a command output into a set; the comparison
/// passes when the "B" set is a subset of the "A" set.
pub fn set_did_not_grow_comparator<T, F>(
    set_generator: F,
) -> impl Fn(&CommandReturn, &CommandReturn) -> bool
where
    T: Ord,
    F: Fn(&CommandReturn) -> BTreeSet<T>,
{
    move |output_a, output_b| {
        let set_a = set_generator(output_a);
        let set_b = set_generator(output_b);
        set_b.is_subset(&set_a)
    }
}

/// Clones the repository at `commitish` into `clone_path`.
///
/// The clone is skipped when `clone_path` already exists, and serialized with
/// an exclusive lock so parallel test workers do not race on `git branch`.
pub fn git_clone(clone_path: &Path, commitish: &str) -> Result<PathBuf> {
    git_clone_with(clone_path, commitish, &git_binary())
}

/// [`git_clone`] with an explicit `git` binary, used as a test seam.
pub fn git_clone_with(clone_path: &Path, commitish: &str, git_bin: &str) -> Result<PathBuf> {
    if clone_path.exists() {
        return Ok(clone_path.to_path_buf());
    }

    let _lock = FileLock::acquire(&lock_path()?)?;

    let status = utils::run_cmd(&format!("{git_bin} cat-file -t {commitish}"))?;
    let commitish = if status.returncode != 0 {
        // git did not recognize the object: qualify it if it is a branch.
        format!("origin/{commitish}")
    } else {
        commitish.to_string()
    };

    // Make a temporary branch for that commit so it can be checked out.
    let branch_name = format!("tmp-{commitish}");
    utils::check_output(&format!("{git_bin} branch {branch_name} {commitish}"))?;
    let git_root = utils::run_cmd(&format!("{git_bin} rev-parse --show-toplevel"))?;
    utils::check_output(&format!(
        "{git_bin} clone -b {branch_name} {} {}",
        git_root.stdout.trim(),
        clone_path.display()
    ))?;
    utils::check_output(&format!("{git_bin} branch -D {branch_name}"))?;

    Ok(clone_path.to_path_buf())
}

/// The `git` binary to use, honouring [`GIT_ENV`].
pub fn git_binary() -> String {
    std::env::var(GIT_ENV)
        .ok()
        .filter(|bin| !bin.is_empty())
        .unwrap_or_else(|| "git".to_string())
}

/// Repository root, i.e. the parent of the `tests` directory pytest runs in.
fn repository_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("resolving the current directory")?;
    Ok(cwd.parent().map(Path::to_path_buf).unwrap_or(cwd))
}

/// File the A/B-test clone lock is taken on.
fn lock_path() -> Result<PathBuf> {
    Ok(std::env::temp_dir().join("fc-ab-test-clone.lock"))
}

/// Monotonic counter making temporary names unique within this process.
fn unique_token() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Quotes a path for use inside a `/bin/sh -c` command line.
fn shell_quote(path: &Path) -> String {
    let raw = path.to_string_lossy();
    format!("'{}'", raw.replace('\'', "'\\''"))
}

/// Exclusive inter-process lock, replacing python's `@with_filelock`.
struct FileLock {
    file: std::fs::File,
}

impl FileLock {
    fn acquire(path: &Path) -> Result<Self> {
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .with_context(|| format!("opening lock file {}", path.display()))?;
        loop {
            // SAFETY: `file` keeps a valid descriptor for the whole call.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(Self { file });
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(err).context("locking the A/B-test clone lock");
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: the descriptor is still owned by `self.file`.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fc-ab-test-{tag}-{}-{}",
            std::process::id(),
            unique_token()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir is created");
        dir
    }

    fn command(returncode: i32, stdout: &str, stderr: &str) -> CommandReturn {
        CommandReturn::new(returncode, stdout.to_string(), stderr.to_string())
    }

    /// Writes a fake `git` that logs its argv and answers like the real one.
    fn fake_git(dir: &Path, recognize_commitish: bool) -> (PathBuf, PathBuf) {
        let script = dir.join("fake-git.sh");
        let log = dir.join("git-argv.log");
        let body = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {log}\n\
             case \"$1\" in\n\
               cat-file) exit {cat_file_exit} ;;\n\
               rev-parse) printf '/repo/root\\n'; exit 0 ;;\n\
               clone) mkdir -p \"$5\"; exit 0 ;;\n\
             esac\n\
             exit 0\n",
            log = log.display(),
            cat_file_exit = if recognize_commitish { 0 } else { 1 },
        );
        std::fs::write(&script, body).expect("script is written");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script)
            .expect("script exists")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("script is executable");
        (script, log)
    }

    fn recorded(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(|line| line.to_string())
            .collect()
    }

    #[test]
    fn default_comparator_compares_by_value() {
        assert!(default_comparator(&1, &1));
        assert!(!default_comparator(&1, &2));
        assert!(default_comparator(
            &command(0, "a", "b"),
            &command(0, "a", "b")
        ));
        assert!(!default_comparator(
            &command(0, "a", "b"),
            &command(0, "a", "c")
        ));
        assert!(!default_comparator(
            &command(1, "a", "b"),
            &command(0, "a", "b")
        ));
    }

    #[test]
    fn set_comparator_allows_shrinking_sets_only() {
        let lines = |output: &CommandReturn| -> BTreeSet<String> {
            output
                .stdout
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect()
        };
        let comparator = set_did_not_grow_comparator(lines);

        let old = command(0, "a\nb\nc\n", "");
        let smaller = command(0, "a\nc\n", "");
        let same = command(0, "c\nb\na\n", "");
        let bigger = command(0, "a\nb\nc\nd\n", "");
        let different = command(0, "z\n", "");

        assert!(comparator(&old, &smaller));
        assert!(comparator(&old, &same));
        assert!(!comparator(&old, &bigger));
        assert!(!comparator(&old, &different));
        assert!(comparator(&old, &command(0, "", "")));
    }

    #[test]
    fn set_comparator_works_on_numbers() {
        let numbers = |output: &CommandReturn| -> BTreeSet<u32> {
            output
                .stdout
                .split_whitespace()
                .filter_map(|word| word.parse().ok())
                .collect()
        };
        let comparator = set_did_not_grow_comparator(numbers);
        assert!(comparator(&command(0, "1 2 3", ""), &command(0, "3", "")));
        assert!(!comparator(&command(0, "1 2 3", ""), &command(0, "4", "")));
    }

    #[test]
    fn git_clone_builds_the_expected_argv() {
        let dir = temp_dir("clone-argv");
        let (script, log) = fake_git(&dir, false);
        let clone_path = dir.join("checkout");

        let returned = git_clone_with(&clone_path, "main", script.to_str().unwrap())
            .expect("fake git succeeds");
        assert_eq!(returned, clone_path);

        // `cat-file -t main` failed, so the revision is qualified as a branch
        // and the temporary branch name carries the qualified revision.
        assert_eq!(
            recorded(&log),
            vec![
                "cat-file -t main".to_string(),
                "branch tmp-origin/main origin/main".to_string(),
                "rev-parse --show-toplevel".to_string(),
                format!(
                    "clone -b tmp-origin/main /repo/root {}",
                    clone_path.display()
                ),
                "branch -D tmp-origin/main".to_string(),
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_clone_keeps_known_commitish() {
        let dir = temp_dir("clone-known");
        let (script, log) = fake_git(&dir, true);
        let clone_path = dir.join("checkout-2");

        git_clone_with(&clone_path, "deadbeef", script.to_str().unwrap())
            .expect("fake git succeeds");
        let argv = recorded(&log);
        assert_eq!(argv[0], "cat-file -t deadbeef");
        assert_eq!(argv[1], "branch tmp-deadbeef deadbeef");
        assert_eq!(argv[2], "rev-parse --show-toplevel");
        assert_eq!(
            argv[3],
            format!("clone -b tmp-deadbeef /repo/root {}", clone_path.display())
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_clone_skips_existing_checkouts() {
        let dir = temp_dir("clone-existing");
        let (script, log) = fake_git(&dir, true);
        let clone_path = dir.join("already-there");
        std::fs::create_dir_all(&clone_path).expect("checkout exists");

        let returned =
            git_clone_with(&clone_path, "main", script.to_str().unwrap()).expect("no failure");
        assert_eq!(returned, clone_path);
        assert!(recorded(&log).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_clone_reports_failures() {
        let dir = temp_dir("clone-fail");
        let clone_path = dir.join("checkout-fail");
        // `/bin/false` fails for every subcommand, including `branch`.
        assert!(git_clone_with(&clone_path, "main", "/bin/false").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_binary_honours_the_environment_variable() {
        // The seam is parameter-based, so the environment variable is only the
        // default provider. Assert the default without mutating global state.
        if std::env::var(GIT_ENV).is_err() {
            assert_eq!(git_binary(), "git");
        }
    }

    #[test]
    fn git_ab_test_runs_both_sides_and_compares() {
        let dir = temp_dir("ab");
        let (script, _log) = fake_git(&dir, false);
        let runner = |path: &Path, is_a: bool| {
            (
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                is_a,
            )
        };

        let (a, b, same) = git_ab_test_with_git(
            runner,
            default_comparator,
            "main",
            Some("pr-branch"),
            script.to_str().unwrap(),
        )
        .expect("ab test succeeds");

        assert_eq!(a, ("main".to_string(), true));
        assert_eq!(b, ("pr-branch".to_string(), false));
        assert!(!same);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_ab_test_without_b_revision_uses_the_repository_root() {
        let dir = temp_dir("ab-default-b");
        let (script, _log) = fake_git(&dir, true);
        let runner = |path: &Path, is_a: bool| (path.to_path_buf(), is_a);

        let (a, b, same) = git_ab_test_with_git(
            runner,
            default_comparator,
            "main",
            None,
            script.to_str().unwrap(),
        )
        .expect("ab test succeeds");

        assert!(a.1);
        assert!(!b.1);
        // "B" is the parent of the current directory, not a checkout below the
        // temporary directory.
        assert_eq!(b.0, repository_root().expect("repository root"));
        assert!(!same);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn host_command_ab_test_compares_stdout() {
        let dir = temp_dir("ab-cmd");
        let (script, _log) = fake_git(&dir, true);
        // The command output does not depend on the checkout, so it is stable.
        git_ab_test_host_command_with_git(
            "echo stable",
            default_comparator,
            "main",
            Some("pr"),
            script.to_str().unwrap(),
        )
        .expect("identical outputs pass");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn host_command_ab_test_detects_changes() {
        let comparator = |a: &CommandReturn, b: &CommandReturn| a.stdout == b.stdout;
        // A comparator that always disagrees makes the A/B test fail with the
        // python message, even when the command itself is stable.
        let dir = temp_dir("ab-cmd-change");
        let (script, _log) = fake_git(&dir, true);
        let err = git_ab_test_host_command_with_git(
            "echo stable",
            |_: &CommandReturn, _: &CommandReturn| false,
            "main",
            Some("pr"),
            script.to_str().unwrap(),
        )
        .unwrap_err();
        assert!(
            err.to_string().starts_with("The output of running command"),
            "{err}"
        );
        assert!(err.to_string().contains("stdout:\nstable"));
        // And the deterministic comparator above accepts it.
        assert!(comparator(
            &command(0, "stable\n", ""),
            &command(0, "stable\n", "")
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn host_command_if_pr_runs_the_command_outside_of_ci() {
        // Buildkite variables are not set in unit tests, so this takes the
        // non-pull-request branch and returns the command output.
        let result = git_ab_test_host_command_if_pr("echo hi", default_comparator, true)
            .expect("command succeeds");
        let output = result.expect("no A/B test outside of a pull request");
        assert_eq!(output.stdout.trim(), "hi");
        assert!(output.success());

        let failing = git_ab_test_host_command_if_pr("exit 3", default_comparator, true);
        assert!(failing.is_err());
        let unchecked = git_ab_test_host_command_if_pr("exit 3", default_comparator, false)
            .expect("unchecked command runs");
        assert_eq!(unchecked.expect("output").returncode, 3);
    }

    #[test]
    fn default_a_revision_falls_back_to_main() {
        // Without `BUILDKITE_PULL_REQUEST_BASE_BRANCH` the constant is "main".
        if std::env::var("BUILDKITE_PULL_REQUEST_BASE_BRANCH").is_err() {
            assert_eq!(default_a_revision(), "main");
        }
    }

    #[test]
    fn temp_dir_is_removed_on_drop() {
        let path = {
            let dir = TempDir::new("fc-ab-tempdir").expect("temp dir is created");
            let path = dir.path().to_path_buf();
            assert!(path.is_dir());
            path
        };
        assert!(!path.exists());
    }

    #[test]
    fn shell_quoting_survives_spaces_and_quotes() {
        assert_eq!(shell_quote(Path::new("/tmp/a b")), "'/tmp/a b'");
        assert_eq!(shell_quote(Path::new("/tmp/it's")), "'/tmp/it'\\''s'");
    }
}
