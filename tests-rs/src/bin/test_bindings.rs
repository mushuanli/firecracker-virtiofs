// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust port of `tools/test_bindings.py`.
//!
//! Checks that the `bindgen`-generated structs of two Firecracker binaries have
//! the same layout. The script collects debug info with `pahole` (see
//! `man 1 pahole`), keeps only structs whose name contains `bindings` and
//! compares size (hard error) and alignment (warning) between the two binaries.
//!
//! ```text
//! {
//!     "struct_name": {"size": size_in_bytes, "alignment": alignment_in_bytes},
//!     ...
//! }
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use fc_harness::utils;
use regex::Regex;

/// Substring used to keep only `bindgen`-related structs.
const BINDINGS_FILTER: &str = "bindings";

/// Debug info of one struct, as reported by `pahole`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructInfo {
    /// Size in bytes.
    pub size: u64,
    /// Alignment in bytes.
    pub alignment: u64,
}

/// Per-struct outcome of comparing the old and the new binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructReport {
    /// The struct exists in the old binary but not in the new one. This does not
    /// break ABI compatibility, it only means new bindgen code is being used.
    Missing {
        /// Struct name.
        name: String,
    },
    /// The two binaries disagree on the struct size: a hard error.
    SizeMismatch {
        /// Struct name.
        name: String,
        /// Size in the old binary.
        old: u64,
        /// Size in the new binary.
        new: u64,
    },
    /// The two binaries disagree on the struct alignment: a warning only.
    AlignmentMismatch {
        /// Struct name.
        name: String,
        /// Alignment in the old binary.
        old: u64,
        /// Alignment in the new binary.
        new: u64,
    },
    /// Layout is identical.
    Matches {
        /// Struct name.
        name: String,
    },
}

/// Command line arguments, mirroring the python `argparse` definition.
#[derive(Debug, Parser)]
#[command(
    name = "fc-test-bindings",
    about = "Check bindings ABI compatibility for Firecracker"
)]
struct Cli {
    /// Firecracker binary with old bindings.
    #[arg(value_name = "old-firecracker-binary")]
    firecracker_old: PathBuf,

    /// Firecracker binary with new bindings.
    #[arg(value_name = "new-firecracker-binary")]
    firecracker_new: PathBuf,

    /// Restrict collection to this struct (repeatable). Defaults to the whole
    /// binary, like the python script.
    #[arg(short = 'C', long = "struct", value_name = "STRUCT")]
    structs: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    match check_pahole_mismatches(&cli.firecracker_old, &cli.firecracker_new, &cli.structs) {
        Ok(true) => {
            eprintln!("ERROR: Structure layout mismatch");
            std::process::exit(1);
        }
        Ok(false) => eprintln!("INFO: Structure layout matches"),
        Err(err) => {
            eprintln!("{err:#}");
            std::process::exit(1);
        }
    }
}

/// Builds the `pahole` argv, optionally restricted to a single struct.
pub fn pahole_args(binary: &Path, struct_name: Option<&str>) -> Vec<String> {
    let binary = binary.display().to_string();
    match struct_name {
        Some(name) => vec![
            "pahole".to_string(),
            "-C".to_string(),
            name.to_string(),
            binary,
        ],
        None => vec!["pahole".to_string(), binary],
    }
}

/// Runs `pahole` on `binary` and returns its stdout.
pub fn pahole(binary: &Path) -> Result<String> {
    let args = pahole_args(binary, None);
    let output = utils::run_cmd_args(&args)
        .with_context(|| format!("failed to run pahole on {}", binary.display()))?;
    if !output.success() {
        anyhow::bail!("{}", output.describe(&args.join(" ")));
    }
    Ok(output.stdout)
}

/// Runs `pahole -C <struct> <binary>` for every name in `names` and concatenates
/// the outputs. An empty `names` list collects the whole binary.
pub fn collect_pahole(binary: &Path, names: &[String]) -> Result<String> {
    if names.is_empty() {
        return pahole(binary);
    }

    let mut collected = String::new();
    for name in names {
        let args = pahole_args(binary, Some(name));
        let output = utils::run_cmd_args(&args)
            .with_context(|| format!("failed to run pahole on {}", binary.display()))?;
        if !output.success() {
            anyhow::bail!("{}", output.describe(&args.join(" ")));
        }
        collected.push_str(&output.stdout);
        if !collected.ends_with('\n') {
            collected.push('\n');
        }
    }
    Ok(collected)
}

/// Parses `pahole` output, keeping only structs whose name contains `bindings`.
pub fn parse_pahole(pahole_output: &str) -> Result<BTreeMap<String, StructInfo>> {
    // Same expression as the python script, including the `DOTALL` behaviour.
    let pattern = Regex::new(
        r"(?s)struct (.*?)\{.*?/\* size: (\d+).*?\*/.*?\n\} __attribute__\(\(__aligned__\((\d+)\)\)\);",
    )
    .context("invalid pahole regex")?;

    let mut structs = BTreeMap::new();
    for captures in pattern.captures_iter(pahole_output) {
        let name = captures
            .get(1)
            .map(|m| m.as_str().trim())
            .unwrap_or_default();
        if !name.contains(BINDINGS_FILTER) {
            continue;
        }

        let size = captures
            .get(2)
            .map(|m| m.as_str())
            .unwrap_or_default()
            .parse::<u64>()
            .with_context(|| format!("invalid size for struct '{name}'"))?;
        let alignment = captures
            .get(3)
            .map(|m| m.as_str())
            .unwrap_or_default()
            .parse::<u64>()
            .with_context(|| format!("invalid alignment for struct '{name}'"))?;

        structs.insert(name.to_string(), StructInfo { size, alignment });
    }

    Ok(structs)
}

/// Compares the structs of the old binary against the ones of the new binary.
///
/// A struct that only exists in the new binary is not reported: using a new
/// bindgen struct cannot break ABI compatibility.
pub fn compare_bindings(
    old: &BTreeMap<String, StructInfo>,
    new: &BTreeMap<String, StructInfo>,
) -> Vec<StructReport> {
    let mut reports = Vec::new();

    for (name, old_info) in old {
        let Some(new_info) = new.get(name) else {
            reports.push(StructReport::Missing { name: name.clone() });
            continue;
        };

        if old_info.size != new_info.size {
            reports.push(StructReport::SizeMismatch {
                name: name.clone(),
                old: old_info.size,
                new: new_info.size,
            });
            continue;
        }

        if old_info.alignment != new_info.alignment {
            reports.push(StructReport::AlignmentMismatch {
                name: name.clone(),
                old: old_info.alignment,
                new: new_info.alignment,
            });
            continue;
        }

        reports.push(StructReport::Matches { name: name.clone() });
    }

    reports
}

/// Returns `true` when a size mismatch was found, i.e. when the run must fail.
pub fn has_hard_mismatch(reports: &[StructReport]) -> bool {
    reports
        .iter()
        .any(|report| matches!(report, StructReport::SizeMismatch { .. }))
}

/// Renders the reports as `pahole`-style log lines (`ERROR:` / `WARNING:` /
/// `INFO:` prefixes replace python's `logging` formatting).
pub fn report_lines(reports: &[StructReport]) -> Vec<String> {
    let mut lines = Vec::new();
    for report in reports {
        match report {
            StructReport::Missing { name } => lines.push(format!(
                "WARNING: struct '{name}' does not exist in new binary"
            )),
            StructReport::SizeMismatch { name, old, new } => {
                lines.push(format!(
                    "ERROR: size of '{name}' does not match in two binaries"
                ));
                lines.push(format!("ERROR: old: {old}"));
                lines.push(format!("ERROR: new: {new}"));
            }
            StructReport::AlignmentMismatch { name, old, new } => {
                lines.push(format!(
                    "WARNING: alignment of '{name}' does not match in two binaries"
                ));
                lines.push(format!("WARNING: old: {old}"));
                lines.push(format!("WARNING: new: {new}"));
            }
            StructReport::Matches { name } => {
                lines.push(format!("INFO: struct '{name}' matches"));
            }
        }
    }
    lines
}

/// Collects, parses and compares both binaries. Prints the report lines on
/// stderr and returns `true` when the layouts are incompatible.
pub fn check_pahole_mismatches(old: &Path, new: &Path, structs: &[String]) -> Result<bool> {
    let old_structs = parse_pahole(&collect_pahole(old, structs)?)?;
    let new_structs = parse_pahole(&collect_pahole(new, structs)?)?;
    let reports = compare_bindings(&old_structs, &new_structs);

    for line in report_lines(&reports) {
        eprintln!("{line}");
    }

    Ok(has_hard_mismatch(&reports))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic `pahole` output: two bindgen structs with different
    /// alignments, one bindgen struct missing from the "new" sample and one
    /// non-bindgen struct that must be filtered out.
    const PAHOLE_OLD: &str = "\
struct firecracker_bindings::kvm_regs {
\tunsigned long long rax;         /*     0     8 */
\t/* size: 144, cachelines: 3, members: 18 */
\t/* padding: 0 */
} __attribute__((__aligned__(8)));
struct firecracker_bindings::kvm_sregs {
\tunsigned short cs_sel;          /*     0     2 */
\t/* size: 64, cachelines: 1, members: 8 */
} __attribute__((__aligned__(2)));
struct firecracker_bindings::old_only {
\tunsigned int field;             /*     0     4 */
\t/* size: 4, cachelines: 1, members: 1 */
} __attribute__((__aligned__(4)));
struct vmm::api::InstanceInfo {
\tunsigned int id;                /*     0     4 */
\t/* size: 4, cachelines: 1, members: 1 */
} __attribute__((__aligned__(4)));
";

    const PAHOLE_NEW: &str = "\
struct firecracker_bindings::kvm_regs {
\tunsigned long long rax;         /*     0     8 */
\t/* size: 144, cachelines: 3, members: 18 */
\t/* padding: 0 */
} __attribute__((__aligned__(8)));
struct firecracker_bindings::kvm_sregs {
\tunsigned short cs_sel;          /*     0     2 */
\t/* size: 64, cachelines: 1, members: 8 */
} __attribute__((__aligned__(4)));
struct firecracker_bindings::new_only {
\tunsigned long long field;       /*     0     8 */
\t/* size: 8, cachelines: 1, members: 1 */
} __attribute__((__aligned__(8)));
";

    #[test]
    fn pahole_args_without_struct_filter() {
        let args = pahole_args(Path::new("/tmp/firecracker_old"), None);
        assert_eq!(args, vec!["pahole", "/tmp/firecracker_old"]);
    }

    #[test]
    fn pahole_args_with_struct_filter() {
        let args = pahole_args(Path::new("/tmp/firecracker_old"), Some("kvm_regs"));
        assert_eq!(
            args,
            vec!["pahole", "-C", "kvm_regs", "/tmp/firecracker_old"]
        );
    }

    #[test]
    fn parses_sizes_and_alignments() {
        let structs = parse_pahole(PAHOLE_OLD).expect("synthetic output must parse");
        assert_eq!(structs.len(), 3, "non-bindgen structs are filtered out");
        assert_eq!(
            structs.get("firecracker_bindings::kvm_regs"),
            Some(&StructInfo {
                size: 144,
                alignment: 8
            })
        );
        assert_eq!(
            structs.get("firecracker_bindings::kvm_sregs"),
            Some(&StructInfo {
                size: 64,
                alignment: 2
            })
        );
        assert!(structs.contains_key("firecracker_bindings::old_only"));
        assert!(!structs.contains_key("vmm::api::InstanceInfo"));
    }

    #[test]
    fn empty_output_yields_no_structs() {
        assert!(parse_pahole("").expect("empty output parses").is_empty());
    }

    #[test]
    fn detects_alignment_mismatch_only_as_warning() {
        let old = parse_pahole(PAHOLE_OLD).expect("parses");
        let new = parse_pahole(PAHOLE_NEW).expect("parses");
        let reports = compare_bindings(&old, &new);

        assert!(!has_hard_mismatch(&reports));
        let mismatch = reports
            .iter()
            .find(|report| matches!(report, StructReport::AlignmentMismatch { .. }))
            .expect("alignment mismatch is reported");
        assert_eq!(
            mismatch,
            &StructReport::AlignmentMismatch {
                name: "firecracker_bindings::kvm_sregs".to_string(),
                old: 2,
                new: 4,
            }
        );
    }

    #[test]
    fn detects_size_mismatch_as_hard_error() {
        let mut new = parse_pahole(PAHOLE_OLD).expect("parses");
        new.insert(
            "firecracker_bindings::kvm_regs".to_string(),
            StructInfo {
                size: 152,
                alignment: 8,
            },
        );
        let old = parse_pahole(PAHOLE_OLD).expect("parses");
        let reports = compare_bindings(&old, &new);

        assert!(has_hard_mismatch(&reports));
        let lines = report_lines(&reports);
        assert!(lines.iter().any(|line| line
            == "ERROR: size of 'firecracker_bindings::kvm_regs' does not match in two binaries"));
        assert!(lines.iter().any(|line| line == "ERROR: old: 144"));
        assert!(lines.iter().any(|line| line == "ERROR: new: 152"));
    }

    #[test]
    fn structs_only_in_the_new_binary_are_ignored() {
        let old = parse_pahole(PAHOLE_OLD).expect("parses");
        let new = parse_pahole(PAHOLE_NEW).expect("parses");
        let reports = compare_bindings(&old, &new);

        assert!(!reports.iter().any(
            |report| matches!(report, StructReport::Missing { name } if name.ends_with("new_only"))
        ));
        assert!(reports.iter().any(
            |report| matches!(report, StructReport::Missing { name } if name.ends_with("old_only"))
        ));
    }

    #[test]
    fn matching_structs_are_reported_as_info() {
        let old = parse_pahole(PAHOLE_OLD).expect("parses");
        let reports = compare_bindings(&old, &old);
        let lines = report_lines(&reports);

        assert!(!has_hard_mismatch(&reports));
        assert!(lines
            .iter()
            .all(|line| line.starts_with("INFO: struct '") && line.ends_with("' matches")));
        assert_eq!(lines.len(), 3);
    }
}
