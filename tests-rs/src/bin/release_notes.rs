// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust port of `tools/release-notes.py`.
//!
//! Prints the `CHANGELOG.md` section of one version with the markdown stripped,
//! so the text can be pasted into a GitHub release body.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use fc_harness::defs;

/// Number of leading `CHANGELOG.md` lines holding the "keep a changelog"
/// metadata block. The python script skips them unconditionally.
const CHANGELOG_HEADER_LINES: usize = 7;

/// Command line arguments, mirroring `sys.argv[1]` of the python script.
#[derive(Debug, Parser)]
#[command(
    name = "fc-release-notes",
    about = "Print changelog of specified version with markdown stripped"
)]
struct Cli {
    /// Version whose changelog entry should be printed, e.g. `1.7.0`.
    version: String,
}

fn main() {
    let cli = Cli::parse();
    let changelog_path = defs::workspace_dir().join("CHANGELOG.md");

    let changelog = match read_changelog(&changelog_path) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("{err:#}");
            std::process::exit(1);
        }
    };

    match release_notes(&cli.version, &changelog) {
        Ok(section) => print!("{section}"),
        Err(err) => {
            // The python script prints this message on stdout and then exits
            // with status 1, so release tooling can capture it unchanged.
            println!("{err}");
            std::process::exit(1);
        }
    }
}

/// Reads the changelog file, adding the path to the error context.
pub fn read_changelog(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

/// Extracts the changelog section of `version` with the markdown stripped.
///
/// The lookup mirrors `tools/release-notes.py`: the first
/// [`CHANGELOG_HEADER_LINES`] lines are dropped, then everything between the
/// `## [<version>]` heading and the next `## [` heading is emitted. Heading
/// markers (`#`) and bullet markers (`-` -> `*`) are stripped so the result is
/// plain text.
pub fn release_notes(version: &str, changelog: &str) -> Result<String> {
    let mut lines = changelog.split_inclusive('\n').skip(CHANGELOG_HEADER_LINES);
    let start_marker = format!("## [{version}]");

    let mut found = false;
    for line in &mut lines {
        if line.starts_with(&start_marker) {
            found = true;
            break;
        }
    }

    if !found {
        return Err(anyhow!(
            "Could not find changelog entry for version {version}!"
        ));
    }

    let mut section = String::new();
    for line in lines {
        if line.starts_with("## [") {
            break;
        }
        section.push_str(&strip_markdown(line));
    }

    Ok(section)
}

/// Strips one line of markdown: leading `#` heading markers and the `-` bullet
/// marker. Everything else is preserved, including the trailing newline.
pub fn strip_markdown(line: &str) -> String {
    let mut stripped = line.to_string();

    if stripped.starts_with('#') {
        stripped = stripped.trim_start_matches('#').trim_start().to_string();
    }

    if stripped.starts_with('-') {
        stripped = stripped.replacen('-', "*", 1);
    }

    stripped
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic changelog: a 7-line "keep a changelog" header followed by two
    /// version sections and an unreleased section.
    const CHANGELOG: &str = "# Changelog\n\
\n\
All notable changes to this project will be documented in this file.\n\
\n\
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),\n\
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).\n\
\n\
## [Unreleased]\n\
\n\
### Added\n\
\n\
- Unreleased thing.\n\
\n\
## [1.7.0]\n\
\n\
### Added\n\
\n\
- Added `--new-flag`.\n\
- Fixed a thing in the snapshot path.\n\
\n\
### Fixed\n\
\n\
- Nothing.\n\
\n\
## [1.6.0]\n\
\n\
### Added\n\
\n\
- Older entry that must not leak into 1.7.0.\n";

    #[test]
    fn header_is_skipped() {
        // A heading that only exists inside the 7 skipped lines is not found.
        let header_only = "# Changelog\n\
## [0.0.1]\n\
\n\
All notable changes.\n\
\n\
The format is based.\n\
and this project adheres.\n\
\n\
## [1.0.0]\n\
\n\
- Something.\n";
        assert!(release_notes("0.0.1", header_only).is_err());
        assert_eq!(
            release_notes("1.0.0", header_only).expect("1.0.0 is present"),
            // The blank line after the version heading is part of the section,
            // exactly like the python script prints it.
            "\n* Something.\n"
        );
    }

    #[test]
    fn extracts_requested_section_only() {
        let section = release_notes("1.7.0", CHANGELOG).expect("1.7.0 is present");
        assert!(section.contains("Added `--new-flag`."));
        assert!(section.contains("Fixed a thing in the snapshot path."));
        assert!(!section.contains("Older entry"));
        assert!(!section.contains("Unreleased thing"));
    }

    #[test]
    fn strips_headings_and_bullets() {
        let section = release_notes("1.7.0", CHANGELOG).expect("1.7.0 is present");
        assert!(!section.contains('#'), "headings must be stripped");
        assert!(!section.contains("- "), "bullets must become asterisks");
        assert_eq!(
            section,
            concat!(
                "\n",
                "Added\n",
                "\n",
                "* Added `--new-flag`.\n",
                "* Fixed a thing in the snapshot path.\n",
                "\n",
                "Fixed\n",
                "\n",
                "* Nothing.\n",
                "\n",
            )
        );
    }

    #[test]
    fn section_ends_at_next_version() {
        let section = release_notes("1.6.0", CHANGELOG).expect("1.6.0 is present");
        assert_eq!(
            section,
            "\nAdded\n\n* Older entry that must not leak into 1.7.0.\n"
        );
    }

    #[test]
    fn missing_version_reports_the_python_message() {
        let err = release_notes("9.9.9", CHANGELOG).expect_err("9.9.9 is absent");
        assert_eq!(
            err.to_string(),
            "Could not find changelog entry for version 9.9.9!"
        );
    }

    #[test]
    fn strip_markdown_helpers() {
        assert_eq!(strip_markdown("### Added\n"), "Added\n");
        assert_eq!(strip_markdown("#Headline\n"), "Headline\n");
        assert_eq!(strip_markdown("- item\n"), "* item\n");
        assert_eq!(strip_markdown("plain text\n"), "plain text\n");
        assert_eq!(strip_markdown("\n"), "\n");
    }

    #[test]
    fn header_layout_matches_the_skip() {
        // Guards the constant against the upstream header layout: 7 metadata
        // lines, then the first version heading.
        let header: Vec<&str> = CHANGELOG.split_inclusive('\n').take(8).collect();
        assert_eq!(header.len(), 8);
        assert!(header[CHANGELOG_HEADER_LINES].starts_with("## ["));
    }
}
