// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Static and custom CPU templates, ported from
//! `tests/framework/utils_cpu_templates.py`.
//!
//! Python reads `global_props` (host kernel version, CPU vendor, codename) at
//! import time and derives module level catalogues from it. The port keeps the
//! selection pure: [`supported_cpu_templates`] and
//! [`supported_custom_cpu_templates`] take those three platform facts as
//! arguments, so the tables are testable on any host. `pin_cpu_template` has no
//! counterpart because it only builds a pytest marker.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::defs;

/// Static CPU templates available on Intel hosts.
pub const INTEL_TEMPLATES: [&str; 4] = ["C3", "T2", "T2CL", "T2S"];

/// Static CPU templates available on AMD hosts.
pub const AMD_TEMPLATES: [&str; 1] = ["T2A"];

/// Static CPU templates available on ARM hosts.
pub const ARM_TEMPLATES: [&str; 1] = ["V1N1"];

/// CPU vendors the template tables distinguish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    /// Intel.
    Intel,
    /// AMD.
    Amd,
    /// ARM.
    Arm,
    /// Anything else.
    Other,
}

impl CpuVendor {
    /// Parses a vendor name as spelled in `CpuVendor`'s python enum.
    pub fn from_name(name: &str) -> Self {
        match normalize_name(name).as_str() {
            "INTEL" => Self::Intel,
            "AMD" => Self::Amd,
            "ARM" | "AARCH64" => Self::Arm,
            _ => Self::Other,
        }
    }
}

/// CPU codenames the template tables distinguish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuCodename {
    /// Intel Cascade Lake.
    IntelCascadeLake,
    /// Intel Ice Lake.
    IntelIceLake,
    /// Intel Sapphire Rapids.
    IntelSapphireRapids,
    /// Intel Granite Rapids.
    IntelGraniteRapids,
    /// AMD Milan.
    AmdMilan,
    /// AMD Genoa (no template yet).
    AmdGenoa,
    /// ARM Neoverse N1.
    ArmNeoverseN1,
    /// ARM Neoverse V1.
    ArmNeoverseV1,
    /// ARM Neoverse V2.
    ArmNeoverseV2,
    /// ARM Neoverse V3 (no template yet).
    ArmNeoverseV3,
    /// Anything else.
    Other,
}

impl CpuCodename {
    /// Parses a codename as spelled in `CpuModel`'s python enum, e.g.
    /// `INTEL_CASCADELAKE` or `intel-cascadelake`.
    pub fn from_name(name: &str) -> Self {
        match normalize_name(name).as_str() {
            "INTEL_CASCADELAKE" => Self::IntelCascadeLake,
            "INTEL_ICELAKE" => Self::IntelIceLake,
            "INTEL_SAPPHIRE_RAPIDS" => Self::IntelSapphireRapids,
            "INTEL_GRANITE_RAPIDS" => Self::IntelGraniteRapids,
            "AMD_MILAN" => Self::AmdMilan,
            "AMD_GENOA" => Self::AmdGenoa,
            "ARM_NEOVERSE_N1" => Self::ArmNeoverseN1,
            "ARM_NEOVERSE_V1" => Self::ArmNeoverseV1,
            "ARM_NEOVERSE_V2" => Self::ArmNeoverseV2,
            "ARM_NEOVERSE_V3" => Self::ArmNeoverseV3,
            _ => Self::Other,
        }
    }
}

/// Upper-cases a name and maps separators to `_`, so `intel-cascadelake` and
/// `INTEL_CASCADELAKE` compare equal.
fn normalize_name(name: &str) -> String {
    name.trim()
        .replace('-', "_")
        .replace(' ', "_")
        .to_ascii_uppercase()
}

/// The host `major.minor` kernel version, as compared by the python tables.
pub fn host_linux_version_tuple() -> (u32, u32) {
    parse_linux_version(&defs::host_kernel_version(1))
}

/// Parses a `major.minor` string; missing components default to zero.
pub fn parse_linux_version(version: &str) -> (u32, u32) {
    let mut parts = version.trim().split('.');
    let major = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor)
}

/// `host_linux >= want` for `major.minor` tuples.
fn version_at_least(host_linux: (u32, u32), want: (u32, u32)) -> bool {
    host_linux >= want
}

/// Owned copy of a static template list.
fn owned(templates: &[&str]) -> Vec<String> {
    templates.iter().map(|name| (*name).to_string()).collect()
}

/// Owned, sorted copy of a static template list minus `excluded`, mirroring
/// `sorted(set(TEMPLATES) - {name})`.
fn owned_without(templates: &[&str], excluded: &str) -> Vec<String> {
    let mut names: Vec<String> = templates
        .iter()
        .filter(|name| **name != excluded)
        .map(|name| (*name).to_string())
        .collect();
    names.sort();
    names
}

fn owned_sorted(templates: &[&str]) -> Vec<String> {
    let mut names = owned(templates);
    names.sort();
    names
}

/// Returns the static CPU templates supported by the platform.
pub fn supported_cpu_templates(
    vendor: CpuVendor,
    codename: CpuCodename,
    host_linux: (u32, u32),
) -> Vec<String> {
    match (vendor, codename) {
        (CpuVendor::Intel, CpuCodename::IntelCascadeLake) => owned_sorted(&INTEL_TEMPLATES),
        (CpuVendor::Intel, CpuCodename::IntelIceLake) => owned_without(&INTEL_TEMPLATES, "T2S"),
        (CpuVendor::Amd, CpuCodename::AmdMilan) => owned_sorted(&AMD_TEMPLATES),
        (CpuVendor::Arm, CpuCodename::ArmNeoverseV1) if version_at_least(host_linux, (6, 1)) => {
            owned_sorted(&ARM_TEMPLATES)
        }
        _ => Vec::new(),
    }
}

/// Returns the custom CPU templates supported by the platform.
pub fn supported_custom_cpu_templates(
    vendor: CpuVendor,
    codename: CpuCodename,
    host_linux: (u32, u32),
) -> Vec<String> {
    match (vendor, codename) {
        (CpuVendor::Intel, CpuCodename::IntelCascadeLake) => owned_sorted(&INTEL_TEMPLATES),
        (CpuVendor::Intel, CpuCodename::IntelIceLake) => owned_without(&INTEL_TEMPLATES, "T2S"),
        (CpuVendor::Intel, CpuCodename::IntelSapphireRapids) => {
            // Intel AMX needs kernel 5.17+; KVM does not expose the CPUID range
            // below that.
            if version_at_least(host_linux, (5, 17)) {
                vec!["SPR_TO_T2_6.1".to_string()]
            } else {
                vec!["SPR_TO_T2_5.10".to_string()]
            }
        }
        (CpuVendor::Intel, CpuCodename::IntelGraniteRapids) => {
            if version_at_least(host_linux, (5, 17)) {
                vec!["GNR_TO_T2_6.1".to_string()]
            } else {
                vec!["GNR_TO_T2_5.10".to_string()]
            }
        }
        (CpuVendor::Amd, CpuCodename::AmdMilan) => owned_sorted(&AMD_TEMPLATES),
        (CpuVendor::Arm, CpuCodename::ArmNeoverseN1) if version_at_least(host_linux, (6, 1)) => {
            vec!["V1N1".to_string()]
        }
        (CpuVendor::Arm, CpuCodename::ArmNeoverseV1) if version_at_least(host_linux, (6, 1)) => {
            vec!["V1N1".to_string(), "AARCH64_WITH_SVE_AND_PAC".to_string()]
        }
        (CpuVendor::Arm, CpuCodename::ArmNeoverseV1) => {
            vec!["AARCH64_WITH_SVE_AND_PAC".to_string()]
        }
        (CpuVendor::Arm, CpuCodename::ArmNeoverseV2) => {
            vec!["AARCH64_WITH_SVE_AND_PAC".to_string()]
        }
        _ => Vec::new(),
    }
}

/// A CPU template value, replacing the pytest parameter dictionaries.
#[derive(Debug, Clone, PartialEq)]
pub enum CpuTemplate {
    /// No template at all (python `None`).
    None,
    /// A static template, referenced by name only.
    Static(String),
    /// A custom template: its name plus the JSON definition.
    Custom {
        /// Template name, e.g. `SPR_TO_T2_6.1`.
        name: String,
        /// Parsed template JSON.
        template: serde_json::Value,
    },
}

impl CpuTemplate {
    /// The template name, or `None` when no template is configured.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Static(name) => Some(name),
            Self::Custom { name, .. } => Some(name),
        }
    }
}

/// Returns the CPU template name, optionally prefixed with its kind.
pub fn get_cpu_template_name(cpu_template: &CpuTemplate, with_type: bool) -> String {
    match cpu_template {
        CpuTemplate::None => "None".to_string(),
        CpuTemplate::Static(name) => {
            if with_type {
                format!("static_{name}")
            } else {
                name.clone()
            }
        }
        CpuTemplate::Custom { name, .. } => {
            if with_type {
                format!("custom_{name}")
            } else {
                name.clone()
            }
        }
    }
}

/// Path of the JSON definition of the custom template `name`.
pub fn custom_cpu_template_path(name: &str) -> PathBuf {
    defs::workspace_dir()
        .join("tests")
        .join("data")
        .join("custom_cpu_templates")
        .join(format!("{name}.json"))
}

/// Loads the custom CPU template `name` from `tests/data/custom_cpu_templates`.
pub fn load_custom_cpu_template(name: &str) -> Result<CpuTemplate> {
    let path = custom_cpu_template_path(name);
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("reading custom CPU template {}", path.display()))?;
    let template: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("parsing custom CPU template {}", path.display()))?;
    Ok(CpuTemplate::Custom {
        name: name.to_string(),
        template,
    })
}

/// Static templates as parameter values (python `static_cpu_templates_params`).
pub fn static_cpu_templates(
    vendor: CpuVendor,
    codename: CpuCodename,
    host_linux: (u32, u32),
) -> Vec<CpuTemplate> {
    let mut names = supported_cpu_templates(vendor, codename, host_linux);
    names.sort();
    names.into_iter().map(CpuTemplate::Static).collect()
}

/// Custom templates as parameter values (python `custom_cpu_templates_params`).
pub fn custom_cpu_templates(
    vendor: CpuVendor,
    codename: CpuCodename,
    host_linux: (u32, u32),
) -> Result<Vec<CpuTemplate>> {
    let mut names = supported_custom_cpu_templates(vendor, codename, host_linux);
    names.sort();
    names
        .iter()
        .map(|name| load_custom_cpu_template(name))
        .collect()
}

/// The full template catalogue, starting with "no template"
/// (python `ALL_CPU_TEMPLATES`).
pub fn all_cpu_templates(
    vendor: CpuVendor,
    codename: CpuCodename,
    host_linux: (u32, u32),
) -> Result<Vec<CpuTemplate>> {
    let mut templates = vec![CpuTemplate::None];
    templates.extend(static_cpu_templates(vendor, codename, host_linux));
    templates.extend(custom_cpu_templates(vendor, codename, host_linux)?);
    Ok(templates)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODERN_LINUX: (u32, u32) = (6, 1);
    const OLD_LINUX: (u32, u32) = (5, 10);

    #[test]
    fn get_cpu_template_name_matches_python() {
        assert_eq!(get_cpu_template_name(&CpuTemplate::None, false), "None");
        assert_eq!(get_cpu_template_name(&CpuTemplate::None, true), "None");

        let static_tmpl = CpuTemplate::Static("T2CL".to_string());
        assert_eq!(get_cpu_template_name(&static_tmpl, false), "T2CL");
        assert_eq!(get_cpu_template_name(&static_tmpl, true), "static_T2CL");

        let custom = CpuTemplate::Custom {
            name: "SPR_TO_T2_6.1".to_string(),
            template: serde_json::json!({"name": "SPR_TO_T2_6.1"}),
        };
        assert_eq!(get_cpu_template_name(&custom, false), "SPR_TO_T2_6.1");
        assert_eq!(get_cpu_template_name(&custom, true), "custom_SPR_TO_T2_6.1");
        assert_eq!(custom.name(), Some("SPR_TO_T2_6.1"));
        assert_eq!(CpuTemplate::None.name(), None);
    }

    #[test]
    fn static_tables_follow_python_cases() {
        assert_eq!(
            supported_cpu_templates(
                CpuVendor::Intel,
                CpuCodename::IntelCascadeLake,
                MODERN_LINUX
            ),
            vec!["C3", "T2", "T2CL", "T2S"]
        );
        assert_eq!(
            supported_cpu_templates(CpuVendor::Intel, CpuCodename::IntelIceLake, MODERN_LINUX),
            vec!["C3", "T2", "T2CL"]
        );
        assert_eq!(
            supported_cpu_templates(CpuVendor::Amd, CpuCodename::AmdMilan, MODERN_LINUX),
            vec!["T2A"]
        );
        assert_eq!(
            supported_cpu_templates(CpuVendor::Arm, CpuCodename::ArmNeoverseV1, MODERN_LINUX),
            vec!["V1N1"]
        );
        assert!(
            supported_cpu_templates(CpuVendor::Arm, CpuCodename::ArmNeoverseV1, OLD_LINUX)
                .is_empty()
        );
    }

    #[test]
    fn custom_tables_follow_python_cases() {
        assert_eq!(
            supported_custom_cpu_templates(
                CpuVendor::Intel,
                CpuCodename::IntelSapphireRapids,
                MODERN_LINUX
            ),
            vec!["SPR_TO_T2_6.1"]
        );
        assert_eq!(
            supported_custom_cpu_templates(
                CpuVendor::Intel,
                CpuCodename::IntelSapphireRapids,
                OLD_LINUX
            ),
            vec!["SPR_TO_T2_5.10"]
        );
        assert_eq!(
            supported_custom_cpu_templates(
                CpuVendor::Intel,
                CpuCodename::IntelGraniteRapids,
                MODERN_LINUX
            ),
            vec!["GNR_TO_T2_6.1"]
        );
        assert_eq!(
            supported_custom_cpu_templates(
                CpuVendor::Arm,
                CpuCodename::ArmNeoverseN1,
                MODERN_LINUX
            ),
            vec!["V1N1"]
        );
        assert_eq!(
            supported_custom_cpu_templates(
                CpuVendor::Arm,
                CpuCodename::ArmNeoverseV1,
                MODERN_LINUX
            ),
            vec!["V1N1", "AARCH64_WITH_SVE_AND_PAC"]
        );
        assert_eq!(
            supported_custom_cpu_templates(CpuVendor::Arm, CpuCodename::ArmNeoverseV1, OLD_LINUX),
            vec!["AARCH64_WITH_SVE_AND_PAC"]
        );
        assert_eq!(
            supported_custom_cpu_templates(CpuVendor::Arm, CpuCodename::ArmNeoverseV2, OLD_LINUX),
            vec!["AARCH64_WITH_SVE_AND_PAC"]
        );
        assert!(supported_custom_cpu_templates(
            CpuVendor::Amd,
            CpuCodename::AmdGenoa,
            MODERN_LINUX
        )
        .is_empty());
        assert!(
            supported_custom_cpu_templates(CpuVendor::Other, CpuCodename::Other, MODERN_LINUX)
                .is_empty()
        );
    }

    #[test]
    fn version_parsing_and_comparison() {
        assert_eq!(parse_linux_version("6.1.0-1-amd64"), (6, 1));
        assert_eq!(parse_linux_version("5.17"), (5, 17));
        assert_eq!(parse_linux_version("6"), (6, 0));
        assert_eq!(parse_linux_version(""), (0, 0));
        assert!(version_at_least((6, 1), (6, 1)));
        assert!(!version_at_least((6, 0), (6, 1)));
        assert!(version_at_least((10, 0), (6, 1)));
        let host = host_linux_version_tuple();
        assert!(host.0 > 0, "host kernel major version detected");
    }

    #[test]
    fn names_normalize_like_the_python_enums() {
        assert_eq!(
            CpuVendor::from_name("Intel"),
            CpuVendor::Intel,
            "vendor names are case-insensitive"
        );
        assert_eq!(CpuVendor::from_name("aarch64"), CpuVendor::Arm);
        assert_eq!(CpuVendor::from_name("s390x"), CpuVendor::Other);
        assert_eq!(
            CpuCodename::from_name("intel-cascadelake"),
            CpuCodename::IntelCascadeLake
        );
        assert_eq!(
            CpuCodename::from_name("ARM_NEOVERSE_V2"),
            CpuCodename::ArmNeoverseV2
        );
        assert_eq!(CpuCodename::from_name("unknown"), CpuCodename::Other);
    }

    #[test]
    fn template_paths_point_into_tests_data() {
        let path = custom_cpu_template_path("SPR_TO_T2_6.1");
        assert!(path.ends_with("tests/data/custom_cpu_templates/SPR_TO_T2_6.1.json"));
    }
}
