// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Buildkite pipeline generation, ported from `.buildkite/common.py`,
//! `.buildkite/pipeline_cross.py`, `.buildkite/pipeline_perf.py` and
//! `.buildkite/pipeline_cpu_template.py`.
//!
//! Python builds the pipelines as nested dicts and `json.dumps` them; here the
//! same structure is built with [`serde_json::Value`], so overlays, step
//! fan-out and the emitted JSON stay comparable with the python output. The
//! `devtool test` invocations are byte-identical, which is what the pytest
//! command lines in CI depend on.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rand::Rng;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::utils;

/// Instances the pipelines fan out over by default.
pub const DEFAULT_INSTANCES: [&str; 13] = [
    "m5n.metal",      // Intel Cascade Lake
    "m6i.metal",      // Intel Ice Lake
    "m7i.metal-24xl", // Intel Sapphire Rapids
    "m7i.metal-48xl", // Intel Sapphire Rapids
    "m8i.metal-48xl", // Intel Granite Rapids
    "m8i.metal-96xl", // Intel Granite Rapids
    "m6a.metal",      // AMD Milan
    "m7a.metal-48xl", // AMD Genoa
    "m6g.metal",      // Graviton2
    "m7g.metal",      // Graviton3
    "m8g.metal-24xl", // Graviton4 1 socket
    "m8g.metal-48xl", // Graviton4 2 sockets
    "m9g.metal-48xl", // Graviton5
];

/// Default `(os, kernel version)` platforms.
pub const DEFAULT_PLATFORMS: [(&str, &str); 3] = [
    ("al2", "linux_5.10"),
    ("al2023", "linux_6.1"),
    ("al2023", "linux_6.18"),
];

/// Default number of A/B iterations of the performance tests.
pub const A_B_TEST_DEFAULT_MAX_ITERATIONS: u32 = 4;

/// Auto-retry policy shared by every step.
pub fn default_retry() -> Value {
    json!({
        "automatic": [
            // Never retry timeouts, regardless of exit status.
            {"signal_reason": "cancel", "limit": 0},
            // Retry once when Buildkite lost contact with the agent.
            {"exit_status": -1, "limit": 1},
        ],
    })
}

/// Architecture of an instance, from the Graviton/Intel/AMD naming scheme.
pub fn get_arch_for_instance(instance: &str) -> &'static str {
    match instance.chars().nth(2) {
        Some('g') => "aarch64",
        _ => "x86_64",
    }
}

/// Recursively overlays `update` on top of `base`, returning a new value.
pub fn overlay_dict(base: &Value, update: &Value) -> Value {
    let (Some(base_map), Some(update_map)) = (base.as_object(), update.as_object()) else {
        return update.clone();
    };
    let mut result = base_map.clone();
    for (key, value) in update_map {
        let merged = match (result.get(key), value) {
            (Some(existing), Value::Object(_)) => overlay_dict(existing, value),
            _ => value.clone(),
        };
        result.insert(key.clone(), merged);
    }
    Value::Object(result)
}

/// Interpolates `{name}` placeholders of `field` with the values in `args`.
///
/// Non-string fields are returned unchanged, like `common.py`'s `field_fmt`.
/// Unknown placeholders are left in place instead of raising `KeyError`.
pub fn field_fmt(field: &Value, args: &Map<String, Value>) -> Value {
    match field {
        Value::String(template) => Value::String(format_template(template, args)),
        other => other.clone(),
    }
}

/// Applies [`field_fmt`] over a whole (nested) object.
pub fn dict_fmt(template: &Value, args: &Map<String, Value>) -> Value {
    match template {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| match value {
                    Value::Object(_) => (key.clone(), dict_fmt(value, args)),
                    _ => (key.clone(), field_fmt(value, args)),
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Interpolates `{name}` placeholders using the string values of `args`.
pub fn format_template(template: &str, args: &Map<String, Value>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end_offset) = rest[start..].find('}') else {
            break;
        };
        let end = start + end_offset;
        let name = &rest[start + 1..end];
        match args.get(name) {
            Some(Value::String(value)) => {
                out.push_str(&rest[..start]);
                out.push_str(value);
                rest = &rest[end + 1..];
            }
            // Leave unknown or non-string placeholders untouched.
            _ => {
                out.push_str(&rest[..=end]);
                rest = &rest[end + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Generates one group step per instance/platform combination.
///
/// Every generated step gets a `command` (interpolated), a `label` and its
/// `agents`; `kwargs` is interpolated and overlaid on top of those fields.
pub fn group(
    label: &str,
    commands: &[String],
    instances: &[String],
    platforms: &[(String, String)],
    kwargs: &Value,
) -> Value {
    let mut steps = Vec::new();
    for instance in instances {
        for (os, kv) in platforms {
            let mut args = Map::new();
            args.insert("instance".to_string(), json!(instance));
            args.insert("os".to_string(), json!(os));
            args.insert("kv".to_string(), json!(kv));

            let commands = commands
                .iter()
                .map(|command| json!(format_template(command, &args)))
                .collect::<Vec<_>>();
            let mut step = Map::new();
            step.insert("command".to_string(), Value::Array(commands));
            step.insert(
                "label".to_string(),
                json!(format!("{label}-{instance}-{os}-{kv}")),
            );
            step.insert("agents".to_string(), Value::Object(args.clone()));

            let step_kwargs = dict_fmt(kwargs, &args);
            steps.push(overlay_dict(&step_kwargs, &Value::Object(step)));
        }
    }
    json!({"group": label, "steps": steps})
}

/// Arguments shared by all pipeline generators (`common.py`'s parser).
#[derive(Debug, Clone)]
pub struct PipelineArgs {
    /// Instances to fan out over.
    pub instances: Vec<String>,
    /// `(os, kernel version)` platforms to fan out over.
    pub platforms: Vec<(String, String)>,
    /// Extra parameters added to every step, as a nested object.
    pub step_param: Value,
    /// Directory with pre-built Firecracker binaries.
    pub binary_dir: Option<String>,
    /// S3 URI with pre-built Firecracker binaries.
    pub artifacts: Option<String>,
    /// Whether the `kani` step is skipped.
    pub no_kani: bool,
    /// Number of parallel test instances per step.
    pub parallelism: u64,
    /// Maximum leaf jobs per pipeline chunk; chunks the JSON output when set.
    pub max_jobs: Option<usize>,
}

impl Default for PipelineArgs {
    fn default() -> Self {
        Self {
            instances: DEFAULT_INSTANCES.iter().map(|i| (*i).to_string()).collect(),
            platforms: DEFAULT_PLATFORMS
                .iter()
                .map(|(os, kv)| ((*os).to_string(), (*kv).to_string()))
                .collect(),
            step_param: json!({}),
            binary_dir: None,
            artifacts: std::env::var("ARTIFACTS_OVERRIDE").ok(),
            no_kani: false,
            parallelism: 1,
            max_jobs: None,
        }
    }
}

impl PipelineArgs {
    /// Arguments as the CI scripts receive them on the command line.
    pub fn from_cli() -> Result<Self> {
        PipelineCli::parse().to_args()
    }
}

/// Command line interface of the pipeline generators.
#[derive(Debug, Clone, clap::Parser)]
#[command(about = "Generate a Buildkite pipeline for the Firecracker test suite")]
pub struct PipelineCli {
    /// Instances to run on; defaults to the standard instance list.
    #[arg(long, num_args = 1.., value_name = "INSTANCE")]
    pub instances: Vec<String>,
    /// Platforms as `OS-KV`; defaults to the standard platform list.
    #[arg(long, num_args = 1.., value_name = "OS-KV")]
    pub platforms: Vec<String>,
    /// Parameters added to every step, `a/b/c=3` style.
    #[arg(long = "step-param", value_name = "PARAM=VALUE")]
    pub step_param: Vec<String>,
    /// Use the Firecracker binaries from this path.
    #[arg(long, value_name = "PATH")]
    pub binary_dir: Option<String>,
    /// Use the Firecracker binaries from this S3 uri.
    #[arg(long, value_name = "S3_URI")]
    pub artifacts: Option<String>,
    /// Do not add the kani step.
    #[arg(long)]
    pub no_kani: bool,
    /// How many instances of each test to create.
    #[arg(long, default_value_t = 1)]
    pub parallelism: u64,
    /// Maximum leaf jobs per pipeline chunk; emits a JSON array when set.
    #[arg(long)]
    pub max_jobs: Option<usize>,
}

impl PipelineCli {
    /// Converts the parsed flags into [`PipelineArgs`].
    pub fn to_args(&self) -> Result<PipelineArgs> {
        let defaults = PipelineArgs::default();
        let platforms = if self.platforms.is_empty() {
            defaults.platforms
        } else {
            self.platforms
                .iter()
                .map(|spec| parse_platform(spec))
                .collect::<Result<Vec<_>>>()?
        };

        let mut step_param = json!({});
        for spec in &self.step_param {
            step_param = overlay_dict(&step_param, &parse_step_param(spec)?);
        }

        Ok(PipelineArgs {
            instances: if self.instances.is_empty() {
                defaults.instances
            } else {
                self.instances.clone()
            },
            platforms,
            step_param,
            binary_dir: self.binary_dir.clone(),
            artifacts: self.artifacts.clone().or(defaults.artifacts),
            no_kani: self.no_kani,
            parallelism: self.parallelism,
            max_jobs: self.max_jobs,
        })
    }
}

/// Parses one `--platforms` value (`al2023-linux_6.1`) into `(os, kv)`.
pub fn parse_platform(spec: &str) -> Result<(String, String)> {
    match spec.split_once('-') {
        Some((os, kv)) if !os.is_empty() && !kv.is_empty() => Ok((os.to_string(), kv.to_string())),
        _ => bail!("platform must have the form OS-KV, got '{spec}'"),
    }
}

/// Parses one `--step-param a/b/c=3` value into a nested object.
///
/// Values starting like a python literal (`[`, `{`, `'`) are interpreted as
/// literals; everything else stays a string.
pub fn parse_step_param(spec: &str) -> Result<Value> {
    let (key_str, raw_value) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("step parameter must have the form PARAM=VALUE, got '{spec}'"))?;

    let mut keys = key_str.split('/').collect::<Vec<_>>();
    let leaf = keys
        .pop()
        .filter(|leaf| !leaf.is_empty())
        .ok_or_else(|| anyhow!("step parameter must have the form PARAM=VALUE, got '{spec}'"))?;

    let mut update = Map::new();
    update.insert(leaf.to_string(), literal_value(raw_value));
    for key in keys.into_iter().rev() {
        if key.is_empty() {
            bail!("step parameter path has an empty component: '{spec}'");
        }
        let mut wrapper = Map::new();
        wrapper.insert(key.to_string(), Value::Object(update));
        update = wrapper;
    }
    Ok(Value::Object(update))
}

/// Interprets a `--step-param` value the way `ast.literal_eval` would.
fn literal_value(raw: &str) -> Value {
    match raw.chars().next() {
        Some('[') | Some('{') => {
            serde_json::from_str::<Value>(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
        }
        Some('\'') => Value::String(raw.trim_matches('\'').to_string()),
        _ => Value::String(raw.to_string()),
    }
}

/// Random hex string of `k` characters, like `random.choices(hexdigits)`.
pub fn random_str(k: usize) -> String {
    const HEXDIGITS: &[u8] = b"0123456789abcdefABCDEF";
    let mut rng = rand::thread_rng();
    (0..k)
        .map(|_| HEXDIGITS[rng.gen_range(0..HEXDIGITS.len())] as char)
        .collect()
}

/// Steps building an A/B-test revision.
pub fn ab_revision_build(revision: &str) -> Vec<String> {
    vec![format!(
        "./tools/devtool -y build --rev {revision} --release"
    )]
}

/// Environment inputs of [`shared_build`].
#[derive(Debug, Clone, Default)]
pub struct BuildEnv {
    /// `REVISION_A`, set by the A/B-test pipelines.
    pub revision_a: Option<String>,
    /// `REVISION_B`, set by the A/B-test pipelines.
    pub revision_b: Option<String>,
    /// Base branch of a pull request build, `None` outside of pull requests.
    pub pull_request_base: Option<String>,
}

impl BuildEnv {
    /// Reads the build environment variables of the current process.
    pub fn from_env() -> Self {
        let pull_request_base = match std::env::var("BUILDKITE_PULL_REQUEST") {
            Ok(value) if value != "false" => Some(
                std::env::var("BUILDKITE_PULL_REQUEST_BASE_BRANCH")
                    .unwrap_or_else(|_| "main".to_string()),
            ),
            _ => None,
        };
        Self {
            revision_a: std::env::var("REVISION_A").ok(),
            revision_b: std::env::var("REVISION_B").ok(),
            pull_request_base,
        }
    }
}

/// Build commands and artifact name shared by a whole Buildkite build.
///
/// Covers the three supported scenarios: nightly (compile HEAD of main),
/// pull request (compile the base and the PR HEAD) and A/B pipeline (compile
/// `REVISION_A`/`REVISION_B`).
pub fn shared_build() -> Result<(Vec<String>, String)> {
    shared_build_with(&BuildEnv::from_env(), &random_str(8))
}

/// [`shared_build`] with explicit environment inputs and artifact suffix.
pub fn shared_build_with(env: &BuildEnv, suffix: &str) -> Result<(Vec<String>, String)> {
    let mut build_cmds = match (&env.revision_a, &env.pull_request_base) {
        (Some(revision_a), _) => {
            let revision_b = env
                .revision_b
                .as_deref()
                .ok_or_else(|| anyhow!("REVISION_B environment variable not set"))?;
            let mut cmds = ab_revision_build(revision_a);
            if revision_a != revision_b {
                cmds.extend(ab_revision_build(revision_b));
            }
            cmds
        }
        (None, Some(base)) => {
            let mut cmds = ab_revision_build(base);
            cmds.push("./tools/devtool -y build --release".to_string());
            cmds
        }
        (None, None) => vec!["./tools/devtool -y build --release".to_string()],
    };

    let binary_dir = format!("build_$(uname -m)_{suffix}.tar.gz");
    build_cmds.extend([
        "du -sh build/*".to_string(),
        format!("tar czf {binary_dir} build"),
        format!("buildkite-agent artifact upload {binary_dir}"),
    ]);
    Ok((build_cmds, binary_dir))
}

/// Retags the `kv` agent tag of every step matching a pin.
///
/// `pins` maps the new `kv` value to the agent fields it matches, e.g.
/// `{"linux_6.1-pinned": {"instance": "m6i.metal", "kv": "linux_6.1"}}`.
pub fn apply_pins(steps: &[Value], pins: &Value) -> Vec<Value> {
    let pins = pins.as_object().cloned().unwrap_or_default();
    steps
        .iter()
        .map(|step| {
            let mut step = step.clone();
            if step.get("group").is_some() {
                if let Some(inner) = step.get("steps").and_then(Value::as_array) {
                    let pinned = apply_pins(inner, &Value::Object(pins.clone()));
                    step["steps"] = Value::Array(pinned);
                }
                return step;
            }
            if step.is_string() {
                return step;
            }
            let agents = step
                .get("agents")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            for (new_kv, matcher) in pins.iter() {
                let matches = matcher
                    .as_object()
                    .map(|fields| {
                        fields.iter().all(|(key, value)| {
                            agents
                                .get(key)
                                .map(|actual| actual == value)
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
                if matches {
                    step["agents"]["kv"] = json!(new_kv);
                    break;
                }
            }
            step
        })
        .collect()
}

/// Files changed in this pull request; empty outside of a pull request.
pub fn get_changed_files() -> Result<Vec<PathBuf>> {
    match std::env::var("BUILDKITE_PULL_REQUEST") {
        Ok(value) if value != "false" => {}
        _ => return Ok(Vec::new()),
    }

    let branch =
        std::env::var("BUILDKITE_PULL_REQUEST_BASE_BRANCH").unwrap_or_else(|_| "main".to_string());
    let output = utils::check_output(&format!("git diff --name-only origin/{branch}"))?;
    Ok(output
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect())
}

/// Whether the whole test suite has to run, given the changed files.
pub fn run_all_tests(changed_files: &[PathBuf]) -> bool {
    if changed_files.is_empty() {
        return true;
    }
    changed_files.iter().any(|path| {
        let suffix = path.extension().and_then(|ext| ext.to_str());
        let in_github = path
            .components()
            .next()
            .map(|first| first.as_os_str() == ".github")
            .unwrap_or(false);
        suffix != Some("md") && !(in_github && suffix == Some("yml"))
    })
}

/// Which half of the CI guest artifacts a pull request touches.
///
/// Returns `"all"` when `resources/rebuild.sh` or both halves changed,
/// `"rootfs"`/`"kernels"` when only one half changed, and `None` when no
/// artifact source changed.
pub fn ci_artifacts_change_mode(changed_files: &[PathBuf]) -> Option<&'static str> {
    let mut rootfs_changed = false;
    let mut kernel_changed = false;
    let mut rebuild_all = false;

    for path in changed_files {
        let parts = path
            .iter()
            .map(|part| part.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == "rebuild.sh" && parts.first().map(String::as_str) == Some("resources") {
            rebuild_all = true;
        } else if parts.len() >= 2 && parts[0] == "resources" && parts[1] == "rootfs" {
            rootfs_changed = true;
        } else if parts.len() >= 2
            && parts[0] == "resources"
            && (parts[1] == "guest_configs" || parts[1] == "patches")
        {
            kernel_changed = true;
        }
    }

    if rebuild_all || (rootfs_changed && kernel_changed) {
        Some("all")
    } else if rootfs_changed {
        Some("rootfs")
    } else if kernel_changed {
        Some("kernels")
    } else {
        None
    }
}

/// Buildkite pipeline builder, mirroring `common.py`'s `BKPipeline`.
#[derive(Debug, Clone)]
pub struct BKPipeline {
    /// Steps added to the pipeline so far.
    pub steps: Vec<Value>,
    /// Parsed common arguments.
    pub args: PipelineArgs,
    /// Per-instance step defaults.
    pub per_instance: Value,
    /// Per-architecture step defaults.
    pub per_arch: Value,
    /// Name of the shared build artifact, when a build step was added.
    pub shared_build: Option<String>,
    /// Binary directory taken from the command line.
    pub binary_dir: Option<String>,
    /// Artifacts S3 URI taken from the command line.
    pub artifacts: Option<String>,
}

impl BKPipeline {
    /// Creates a pipeline, adding the shared build step unless one is supplied.
    pub fn new(args: PipelineArgs, with_build_step: bool, kwargs: &Value) -> Result<Self> {
        let retry = overlay_dict(&default_retry(), kwargs.get("retry").unwrap_or(&json!({})));

        let mut per_instance = json!({
            "instances": args.instances,
            "platforms": args.platforms,
            "artifact_paths": ["./test_results/**/*"],
            "retry": retry,
        });
        if kwargs.as_object().is_some() {
            per_instance = overlay_dict(&per_instance, kwargs);
        }
        let per_instance = overlay_dict(&per_instance, &args.step_param);

        let per_arch = overlay_dict(
            &per_instance,
            &json!({
                "instances": ["m6i.metal", "m7g.metal"],
                "platforms": [["al2023", "linux_6.1"]],
            }),
        );

        let mut pipeline = Self {
            steps: Vec::new(),
            shared_build: None,
            binary_dir: args.binary_dir.clone(),
            artifacts: args.artifacts.clone(),
            args,
            per_instance,
            per_arch,
        };

        if pipeline.binary_dir.is_none() && with_build_step {
            let (build_cmds, shared_build) = shared_build()?;
            pipeline.shared_build = Some(shared_build.clone());
            pipeline.build_group_per_arch(
                "build",
                &build_cmds,
                false,
                Some(&shared_build),
                &json!({}),
            )?;
        }

        Ok(pipeline)
    }

    /// Adds a step to the pipeline, injecting the shared-build commands.
    ///
    /// Returns the index of the added step: python returns the (mutable) dict,
    /// which Rust callers reach through [`BKPipeline::step_mut`].
    pub fn add_step(&mut self, step: Value, depends_on_build: bool) -> Result<usize> {
        let step = if depends_on_build && step.as_object().is_some() {
            self.adapt_group(step)?
        } else {
            step
        };
        self.steps.push(step);
        Ok(self.steps.len() - 1)
    }

    /// Mutable access to an added step.
    pub fn step_mut(&mut self, index: usize) -> Result<&mut Value> {
        self.steps
            .get_mut(index)
            .ok_or_else(|| anyhow!("step {index} does not exist"))
    }

    /// Prepends the build-sharing commands and dependencies to a group.
    fn adapt_group(&self, mut group: Value) -> Result<Value> {
        let mut prepend: Vec<Value> = Vec::new();
        if let Some(shared_build) = &self.shared_build {
            prepend.push(json!(format!(
                "buildkite-agent artifact download \"{shared_build}\" ."
            )));
            prepend.push(json!(format!("tar xzf {shared_build}")));
        }
        if let Some(binary_dir) = &self.binary_dir {
            prepend.push(json!(format!(
                "buildkite-agent artifact download \"{binary_dir}/$(uname -m)/*\" ."
            )));
            prepend.push(json!(format!("chmod -v a+x {binary_dir}/**/*")));
        }

        let steps = group
            .get_mut("steps")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("group step has no 'steps' array"))?;

        for step in steps.iter_mut() {
            let mut command = prepend.clone();
            match step.get("command") {
                Some(Value::Array(existing)) => command.extend(existing.iter().cloned()),
                Some(Value::String(existing)) => command.push(json!(existing)),
                _ => {}
            }
            step["command"] = Value::Array(command);

            let Some(shared_build) = &self.shared_build else {
                continue;
            };

            let instance = step
                .pointer("/agents/instance")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("step has no agents.instance"))?
                .to_string();
            let arch = get_arch_for_instance(&instance);

            let mut dependencies = match step.get("depends_on") {
                None => Vec::new(),
                Some(Value::String(dep)) => vec![dep.clone()],
                Some(Value::Array(deps)) => deps
                    .iter()
                    .map(|dep| dep.as_str().unwrap_or_default().to_string())
                    .collect(),
                Some(other) => bail!("depends_on should be a string or a list but is {other}"),
            };
            dependencies.push(shared_build.clone());
            step["depends_on"] = Value::Array(
                dependencies
                    .iter()
                    .map(|dep| json!(self.build_key(dep, arch)))
                    .collect(),
            );
        }

        Ok(group)
    }

    /// Builds a group step, parametrizing over instances and platforms.
    ///
    /// `kwargs` must contain `label` and `command`; `instances`/`platforms`
    /// default to the pipeline-wide selection.
    pub fn build_group(&mut self, kwargs: &Value, depends_on_build: bool) -> Result<usize> {
        let mut combined = overlay_dict(&self.per_instance, kwargs);
        combined["parallelism"] = json!(self.args.parallelism);

        let label = combined
            .get("label")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("group step needs a label"))?
            .to_string();
        let commands = to_commands(combined.get("command"))?;
        let instances = to_instances(combined.get("instances"))?;
        let platforms = to_platforms(combined.get("platforms"))?;
        let step_kwargs = step_kwargs(&combined);

        let grp = group(&label, &commands, &instances, &platforms, &step_kwargs);
        self.add_step(grp, depends_on_build)
    }

    /// Buildkite key of a build step, for the given architecture.
    pub fn build_key(&self, key: &str, arch: &str) -> String {
        key.replace("$(uname -m)", arch).replace(".tar.gz", "")
    }

    /// Builds a group step, parametrizing over the architectures only.
    pub fn build_group_per_arch(
        &mut self,
        label: &str,
        commands: &[String],
        depends_on_build: bool,
        set_key: Option<&str>,
        kwargs: &Value,
    ) -> Result<usize> {
        let combined = overlay_dict(&self.per_arch, kwargs);
        let instances = to_instances(combined.get("instances"))?;
        let platforms = to_platforms(combined.get("platforms"))?;
        let step_kwargs = step_kwargs(&combined);

        let mut grp = group(label, commands, &instances, &platforms, &step_kwargs);
        if let Some(set_key) = set_key {
            let steps = grp
                .get_mut("steps")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| anyhow!("group step has no 'steps' array"))?;
            for step in steps.iter_mut() {
                let instance = step
                    .pointer("/agents/instance")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("step has no agents.instance"))?;
                let arch = get_arch_for_instance(instance);
                step["key"] = json!(self.build_key(set_key, arch));
            }
        }
        self.add_step(grp, depends_on_build)
    }

    /// Splits the steps into chunks of at most `max_jobs` leaf jobs each.
    pub fn chunk_steps(&self, max_jobs: usize) -> Vec<Vec<Value>> {
        let mut chunks: Vec<Vec<Value>> = Vec::new();
        let mut current_chunk: Vec<Value> = Vec::new();
        let mut current_count = 0usize;

        for step in &self.steps {
            if step.get("group").is_some() {
                let mut remaining = step
                    .get("steps")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                while !remaining.is_empty() {
                    // Reserve one slot for the group step itself.
                    let mut available = max_jobs.saturating_sub(current_count + 1);
                    if available == 0 {
                        chunks.push(std::mem::take(&mut current_chunk));
                        current_count = 0;
                        available = max_jobs.saturating_sub(1);
                    }
                    // At least one leaf job has to be taken, otherwise a
                    // `max_jobs` of 1 would never make progress.
                    let take = available.max(1).min(remaining.len());
                    let rest = remaining.split_off(take);
                    let taken = std::mem::replace(&mut remaining, rest);
                    let mut chunked = step.clone();
                    chunked["steps"] = Value::Array(taken.clone());
                    current_chunk.push(chunked);
                    current_count += taken.len() + 1;
                }
            } else {
                if !current_chunk.is_empty() && current_count + 1 > max_jobs {
                    chunks.push(std::mem::take(&mut current_chunk));
                    current_count = 0;
                }
                current_chunk.push(step.clone());
                current_count += 1;
            }
        }

        if !current_chunk.is_empty() {
            chunks.push(current_chunk);
        }
        chunks
    }

    /// Renders the pipeline as a JSON object.
    pub fn to_dict(&self) -> Value {
        json!({"steps": self.steps})
    }

    /// Serializes the pipeline the way `json.dumps(indent=4, sort_keys=True)` does.
    ///
    /// With `max_jobs` set this returns a JSON array of pipelines, each with at
    /// most `max_jobs` leaf jobs; otherwise a single pipeline object.
    pub fn to_json(&self) -> Result<String> {
        let to_serialize = match self.args.max_jobs {
            None => self.to_dict(),
            Some(max_jobs) => Value::Array(
                self.chunk_steps(max_jobs)
                    .iter()
                    .map(|chunk| json!({"steps": chunk}))
                    .collect(),
            ),
        };

        let mut buffer = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
        to_serialize
            .serialize(&mut serializer)
            .context("serializing the pipeline")?;
        String::from_utf8(buffer).context("pretty printed pipeline is not UTF-8")
    }

    /// Generates a `devtool download_ci_artifacts` command.
    pub fn devtool_download_artifacts(&self, artifacts: &[String]) -> String {
        let mut parts = vec!["./tools/devtool -y download_ci_artifacts".to_string()];
        parts.extend(artifacts.iter().cloned());
        parts.join(" ")
    }

    /// Generates a `devtool test` command.
    pub fn devtool_test(
        &self,
        devtool_opts: Option<&str>,
        pytest_opts: Option<&str>,
    ) -> Vec<String> {
        let mut parts = vec!["./tools/devtool -y test".to_string()];
        if self.shared_build.is_some() {
            parts.push("--no-build".to_string());
        }
        if let Some(artifacts) = &self.artifacts {
            parts.push(format!("--artifacts '{artifacts}'"));
        }
        if let Some(opts) = devtool_opts.filter(|opts| !opts.is_empty()) {
            parts.push(opts.to_string());
        }
        parts.push("--".to_string());
        if let Some(binary_dir) = &self.binary_dir {
            parts.push(format!("--binary-dir=../{binary_dir}/$(uname -m)"));
        }
        if let Some(opts) = pytest_opts.filter(|opts| !opts.is_empty()) {
            parts.push(opts.to_string());
        }
        vec![parts.join(" ")]
    }
}

/// Extracts the `command` list of a group step description.
fn to_commands(command: Option<&Value>) -> Result<Vec<String>> {
    match command {
        Some(Value::String(single)) => Ok(vec![single.clone()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow!("command entries must be strings"))
            })
            .collect(),
        _ => bail!("group step needs a command"),
    }
}

fn to_instances(value: Option<&Value>) -> Result<Vec<String>> {
    let items = value
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("group step needs an instance list"))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("instances must be strings"))
        })
        .collect()
}

fn to_platforms(value: Option<&Value>) -> Result<Vec<(String, String)>> {
    let items = value
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("group step needs a platform list"))?;
    items
        .iter()
        .map(|item| {
            let pair = item
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(|| anyhow!("platforms must be [os, kv] pairs"))?;
            let os = pair[0]
                .as_str()
                .ok_or_else(|| anyhow!("platform os must be a string"))?;
            let kv = pair[1]
                .as_str()
                .ok_or_else(|| anyhow!("platform kv must be a string"))?;
            Ok((os.to_string(), kv.to_string()))
        })
        .collect()
}

/// Everything of a combined step description except the group parameters.
fn step_kwargs(combined: &Value) -> Value {
    let mut kwargs = combined.as_object().cloned().unwrap_or_default();
    for key in ["label", "command", "instances", "platforms"] {
        kwargs.remove(key);
    }
    Value::Object(kwargs)
}

/// One performance test of `pipeline_perf.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfTest {
    /// Buildkite step label.
    pub label: &'static str,
    /// pytest selection: test paths plus an optional `-k` expression.
    pub tests: &'static str,
    /// Options passed to `devtool test`.
    pub devtool_opts: &'static str,
    /// Options passed to the `ab_test` runner.
    pub ab_opts: Option<&'static str>,
    /// Number of A/B iterations.
    pub max_iterations: Option<u32>,
}

const fn perf_test(
    label: &'static str,
    tests: &'static str,
    devtool_opts: &'static str,
    ab_opts: Option<&'static str>,
    max_iterations: Option<u32>,
) -> PerfTest {
    PerfTest {
        label,
        tests,
        devtool_opts,
        ab_opts,
        max_iterations,
    }
}

/// Catalog of the performance tests, in pipeline order.
pub fn perf_tests() -> &'static [(&'static str, PerfTest)] {
    static TESTS: [(&str, PerfTest); 14] = [
        (
            "virtio-block-sync",
            perf_test(
                "virtio-block-sync",
                "integration_tests/performance/test_block.py::test_block_performance -k 'not Async'",
                "-c 1-10 -m 0",
                None,
                None,
            ),
        ),
        (
            "virtio-block-async",
            perf_test(
                "virtio-block-async",
                "integration_tests/performance/test_block.py::test_block_performance -k Async",
                "-c 1-10 -m 0",
                None,
                None,
            ),
        ),
        (
            "vhost-user-block",
            perf_test(
                "vhost-user-block",
                "integration_tests/performance/test_block.py::test_block_vhost_user_performance",
                "-c 1-10 -m 0",
                Some("--noise-threshold bw_read=0.1"),
                None,
            ),
        ),
        (
            "pmem",
            perf_test(
                "pmem",
                "integration_tests/performance/test_pmem.py",
                "-c 1-10 -m 0",
                None,
                None,
            ),
        ),
        (
            "network",
            perf_test(
                "network",
                "integration_tests/performance/test_network.py",
                "-c 1-10 -m 0",
                None,
                None,
            ),
        ),
        (
            "vsock-throughput",
            perf_test(
                "vsock-throughput",
                "integration_tests/performance/test_vsock.py",
                "-c 1-10 -m 0",
                None,
                None,
            ),
        ),
        (
            "memory-hotplug",
            perf_test(
                "memory-hotplug",
                "integration_tests/performance/test_hotplug_memory.py",
                "-c 1-10 -m 0",
                Some("--absolute-strength 0.005 --noise-threshold hotunplug_total_time=0.1"),
                None,
            ),
        ),
        (
            "snapshot-latency",
            perf_test(
                "snapshot-latency",
                "integration_tests/performance/test_snapshot.py::test_restore_latency \
                 integration_tests/performance/test_snapshot.py::test_post_restore_latency \
                 integration_tests/performance/test_snapshot.py::test_snapshot_create_latency",
                "-c 1-12 -m 0",
                None,
                None,
            ),
        ),
        (
            "population-latency",
            perf_test(
                "population-latency",
                "integration_tests/performance/test_snapshot.py::test_population_latency",
                "-c 1-12 -m 0",
                None,
                None,
            ),
        ),
        (
            "memory-overhead",
            perf_test(
                "memory-overhead",
                "integration_tests/performance/test_memory_overhead.py",
                "-c 1-10 -m 0",
                None,
                None,
            ),
        ),
        (
            "boottime",
            perf_test(
                "boottime",
                "integration_tests/performance/test_boottime.py::test_boottime",
                "-c 1-10 -m 0",
                None,
                None,
            ),
        ),
        (
            "process-startup",
            perf_test(
                "process-startup",
                "integration_tests/performance/test_process_startup_time.py",
                "-c 1-10 -m 0",
                None,
                None,
            ),
        ),
        (
            "jailer",
            perf_test(
                "jailer",
                "integration_tests/performance/test_jailer.py",
                "-c 1-10 -m 0",
                Some("--noise-threshold startup=0.1"),
                None,
            ),
        ),
        (
            "mmds",
            perf_test(
                "mmds",
                "integration_tests/performance/test_mmds.py",
                "-c 1-10 -m 0",
                None,
                Some(30),
            ),
        ),
    ];
    &TESTS
}

/// Looks up a performance test by name.
pub fn perf_test_by_name(name: &str) -> Option<&'static PerfTest> {
    perf_tests()
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, test)| test)
}

/// A/B revisions and artifact overrides of the A/B-test pipelines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AbRevisions {
    /// `REVISION_A`.
    pub a: Option<String>,
    /// `REVISION_B`.
    pub b: Option<String>,
    /// `REVISION_A_ARTIFACTS`.
    pub a_artifacts: Option<String>,
    /// `REVISION_B_ARTIFACTS`.
    pub b_artifacts: Option<String>,
}

impl AbRevisions {
    /// Reads the revisions from the environment, validating that both are set.
    pub fn from_env() -> Result<Self> {
        let revisions = Self {
            a: std::env::var("REVISION_A").ok(),
            b: std::env::var("REVISION_B").ok(),
            a_artifacts: std::env::var("REVISION_A_ARTIFACTS").ok(),
            b_artifacts: std::env::var("REVISION_B_ARTIFACTS").ok(),
        };
        revisions.validate()?;
        Ok(revisions)
    }

    /// Checks that each A/B pair is either fully set or fully unset.
    pub fn validate(&self) -> Result<()> {
        if self.a.is_some() != self.b.is_some() {
            bail!("either both REVISION_A and REVISION_B or neither must be set");
        }
        if self.a_artifacts.is_some() != self.b_artifacts.is_some() {
            bail!(
                "either both REVISION_A_ARTIFACTS and REVISION_B_ARTIFACTS or neither must be set"
            );
        }
        Ok(())
    }
}

/// Builds the steps of `pipeline_perf.py`.
///
/// `selected` holds the `--test` values; an empty selection runs every test.
pub fn build_perf_pipeline(
    args: PipelineArgs,
    revisions: &AbRevisions,
    selected: &[String],
) -> Result<BKPipeline> {
    revisions.validate()?;

    let kwargs = json!({
        // Boost the priority so these jobs are preferred by ag=1 agents.
        "priority": 2,
        // ag=1 instances keep performance tests away from each other.
        "agents": {"ag": 1},
        "env": {"FC_TEST_DUMP_ON_FAILURE": "1"},
    });
    let mut pipeline = BKPipeline::new(args, true, &kwargs)?;

    let tests: Vec<&PerfTest> = if selected.is_empty() {
        perf_tests().iter().map(|(_, test)| test).collect()
    } else {
        selected
            .iter()
            .map(|name| {
                perf_test_by_name(name).ok_or_else(|| anyhow!("unknown performance test '{name}'"))
            })
            .collect::<Result<_>>()?
    };

    for test in tests {
        let mut devtool_opts = format!("{} --performance", test.devtool_opts);
        let mut test_script_opts = String::new();
        let mut artifacts: Vec<String> = Vec::new();

        if let Some(revision_a) = &revisions.a {
            devtool_opts.push_str(" --ab");
            let revision_b = revisions.b.as_deref().unwrap_or_default();
            let max_iterations = test
                .max_iterations
                .unwrap_or(A_B_TEST_DEFAULT_MAX_ITERATIONS);
            test_script_opts = format!(
                "{} run --binaries-a build/{revision_a}/ --binaries-b build/{revision_b} --max-iterations={max_iterations} --pytest-opts \"{}\"",
                test.ab_opts.unwrap_or_default(),
                test.tests
            );
            if let Some(a_artifacts) = &revisions.a_artifacts {
                let b_artifacts = revisions.b_artifacts.as_deref().unwrap_or_default();
                artifacts.push(a_artifacts.clone());
                artifacts.push(b_artifacts.to_string());
                test_script_opts.push_str(&format!(
                    " --artifacts-a {a_artifacts} --artifacts-b {b_artifacts}"
                ));
            }
        } else {
            // `-m ''` collects tests regardless of their markers.
            test_script_opts.push_str(&format!(" -m '' {}", test.tests));
        }

        let mut command: Vec<String> = Vec::new();
        if !artifacts.is_empty() {
            command.push(pipeline.devtool_download_artifacts(&artifacts));
        }
        command.extend(pipeline.devtool_test(Some(&devtool_opts), Some(&test_script_opts)));

        pipeline.build_group(&json!({"label": test.label, "command": command}), true)?;
    }

    // Pinning tests to agents of a particular kernel version: the dictionary
    // maps a new `kv` tag to the agent fields it matches.
    let pins = json!({});
    pipeline.steps = apply_pins(&pipeline.steps, &pins);
    Ok(pipeline)
}

/// Instances a snapshot may be restored on, in addition to itself.
pub fn cross_supported_instances() -> Value {
    json!({
        "m5n.metal": ["m6i.metal"],
        "m6i.metal": ["m5n.metal"],
    })
}

/// Buildkite key of a snapshot-create step, with dots sanitized.
///
/// Buildkite keys may only contain `[A-Za-z0-9_\-:]`, so the dots of instance
/// names and kernel versions are replaced by underscores.
pub fn create_step_key(instance: &str, kv: &str) -> String {
    format!("snap-create-{instance}-{kv}").replace('.', "_")
}

/// Instances and platforms of the `pipeline_cross.py` fan-out.
struct CrossMatrix {
    instances_x86_64: Vec<String>,
    instances_aarch64: Vec<String>,
    default_platforms: Vec<(String, String)>,
    x86_64_platforms: Vec<(String, String)>,
    aarch64_platforms: Vec<(String, String)>,
    aarch64_all_platforms: Vec<(String, String)>,
}

impl CrossMatrix {
    fn new() -> Self {
        let restore_only = [("al2023".to_string(), "linux_6.18".to_string())];
        let defaults = DEFAULT_PLATFORMS
            .iter()
            .map(|(os, kv)| ((*os).to_string(), (*kv).to_string()))
            .collect::<Vec<_>>();
        let aarch64_platforms = vec![("al2023".to_string(), "linux_6.1".to_string())];
        Self {
            instances_x86_64: [
                "m5n.metal",
                "m6i.metal",
                "m7i.metal-24xl",
                "m7i.metal-48xl",
                "m8i.metal-48xl",
                "m6a.metal",
                "m7a.metal-48xl",
            ]
            .iter()
            .map(|instance| (*instance).to_string())
            .collect(),
            instances_aarch64: ["m6g.metal", "m7g.metal", "m8g.metal-24xl", "m9g.metal-48xl"]
                .iter()
                .map(|instance| (*instance).to_string())
                .collect(),
            default_platforms: defaults.clone(),
            x86_64_platforms: defaults
                .iter()
                .cloned()
                .chain(restore_only.clone())
                .collect(),
            aarch64_all_platforms: aarch64_platforms
                .iter()
                .cloned()
                .chain(restore_only)
                .collect(),
            aarch64_platforms,
        }
    }
}

/// Builds the steps of `pipeline_cross.py`.
pub fn build_cross_pipeline(args: PipelineArgs) -> Result<BKPipeline> {
    let mut pipeline = BKPipeline::new(args, true, &json!({}))?;
    let matrix = CrossMatrix::new();

    let mut per_instance = pipeline
        .per_instance
        .as_object()
        .cloned()
        .unwrap_or_default();
    per_instance.remove("instances");
    per_instance.remove("platforms");

    let mut commands = pipeline.devtool_test(
        Some("--no-archive"),
        Some("-m nonci -n4 integration_tests/functional/test_snapshot_phase1.py"),
    );
    // Punch holes in the memory snapshot files so they compress well.
    commands.extend([
        "find test_results/test_snapshot_phase1 -type f -name mem |xargs -P4 -t -n1 fallocate -d"
            .to_string(),
        "mv -v test_results/test_snapshot_phase1 snapshot_artifacts".to_string(),
        "mkdir -pv snapshots".to_string(),
        "tar cSvf snapshots/{instance}_{kv}.tar snapshot_artifacts".to_string(),
    ]);

    let x86_create = pipeline.build_group(
        &json!({
            "label": "snapshot-create",
            "command": &commands,
            "timeout": 30,
            "artifact_paths": "snapshots/**/*",
            "instances": &matrix.instances_x86_64,
            "platforms": DEFAULT_PLATFORMS,
        }),
        true,
    )?;

    let aarch64_create = pipeline.build_group(
        &json!({
            "label": "snapshot-create-aarch64",
            "command": &commands,
            "timeout": 30,
            "artifact_paths": "snapshots/**/*",
            "instances": &matrix.instances_aarch64,
            "platforms": &matrix.aarch64_platforms,
        }),
        true,
    )?;

    // Key each snapshot-create step so restore steps can depend on the exact
    // source snapshot they need.
    for group_index in [x86_create, aarch64_create] {
        let group = pipeline.step_mut(group_index)?;
        let steps = group
            .get_mut("steps")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("group step has no 'steps' array"))?;
        for step in steps.iter_mut() {
            let instance = step
                .pointer("/agents/instance")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("step has no agents.instance"))?
                .to_string();
            let kv = step
                .pointer("/agents/kv")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("step has no agents.kv"))?
                .to_string();
            step["key"] = json!(create_step_key(&instance, &kv));
        }
    }

    let supported = cross_supported_instances();
    let mut steps: Vec<Value> = Vec::new();

    // Same product order as python's `itertools.product`.
    push_restore_steps(
        &pipeline,
        &mut steps,
        &matrix.instances_x86_64,
        &matrix.default_platforms,
        &matrix.instances_x86_64,
        &matrix.x86_64_platforms,
        &supported,
        &per_instance,
    );
    push_restore_steps(
        &pipeline,
        &mut steps,
        &matrix.instances_aarch64,
        &matrix.aarch64_platforms,
        &matrix.instances_aarch64,
        &matrix.aarch64_all_platforms,
        &supported,
        &per_instance,
    );

    pipeline.add_step(
        json!({"group": "snapshot-restore-across-instances-and-kernels", "steps": steps}),
        true,
    )?;
    Ok(pipeline)
}

/// Appends the snapshot-restore steps of one architecture to `steps`.
#[allow(clippy::too_many_arguments)]
fn push_restore_steps(
    pipeline: &BKPipeline,
    steps: &mut Vec<Value>,
    src_instances: &[String],
    src_platforms: &[(String, String)],
    dst_instances: &[String],
    dst_platforms: &[(String, String)],
    supported: &Value,
    per_instance: &Map<String, Value>,
) {
    for src_instance in src_instances {
        for (_, src_kv) in src_platforms {
            for dst_instance in dst_instances {
                for (dst_os, dst_kv) in dst_platforms {
                    // The integration tests already cover src == dst.
                    if src_instance == dst_instance && src_kv == dst_kv {
                        continue;
                    }
                    // Newer to older is not supported.
                    if src_kv > dst_kv {
                        continue;
                    }
                    // Only adjacent kernel versions are tested across kernels.
                    if src_kv == "linux_5.10" && dst_kv == "linux_6.18" {
                        continue;
                    }
                    if src_instance != dst_instance
                        && !supported
                            .get(src_instance)
                            .and_then(Value::as_array)
                            .map(|allowed| allowed.iter().any(|item| item == dst_instance))
                            .unwrap_or(false)
                    {
                        continue;
                    }

                    let k_val = match dst_instance.as_str() {
                        "m5n.metal" | "m6i.metal" => "-k 'not None'",
                        _ => "",
                    };
                    let mut commands = vec![
                        format!(
                            "buildkite-agent artifact download snapshots/{src_instance}_{src_kv}.tar ."
                        ),
                        format!("tar xSvf snapshots/{src_instance}_{src_kv}.tar"),
                    ];
                    commands.extend(pipeline.devtool_test(
                        None,
                        Some(&format!(
                            "-m nonci -n8 --dist worksteal {k_val} integration_tests/functional/test_snapshot_restore_cross_kernel.py"
                        )),
                    ));

                    let mut step = Map::new();
                    step.insert("command".to_string(), json!(commands));
                    step.insert(
                        "label".to_string(),
                        json!(format!(
                            "snapshot-restore-src-{src_instance}-{src_kv}-dst-{dst_instance}-{dst_kv}"
                        )),
                    );
                    step.insert("timeout".to_string(), json!(30));
                    step.insert(
                        "agents".to_string(),
                        json!({"instance": dst_instance, "kv": dst_kv, "os": dst_os}),
                    );
                    step.insert(
                        "depends_on".to_string(),
                        json!([create_step_key(src_instance, src_kv)]),
                    );
                    let mut step = Value::Object(step);
                    for (key, value) in per_instance {
                        step[key] = value.clone();
                    }
                    steps.push(step);
                }
            }
        }
    }
}

/// A plain CPU template test: one group fanned out over instances/platforms.
#[derive(Debug, Clone, Copy)]
pub struct CpuTemplateTest {
    /// Buildkite step label.
    pub label: &'static str,
    /// Commands of the step, templated with `{instance}`/`{os}`/`{kv}`.
    pub commands: &'static [&'static str],
    /// Instance override; defaults to the pipeline-wide list.
    pub instances: Option<&'static [&'static str]>,
    /// Artifact paths of the step.
    pub artifacts: Option<&'static str>,
    /// Step timeout, in minutes.
    pub timeout: Option<u32>,
}

/// Restore step template of the snapshot/restore CPU template test.
#[derive(Debug, Clone, Copy)]
pub struct RestoreStep {
    /// Buildkite step label template.
    pub label: &'static str,
    /// Commands, templated with `{instance}`/`{os}`/`{kv}` of the snapshot.
    pub commands: &'static [&'static str],
    /// Step timeout, in minutes.
    pub timeout: u32,
}

/// Snapshot/restore CPU template test.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotRestoreTest {
    /// Snapshot creation step template.
    pub snapshot: CpuTemplateTest,
    /// Snapshot restore step template.
    pub restore: RestoreStep,
    /// Extra instances a snapshot may be restored on.
    pub cross_instances: &'static [(&'static str, &'static [&'static str])],
    /// Instances the snapshots are created on.
    pub instances: &'static [&'static str],
}

/// A CPU template pipeline test case.
#[derive(Debug, Clone, Copy)]
pub enum CpuTemplateCase {
    /// Test generating a single group of steps.
    Plain(CpuTemplateTest),
    /// Test generating a snapshot group and a restore group.
    SnapshotRestore(SnapshotRestoreTest),
}

const CPU_TEMPLATE_INSTANCES: [&str; 6] = [
    "m5n.metal",
    "m6i.metal",
    "m7i.metal-24xl",
    "m7i.metal-48xl",
    "m6a.metal",
    "m7a.metal-48xl",
];

const CPU_TEMPLATE_SNAPSHOT_INSTANCES: [&str; 5] = [
    "m5n.metal",
    "m6i.metal",
    "m7i.metal-24xl",
    "m7i.metal-48xl",
    "m6a.metal",
];

/// Catalog of the CPU template tests, in pipeline order.
pub fn cpu_template_tests() -> &'static [(&'static str, CpuTemplateCase)] {
    static TESTS: [(&str, CpuTemplateCase); 3] = [
        (
            "rdmsr",
            CpuTemplateCase::Plain(CpuTemplateTest {
                label: "rdmsr",
                commands: &[
                    "tools/devtool -y test --no-build -- -m no_block_pr -n4 --dist worksteal integration_tests/functional/test_cpu_features_x86_64.py -k 'test_cpu_rdmsr' ",
                ],
                instances: Some(&CPU_TEMPLATE_INSTANCES),
                artifacts: None,
                timeout: None,
            }),
        ),
        (
            "fingerprint",
            CpuTemplateCase::Plain(CpuTemplateTest {
                label: "fingerprint",
                commands: &[
                    "tools/devtool -y test --no-build -- -m no_block_pr integration_tests/functional/test_cpu_template_helper.py -k test_guest_cpu_config_change",
                ],
                instances: None,
                artifacts: None,
                timeout: None,
            }),
        ),
        (
            "cpuid_wrmsr",
            CpuTemplateCase::SnapshotRestore(SnapshotRestoreTest {
                snapshot: CpuTemplateTest {
                    label: "snapshot-create",
                    commands: &[
                        "tools/devtool -y test --no-build -- -m nonci -n4 --dist worksteal integration_tests/functional/test_cpu_features_x86_64.py -k 'test_cpu_wrmsr_snapshot or test_cpu_cpuid_snapshot'",
                        "mkdir -pv tests/snapshot_artifacts_upload/{instance}_{os}_{kv}",
                        "sudo mv tests/snapshot_artifacts/* tests/snapshot_artifacts_upload/{instance}_{os}_{kv}",
                    ],
                    instances: None,
                    artifacts: Some("tests/snapshot_artifacts_upload/**/*"),
                    timeout: Some(30),
                },
                restore: RestoreStep {
                    label: "snapshot-restore-src-{instance}-{snapshot_os}-{snapshot_kv}-dst-{restore_instance}-{restore_os}-{restore_kv}",
                    commands: &[
                        "buildkite-agent artifact download tests/snapshot_artifacts_upload/{instance}_{os}_{kv}/**/* .",
                        "mv tests/snapshot_artifacts_upload/{instance}_{os}_{kv} tests/snapshot_artifacts",
                        "tools/devtool -y test --no-build -- -m nonci -n4 --dist worksteal integration_tests/functional/test_cpu_features_x86_64.py -k 'test_cpu_wrmsr_restore or test_cpu_cpuid_restore'",
                    ],
                    timeout: 30,
                },
                cross_instances: &[("m5n.metal", &["m6i.metal"]), ("m6i.metal", &["m5n.metal"])],
                instances: &CPU_TEMPLATE_SNAPSHOT_INSTANCES,
            }),
        ),
    ];
    &TESTS
}

/// Looks up a CPU template test by name.
pub fn cpu_template_test(name: &str) -> Option<&'static CpuTemplateCase> {
    cpu_template_tests()
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, case)| case)
}

/// Generates the snapshot and restore groups of the `cpuid_wrmsr` test.
pub fn group_snapshot_restore(test: &SnapshotRestoreTest) -> Vec<Value> {
    let platforms = DEFAULT_PLATFORMS
        .iter()
        .map(|(os, kv)| ((*os).to_string(), (*kv).to_string()))
        .collect::<Vec<_>>();
    let instances = test
        .instances
        .iter()
        .map(|instance| (*instance).to_string())
        .collect::<Vec<_>>();
    let commands = test
        .snapshot
        .commands
        .iter()
        .map(|command| (*command).to_string())
        .collect::<Vec<_>>();

    let mut snapshot_kwargs = Map::new();
    if let Some(timeout) = test.snapshot.timeout {
        snapshot_kwargs.insert("timeout".to_string(), json!(timeout));
    }
    if let Some(artifacts) = test.snapshot.artifacts {
        snapshot_kwargs.insert("artifacts".to_string(), json!(artifacts));
    }

    let snapshot_group = group(
        test.snapshot.label,
        &commands,
        &instances,
        &platforms,
        &Value::Object(snapshot_kwargs),
    );
    let mut snapshot_entry = snapshot_group.clone();
    snapshot_entry["key"] = json!("snapshot");
    let mut groups = vec![snapshot_entry];

    // `itertools` order: platform first, then the source instance, then the
    // destination instances.
    let mut combinations: Vec<((String, String), String, (String, String), String)> = Vec::new();
    for (os, kv) in &platforms {
        for src_instance in &instances {
            let mut destinations = vec![src_instance.clone()];
            if let Some((_, extra)) = test
                .cross_instances
                .iter()
                .find(|(instance, _)| instance == src_instance)
            {
                destinations.extend(extra.iter().map(|instance| (*instance).to_string()));
            }
            for dst_instance in destinations {
                combinations.push((
                    (os.clone(), kv.clone()),
                    src_instance.clone(),
                    (os.clone(), kv.clone()),
                    dst_instance,
                ));
            }
        }
    }

    let mut steps = Vec::new();
    for (
        (snapshot_os, snapshot_kv),
        snapshot_instance,
        (restore_os, restore_kv),
        restore_instance,
    ) in combinations
    {
        let mut args = Map::new();
        args.insert("instance".to_string(), json!(snapshot_instance));
        args.insert("os".to_string(), json!(snapshot_os));
        args.insert("kv".to_string(), json!(snapshot_kv));
        args.insert("snapshot_os".to_string(), json!(snapshot_os));
        args.insert("snapshot_kv".to_string(), json!(snapshot_kv));
        args.insert("restore_instance".to_string(), json!(restore_instance));
        args.insert("restore_os".to_string(), json!(restore_os));
        args.insert("restore_kv".to_string(), json!(restore_kv));

        let restore_commands = test
            .restore
            .commands
            .iter()
            .map(|command| format_template(command, &args))
            .collect::<Vec<_>>();

        steps.push(json!({
            "command": restore_commands,
            "label": format_template(test.restore.label, &args),
            "timeout": test.restore.timeout,
            "agents": {"instance": restore_instance, "kv": restore_kv, "os": restore_os},
        }));
    }

    groups.push(json!({
        "group": "snapshot-restore",
        "steps": steps,
        "depends_on": "snapshot",
    }));
    groups
}

/// Builds the steps of `pipeline_cpu_template.py`.
pub fn build_cpu_template_pipeline(args: PipelineArgs, selected: &[String]) -> Result<BKPipeline> {
    let mut pipeline = BKPipeline::new(args, true, &json!({}))?;

    let cases: Vec<&CpuTemplateCase> = if selected.is_empty() {
        cpu_template_tests().iter().map(|(_, case)| case).collect()
    } else {
        selected
            .iter()
            .map(|name| {
                cpu_template_test(name).ok_or_else(|| anyhow!("unknown CPU template test '{name}'"))
            })
            .collect::<Result<_>>()?
    };

    for case in cases {
        match case {
            CpuTemplateCase::SnapshotRestore(test) => {
                for grp in group_snapshot_restore(test) {
                    pipeline.add_step(grp, true)?;
                }
            }
            CpuTemplateCase::Plain(test) => {
                let mut kwargs = Map::new();
                kwargs.insert("label".to_string(), json!(test.label));
                kwargs.insert("command".to_string(), json!(test.commands));
                kwargs.insert("artifacts".to_string(), json!(["./test_results/**/*"]));
                if let Some(instances) = test.instances {
                    kwargs.insert("instances".to_string(), json!(instances));
                }
                if let Some(timeout) = test.timeout {
                    kwargs.insert("timeout".to_string(), json!(timeout));
                }
                pipeline.build_group(&Value::Object(kwargs), true)?;
            }
        }
    }

    Ok(pipeline)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arguments of a pipeline that reuses pre-built binaries, so that no
    /// random shared-build artifact name shows up in the output.
    fn args_without_build(instances: &[&str], platforms: &[(&str, &str)]) -> PipelineArgs {
        PipelineArgs {
            instances: instances.iter().map(|i| (*i).to_string()).collect(),
            platforms: platforms
                .iter()
                .map(|(os, kv)| ((*os).to_string(), (*kv).to_string()))
                .collect(),
            binary_dir: Some("build".to_string()),
            artifacts: None,
            max_jobs: None,
            ..PipelineArgs::default()
        }
    }

    fn labels(grp: &Value) -> Vec<String> {
        grp["steps"]
            .as_array()
            .expect("group has steps")
            .iter()
            .map(|step| step["label"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    fn commands(step: &Value) -> Vec<String> {
        step["command"]
            .as_array()
            .expect("step has commands")
            .iter()
            .map(|command| command.as_str().unwrap_or_default().to_string())
            .collect()
    }

    fn pipeline_with(args: PipelineArgs) -> BKPipeline {
        BKPipeline::new(args, false, &json!({})).expect("pipeline is created")
    }

    #[test]
    fn instance_architecture_follows_the_graviton_suffix() {
        assert_eq!(get_arch_for_instance("m5n.metal"), "x86_64");
        assert_eq!(get_arch_for_instance("m7i.metal-48xl"), "x86_64");
        assert_eq!(get_arch_for_instance("m6a.metal"), "x86_64");
        assert_eq!(get_arch_for_instance("m6g.metal"), "aarch64");
        assert_eq!(get_arch_for_instance("m9g.metal-48xl"), "aarch64");
    }

    #[test]
    fn overlay_dict_merges_nested_objects() {
        let base = json!({"a": 1, "b": {"c": 2, "d": 3}, "e": "x"});
        let update = json!({"b": {"d": 4}, "f": "y"});
        assert_eq!(
            overlay_dict(&base, &update),
            json!({"a": 1, "b": {"c": 2, "d": 4}, "e": "x", "f": "y"})
        );
        // Non-object updates replace the base entirely.
        assert_eq!(overlay_dict(&base, &json!(7)), json!(7));
    }

    #[test]
    fn field_and_dict_fmt_interpolate_known_keys() {
        let mut args = Map::new();
        args.insert("instance".to_string(), json!("m6i.metal"));
        args.insert("os".to_string(), json!("al2023"));
        args.insert("kv".to_string(), json!("linux_6.1"));

        assert_eq!(
            field_fmt(&json!("a-{instance}-{os}-{kv}"), &args),
            json!("a-m6i.metal-al2023-linux_6.1")
        );
        assert_eq!(
            field_fmt(&json!("{os}-{unknown}"), &args),
            json!("al2023-{unknown}")
        );
        assert_eq!(field_fmt(&json!(3), &args), json!(3));

        let template = json!({"timeout": 30, "agents": {"queue": "{instance}"}});
        assert_eq!(
            dict_fmt(&template, &args),
            json!({"timeout": 30, "agents": {"queue": "m6i.metal"}})
        );
    }

    #[test]
    fn group_fans_out_over_instances_then_platforms() {
        let instances = vec!["m6i.metal".to_string(), "m7g.metal".to_string()];
        let platforms = vec![
            ("al2".to_string(), "linux_5.10".to_string()),
            ("al2023".to_string(), "linux_6.1".to_string()),
        ];
        let grp = group(
            "unit",
            &["run {instance}-{os}-{kv}".to_string()],
            &instances,
            &platforms,
            &json!({"timeout": 10, "artifact_paths": ["snapshots/**/*"]}),
        );

        assert_eq!(
            labels(&grp),
            vec![
                "unit-m6i.metal-al2-linux_5.10",
                "unit-m6i.metal-al2023-linux_6.1",
                "unit-m7g.metal-al2-linux_5.10",
                "unit-m7g.metal-al2023-linux_6.1",
            ]
        );
        let first = &grp["steps"][0];
        assert_eq!(commands(first), vec!["run m6i.metal-al2-linux_5.10"]);
        assert_eq!(
            first["agents"],
            json!({"instance": "m6i.metal", "os": "al2", "kv": "linux_5.10"})
        );
        assert_eq!(first["timeout"], json!(10));
        assert_eq!(first["artifact_paths"], json!(["snapshots/**/*"]));
        assert_eq!(grp["group"], json!("unit"));
    }

    #[test]
    fn devtool_test_composes_the_pytest_command() {
        let pipeline = pipeline_with(args_without_build(
            &["m6i.metal"],
            &[("al2023", "linux_6.1")],
        ));

        assert_eq!(
            pipeline.devtool_test(
                Some("--performance"),
                Some("-m '' integration_tests/performance/test_boottime.py::test_boottime"),
            ),
            vec![
                "./tools/devtool -y test --performance -- --binary-dir=../build/$(uname -m) -m '' integration_tests/performance/test_boottime.py::test_boottime"
                    .to_string()
            ]
        );
        // Empty options are skipped, like python's truthiness checks.
        assert_eq!(
            pipeline.devtool_test(None, Some("")),
            vec!["./tools/devtool -y test -- --binary-dir=../build/$(uname -m)".to_string()]
        );
        assert_eq!(
            pipeline.devtool_download_artifacts(&["s3://a".to_string(), "s3://b".to_string()]),
            "./tools/devtool -y download_ci_artifacts s3://a s3://b"
        );
    }

    #[test]
    fn devtool_test_reports_shared_build_and_artifacts() {
        let mut pipeline = pipeline_with(PipelineArgs {
            artifacts: Some("s3://bucket/path".to_string()),
            ..args_without_build(&["m6i.metal"], &[("al2023", "linux_6.1")])
        });
        pipeline.shared_build = Some("build_x86_64_abc.tar.gz".to_string());

        assert_eq!(
            pipeline.devtool_test(Some("--no-archive"), None),
            vec![
                "./tools/devtool -y test --no-build --artifacts 's3://bucket/path' --no-archive -- --binary-dir=../build/$(uname -m)"
                    .to_string()
            ]
        );
    }

    #[test]
    fn build_group_generates_pytest_invocations() {
        let mut pipeline = pipeline_with(args_without_build(
            &["m6i.metal", "m7g.metal"],
            &[("al2023", "linux_6.1"), ("al2023", "linux_6.18")],
        ));
        let test_command = pipeline.devtool_test(
            Some("--no-archive"),
            Some("-m nonci -n4 --dist worksteal integration_tests/functional/test_snapshot_phase1.py"),
        );

        let index = pipeline
            .build_group(
                &json!({
                    "label": "snapshot-create",
                    "command": test_command,
                    "timeout": 30,
                    "artifact_paths": "snapshots/**/*",
                }),
                true,
            )
            .expect("group is built");
        assert_eq!(index, 0);

        let grp = &pipeline.steps[0];
        assert_eq!(
            labels(grp),
            vec![
                "snapshot-create-m6i.metal-al2023-linux_6.1",
                "snapshot-create-m6i.metal-al2023-linux_6.18",
                "snapshot-create-m7g.metal-al2023-linux_6.1",
                "snapshot-create-m7g.metal-al2023-linux_6.18",
            ]
        );
        let first = commands(&grp["steps"][0]);
        // The binary-dir download commands are prepended by `adapt_group`.
        assert_eq!(
            first[0],
            "buildkite-agent artifact download \"build/$(uname -m)/*\" ."
        );
        assert_eq!(first[1], "chmod -v a+x build/**/*");
        assert_eq!(
            first[2],
            "./tools/devtool -y test --no-archive -- --binary-dir=../build/$(uname -m) -m nonci -n4 --dist worksteal integration_tests/functional/test_snapshot_phase1.py"
        );
        assert_eq!(grp["steps"][0]["timeout"], json!(30));
        assert_eq!(grp["steps"][0]["parallelism"], json!(1));
        assert_eq!(grp["steps"][0]["artifact_paths"], json!("snapshots/**/*"));
        // No shared build, so no `depends_on` entries are added.
        assert!(grp["steps"][0].get("depends_on").is_none());
    }

    #[test]
    fn group_commands_are_templated_per_instance() {
        let mut pipeline = pipeline_with(args_without_build(
            &["m6i.metal"],
            &[("al2023", "linux_6.1")],
        ));
        pipeline
            .build_group(
                &json!({
                    "label": "snapshot-create",
                    "command": [
                        "mkdir -pv tests/snapshot_artifacts_upload/{instance}_{os}_{kv}",
                        "tar cSvf snapshots/{instance}_{kv}.tar snapshot_artifacts",
                    ],
                }),
                true,
            )
            .expect("group is built");

        let step_commands = commands(&pipeline.steps[0]["steps"][0]);
        assert_eq!(
            step_commands[2],
            "mkdir -pv tests/snapshot_artifacts_upload/m6i.metal_al2023_linux_6.1"
        );
        assert_eq!(
            step_commands[3],
            "tar cSvf snapshots/m6i.metal_linux_6.1.tar snapshot_artifacts"
        );
    }

    #[test]
    fn shared_build_selects_the_right_scenario() {
        // Nightly: compile the HEAD of main only.
        let (cmds, binary_dir) =
            shared_build_with(&BuildEnv::default(), "abc12345").expect("nightly build commands");
        assert_eq!(binary_dir, "build_$(uname -m)_abc12345.tar.gz");
        assert_eq!(cmds[0], "./tools/devtool -y build --release");
        assert_eq!(cmds[1], "du -sh build/*");
        assert_eq!(cmds[2], "tar czf build_$(uname -m)_abc12345.tar.gz build");
        assert_eq!(
            cmds[3],
            "buildkite-agent artifact upload build_$(uname -m)_abc12345.tar.gz"
        );

        // Pull request: compile the base branch and the PR HEAD.
        let (cmds, _) = shared_build_with(
            &BuildEnv {
                pull_request_base: Some("main".to_string()),
                ..BuildEnv::default()
            },
            "abc12345",
        )
        .expect("pull request build commands");
        assert_eq!(cmds[0], "./tools/devtool -y build --rev main --release");
        assert_eq!(cmds[1], "./tools/devtool -y build --release");

        // A/B pipeline: compile both revisions.
        let (cmds, _) = shared_build_with(
            &BuildEnv {
                revision_a: Some("aaa".to_string()),
                revision_b: Some("bbb".to_string()),
                pull_request_base: Some("main".to_string()),
            },
            "abc12345",
        )
        .expect("A/B build commands");
        assert_eq!(cmds[0], "./tools/devtool -y build --rev aaa --release");
        assert_eq!(cmds[1], "./tools/devtool -y build --rev bbb --release");

        // Identical revisions are compiled once.
        let (cmds, _) = shared_build_with(
            &BuildEnv {
                revision_a: Some("aaa".to_string()),
                revision_b: Some("aaa".to_string()),
                pull_request_base: None,
            },
            "abc12345",
        )
        .expect("single revision build commands");
        assert_eq!(cmds.len(), 4);
        assert_eq!(cmds[0], "./tools/devtool -y build --rev aaa --release");

        // A missing REVISION_B is an error, like the python assertion.
        assert!(shared_build_with(
            &BuildEnv {
                revision_a: Some("aaa".to_string()),
                revision_b: None,
                pull_request_base: None,
            },
            "abc12345"
        )
        .is_err());
    }

    #[test]
    fn pipeline_with_build_step_uses_the_shared_artifact() {
        let mut pipeline = BKPipeline::new(
            PipelineArgs {
                binary_dir: None,
                artifacts: None,
                ..args_without_build(&["m6i.metal"], &[("al2023", "linux_6.1")])
            },
            true,
            &json!({"priority": 2}),
        )
        .expect("pipeline is created");

        let shared = pipeline.shared_build.clone().expect("build step exists");
        assert!(shared.starts_with("build_$(uname -m)_"), "{shared}");
        assert!(shared.ends_with(".tar.gz"), "{shared}");
        let suffix = shared
            .trim_start_matches("build_$(uname -m)_")
            .trim_end_matches(".tar.gz")
            .to_string();

        // The build step comes first, keyed per architecture.
        let build_group = &pipeline.steps[0];
        assert_eq!(build_group["group"], json!("build"));
        let keys = build_group["steps"]
            .as_array()
            .expect("build steps")
            .iter()
            .map(|step| step["key"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                format!("build_x86_64_{suffix}"),
                format!("build_aarch64_{suffix}")
            ]
        );

        // Later steps download that artifact and depend on it.
        let test_command = pipeline.devtool_test(None, Some("-m nonci"));
        pipeline
            .build_group(&json!({"label": "unit", "command": test_command}), true)
            .expect("group is built");
        let step = &pipeline.steps[1]["steps"][0];
        let step_commands = commands(step);
        assert_eq!(
            step_commands[0],
            format!("buildkite-agent artifact download \"{shared}\" .")
        );
        assert_eq!(step_commands[1], format!("tar xzf {shared}"));
        assert_eq!(
            step["depends_on"],
            json!([pipeline.build_key(&shared, "x86_64")])
        );
        // `--no-build` is used because the binaries are shared.
        assert!(step_commands[2].contains("--no-build"), "{step_commands:?}");
    }

    #[test]
    fn build_key_strips_the_artifact_suffix() {
        let pipeline = pipeline_with(args_without_build(
            &["m6i.metal"],
            &[("al2023", "linux_6.1")],
        ));
        assert_eq!(
            pipeline.build_key("build_$(uname -m)_abc.tar.gz", "aarch64"),
            "build_aarch64_abc"
        );
        assert_eq!(
            pipeline.build_key("snap-create-x", "x86_64"),
            "snap-create-x"
        );
    }

    #[test]
    fn chunk_steps_splits_groups_to_fit_max_jobs() {
        let mut pipeline = pipeline_with(args_without_build(
            &["m6i.metal", "m7g.metal"],
            &[("al2023", "linux_6.1")],
        ));
        pipeline
            .build_group(&json!({"label": "a", "command": ["true"]}), true)
            .expect("group a");
        pipeline
            .build_group(&json!({"label": "b", "command": ["true"]}), true)
            .expect("group b");

        // Two groups of two leaf jobs each; a chunk holds at most 3 jobs.
        let chunks = pipeline.chunk_steps(3);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 1);
        assert_eq!(chunks[0][0]["steps"].as_array().expect("steps").len(), 2);
        assert_eq!(chunks[1].len(), 1);
        assert_eq!(chunks[1][0]["steps"].as_array().expect("steps").len(), 2);

        let json = pipeline.to_json().expect("pipeline serializes");
        assert!(json.starts_with("{\n    \"steps\": ["), "{json}");
        assert!(json.contains("\"group\": \"a\""));
    }

    #[test]
    fn to_json_emits_one_pipeline_per_chunk() {
        let mut pipeline = pipeline_with(args_without_build(
            &["m6i.metal"],
            &[("al2023", "linux_6.1")],
        ));
        pipeline
            .build_group(&json!({"label": "a", "command": ["true"]}), true)
            .expect("group a");
        pipeline.args.max_jobs = Some(2);

        let json = pipeline.to_json().expect("pipeline serializes");
        assert!(json.starts_with("[\n    {"), "{json}");
        let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed.as_array().is_some());
    }

    #[test]
    fn perf_pipeline_generates_pytest_commands() {
        let pipeline = build_perf_pipeline(
            args_without_build(&["m6i.metal"], &[("al2023", "linux_6.1")]),
            &AbRevisions::default(),
            &["boottime".to_string()],
        )
        .expect("perf pipeline is built");

        let step = &pipeline.steps[0]["steps"][0];
        assert_eq!(step["label"], json!("boottime-m6i.metal-al2023-linux_6.1"));
        assert_eq!(step["priority"], json!(2));
        assert_eq!(step["agents"]["ag"], json!(1));
        assert_eq!(step["env"]["FC_TEST_DUMP_ON_FAILURE"], json!("1"));
        let step_commands = commands(step);
        // The double space matches python: `-m ''` is prefixed by a space.
        assert_eq!(
            step_commands[2],
            "./tools/devtool -y test -c 1-10 -m 0 --performance -- --binary-dir=../build/$(uname -m)  -m '' integration_tests/performance/test_boottime.py::test_boottime"
        );
    }

    #[test]
    fn perf_pipeline_runs_every_test_in_catalog_order() {
        let pipeline = build_perf_pipeline(
            args_without_build(&["m6i.metal"], &[("al2023", "linux_6.1")]),
            &AbRevisions::default(),
            &[],
        )
        .expect("perf pipeline is built");

        assert_eq!(pipeline.steps.len(), perf_tests().len());
        for (index, (_, test)) in perf_tests().iter().enumerate() {
            let label = pipeline.steps[index]["steps"][0]["label"]
                .as_str()
                .unwrap_or_default();
            assert_eq!(label, format!("{}-m6i.metal-al2023-linux_6.1", test.label));
        }
        assert_eq!(
            perf_tests().first().expect("catalog").1.label,
            "virtio-block-sync"
        );
        assert_eq!(perf_test_by_name("nope"), None);
        assert!(build_perf_pipeline(
            args_without_build(&["m6i.metal"], &[("al2023", "linux_6.1")]),
            &AbRevisions::default(),
            &["nope".to_string()],
        )
        .is_err());
    }

    #[test]
    fn perf_pipeline_uses_ab_options_when_revisions_are_set() {
        let pipeline = build_perf_pipeline(
            args_without_build(&["m6i.metal"], &[("al2023", "linux_6.1")]),
            &AbRevisions {
                a: Some("rev-a".to_string()),
                b: Some("rev-b".to_string()),
                a_artifacts: Some("s3://a".to_string()),
                b_artifacts: Some("s3://b".to_string()),
            },
            &["vhost-user-block".to_string()],
        )
        .expect("perf pipeline is built");

        let step_commands = commands(&pipeline.steps[0]["steps"][0]);
        assert_eq!(
            step_commands[2],
            "./tools/devtool -y download_ci_artifacts s3://a s3://b"
        );
        assert_eq!(
            step_commands[3],
            "./tools/devtool -y test -c 1-10 -m 0 --performance --ab -- --binary-dir=../build/$(uname -m) --noise-threshold bw_read=0.1 run --binaries-a build/rev-a/ --binaries-b build/rev-b --max-iterations=4 --pytest-opts \"integration_tests/performance/test_block.py::test_block_vhost_user_performance\" --artifacts-a s3://a --artifacts-b s3://b"
        );
    }

    #[test]
    fn perf_pipeline_honours_per_test_max_iterations() {
        let pipeline = build_perf_pipeline(
            args_without_build(&["m6i.metal"], &[("al2023", "linux_6.1")]),
            &AbRevisions {
                a: Some("rev-a".to_string()),
                b: Some("rev-b".to_string()),
                ..AbRevisions::default()
            },
            &["mmds".to_string()],
        )
        .expect("perf pipeline is built");

        let step_commands = commands(&pipeline.steps[0]["steps"][0]);
        assert!(
            step_commands[2].contains("--max-iterations=30"),
            "{}",
            step_commands[2]
        );
        assert!(step_commands[2]
            .contains("--pytest-opts \"integration_tests/performance/test_mmds.py\""));
    }

    #[test]
    fn ab_revisions_validate_pairing() {
        assert!(AbRevisions::default().validate().is_ok());
        assert!(AbRevisions {
            a: Some("a".to_string()),
            b: None,
            ..AbRevisions::default()
        }
        .validate()
        .is_err());
        assert!(AbRevisions {
            a: Some("a".to_string()),
            b: Some("b".to_string()),
            a_artifacts: Some("x".to_string()),
            b_artifacts: None,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn cross_pipeline_generates_restore_steps() {
        let pipeline = build_cross_pipeline(args_without_build(
            &["m6i.metal"],
            &[("al2023", "linux_6.1")],
        ))
        .expect("cross pipeline is built");

        // snapshot-create, snapshot-create-aarch64 and the restore group.
        assert_eq!(pipeline.steps.len(), 3);
        assert_eq!(pipeline.steps[0]["group"], json!("snapshot-create"));
        assert_eq!(pipeline.steps[1]["group"], json!("snapshot-create-aarch64"));

        let create_steps = pipeline.steps[0]["steps"].as_array().expect("steps");
        // 7 x86_64 instances x 3 default platforms.
        assert_eq!(create_steps.len(), 21);
        assert_eq!(
            create_steps[0]["key"],
            json!("snap-create-m5n_metal-linux_5_10")
        );
        let create_commands = commands(&create_steps[0]);
        assert_eq!(
            create_commands[2],
            "./tools/devtool -y test --no-archive -- --binary-dir=../build/$(uname -m) -m nonci -n4 integration_tests/functional/test_snapshot_phase1.py"
        );
        assert!(create_commands[3].contains("fallocate -d"));
        assert_eq!(create_commands[5], "mkdir -pv snapshots");
        assert_eq!(
            create_commands[6],
            "tar cSvf snapshots/m5n.metal_linux_5.10.tar snapshot_artifacts"
        );
        // 4 aarch64 instances x 1 platform.
        assert_eq!(
            pipeline.steps[1]["steps"].as_array().expect("steps").len(),
            4
        );

        let restore_group = &pipeline.steps[2];
        assert_eq!(
            restore_group["group"],
            json!("snapshot-restore-across-instances-and-kernels")
        );
        let restore_steps = restore_group["steps"].as_array().expect("steps");
        assert_eq!(restore_steps.len(), 39);

        let same_instance = restore_steps
            .iter()
            .find(|step| {
                step["label"]
                    == json!("snapshot-restore-src-m5n.metal-linux_5.10-dst-m5n.metal-linux_6.1")
            })
            .expect("same-instance restore exists");
        assert_eq!(
            same_instance["depends_on"],
            json!(["snap-create-m5n_metal-linux_5_10"])
        );
        assert_eq!(
            same_instance["agents"],
            json!({"instance": "m5n.metal", "kv": "linux_6.1", "os": "al2023"})
        );
        let restore_commands = commands(same_instance);
        assert_eq!(
            restore_commands[2],
            "buildkite-agent artifact download snapshots/m5n.metal_linux_5.10.tar ."
        );
        assert_eq!(
            restore_commands[3],
            "tar xSvf snapshots/m5n.metal_linux_5.10.tar"
        );
        assert_eq!(
            restore_commands[4],
            "./tools/devtool -y test -- --binary-dir=../build/$(uname -m) -m nonci -n8 --dist worksteal -k 'not None' integration_tests/functional/test_snapshot_restore_cross_kernel.py"
        );
        // Steps carry the per-instance defaults.
        assert_eq!(
            same_instance["artifact_paths"],
            json!(["./test_results/**/*"])
        );
        assert_eq!(same_instance["timeout"], json!(30));

        // m6a is not in the keyword map, so it gets no `-k` filter.
        let m6a = restore_steps
            .iter()
            .find(|step| step["agents"]["instance"] == json!("m6a.metal"))
            .expect("m6a restore exists");
        assert!(!commands(m6a)[4].contains("-k"));

        // Older to newer restores are skipped.
        assert!(!restore_steps.iter().any(|step| step["label"]
            == json!("snapshot-restore-src-m6i.metal-linux_6.1-dst-m6i.metal-linux_5.10")));
        // 5.10 -> 6.18 is not adjacent and is skipped.
        assert!(!restore_steps.iter().any(|step| step["label"]
            == json!("snapshot-restore-src-m6i.metal-linux_5.10-dst-m6i.metal-linux_6.18")));
        // Cross-instance restores are limited to the allow-list.
        assert!(!restore_steps.iter().any(|step| {
            step["agents"]["instance"] == json!("m7i.metal-24xl")
                && step["label"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("snapshot-restore-src-m5n.metal")
        }));
    }

    #[test]
    fn cpu_template_plain_groups_use_the_full_instance_list() {
        let pipeline = build_cpu_template_pipeline(
            args_without_build(&["m6i.metal"], &[("al2023", "linux_6.1")]),
            &["rdmsr".to_string()],
        )
        .expect("cpu template pipeline is built");

        let grp = &pipeline.steps[0];
        assert_eq!(grp["group"], json!("rdmsr"));
        let steps = grp["steps"].as_array().expect("steps");
        assert_eq!(steps.len(), CPU_TEMPLATE_INSTANCES.len());
        assert_eq!(steps[0]["label"], json!("rdmsr-m5n.metal-al2023-linux_6.1"));
        let step_commands = commands(&steps[0]);
        assert!(step_commands[2].contains("-n4 --dist worksteal"));
        assert!(step_commands[2].contains("-k 'test_cpu_rdmsr'"));
        // `artifact_paths` comes from the pipeline defaults, `artifacts` from
        // the test definition, exactly like python.
        assert_eq!(steps[0]["artifact_paths"], json!(["./test_results/**/*"]));
        assert_eq!(steps[0]["artifacts"], json!(["./test_results/**/*"]));
    }

    #[test]
    fn cpu_template_fingerprint_uses_the_pipeline_platforms() {
        let pipeline = build_cpu_template_pipeline(
            args_without_build(&["m6i.metal", "m7g.metal"], &[("al2023", "linux_6.1")]),
            &["fingerprint".to_string()],
        )
        .expect("cpu template pipeline is built");

        let steps = pipeline.steps[0]["steps"].as_array().expect("steps");
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0]["label"],
            json!("fingerprint-m6i.metal-al2023-linux_6.1")
        );
        assert_eq!(
            steps[1]["label"],
            json!("fingerprint-m7g.metal-al2023-linux_6.1")
        );
    }

    #[test]
    fn cpu_template_snapshot_restore_groups() {
        let pipeline = build_cpu_template_pipeline(
            args_without_build(&["m6i.metal"], &[("al2023", "linux_6.1")]),
            &["cpuid_wrmsr".to_string()],
        )
        .expect("cpu template pipeline is built");

        assert_eq!(pipeline.steps.len(), 2);
        let snapshot = &pipeline.steps[0];
        assert_eq!(snapshot["key"], json!("snapshot"));
        assert_eq!(snapshot["group"], json!("snapshot-create"));
        let snapshot_steps = snapshot["steps"].as_array().expect("steps");
        // 5 instances x 3 default platforms.
        assert_eq!(snapshot_steps.len(), 15);
        assert_eq!(
            snapshot_steps[0]["label"],
            json!("snapshot-create-m5n.metal-al2-linux_5.10")
        );
        assert_eq!(snapshot_steps[0]["timeout"], json!(30));
        assert_eq!(
            snapshot_steps[0]["artifacts"],
            json!("tests/snapshot_artifacts_upload/**/*")
        );
        let snapshot_commands = commands(&snapshot_steps[0]);
        assert!(snapshot_commands[2].contains("-n4 --dist worksteal"));
        assert_eq!(
            snapshot_commands[3],
            "mkdir -pv tests/snapshot_artifacts_upload/m5n.metal_al2_linux_5.10"
        );

        let restore = &pipeline.steps[1];
        assert_eq!(restore["group"], json!("snapshot-restore"));
        assert_eq!(restore["depends_on"], json!("snapshot"));
        let restore_steps = restore["steps"].as_array().expect("steps");
        // 3 platforms x (5 own instances + 2 cross-instance restores).
        assert_eq!(restore_steps.len(), 21);
        let first = &restore_steps[0];
        assert_eq!(
            first["label"],
            json!("snapshot-restore-src-m5n.metal-al2-linux_5.10-dst-m5n.metal-al2-linux_5.10")
        );
        let restore_commands = commands(first);
        assert_eq!(
            restore_commands[2],
            "buildkite-agent artifact download tests/snapshot_artifacts_upload/m5n.metal_al2_linux_5.10/**/* ."
        );
        assert!(
            restore_commands[4].contains("-k 'test_cpu_wrmsr_restore or test_cpu_cpuid_restore'")
        );
        assert_eq!(
            first["agents"],
            json!({"instance": "m5n.metal", "kv": "linux_5.10", "os": "al2"})
        );

        // m5n snapshots are also restored on m6i, and vice versa, and nothing
        // else is restored across instances.
        assert!(restore_steps
            .iter()
            .any(|step| step["label"].as_str().unwrap_or_default()
                == "snapshot-restore-src-m5n.metal-al2-linux_5.10-dst-m6i.metal-al2-linux_5.10"));
        assert!(!restore_steps.iter().any(|step| step["label"]
            .as_str()
            .unwrap_or_default()
            .starts_with("snapshot-restore-src-m7a.metal-48xl-")
            && step["label"]
                .as_str()
                .unwrap_or_default()
                .contains("-dst-m6i.metal-")));
    }

    #[test]
    fn apply_pins_retags_matching_agents() {
        let steps = vec![json!({
            "label": "a",
            "agents": {"instance": "m6i.metal", "kv": "linux_6.1", "os": "al2023"},
        })];
        let pins = json!({"linux_6.1-pinned": {"instance": "m6i.metal", "kv": "linux_6.1"}});
        let pinned = apply_pins(&steps, &pins);
        assert_eq!(pinned[0]["agents"]["kv"], json!("linux_6.1-pinned"));

        let untouched = apply_pins(
            &[json!({
                "label": "b",
                "agents": {"instance": "m6a.metal", "kv": "linux_6.1"},
            })],
            &pins,
        );
        assert_eq!(untouched[0]["agents"]["kv"], json!("linux_6.1"));

        let grouped = apply_pins(&[json!({"group": "g", "steps": steps})], &pins);
        assert_eq!(
            grouped[0]["steps"][0]["agents"]["kv"],
            json!("linux_6.1-pinned")
        );
        // No pins configured (the perf pipeline default) keeps everything.
        assert_eq!(apply_pins(&steps, &json!({})), steps);
    }

    #[test]
    fn parse_platform_and_step_params() {
        assert_eq!(
            parse_platform("al2023-linux_6.1").expect("valid platform"),
            ("al2023".to_string(), "linux_6.1".to_string())
        );
        assert_eq!(
            parse_platform("al2023-linux-6.1").expect("split on the first dash"),
            ("al2023".to_string(), "linux-6.1".to_string())
        );
        assert!(parse_platform("al2023").is_err());

        assert_eq!(
            parse_step_param("timeout=30").expect("scalar"),
            json!({"timeout": "30"})
        );
        assert_eq!(
            parse_step_param("a/b/c=3").expect("nested"),
            json!({"a": {"b": {"c": "3"}}})
        );
        assert_eq!(
            parse_step_param("agents/env=[1, 2]").expect("list literal"),
            json!({"agents": {"env": [1, 2]}})
        );
        assert_eq!(
            parse_step_param("priority={}").expect("dict literal"),
            json!({"priority": {}})
        );
        assert_eq!(
            parse_step_param("label='hello'").expect("string literal"),
            json!({"label": "hello"})
        );
        assert!(parse_step_param("novalue").is_err());
        assert!(parse_step_param("/a=1").is_err());
    }

    #[test]
    fn random_str_uses_hex_digits() {
        let value = random_str(12);
        assert_eq!(value.len(), 12);
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(random_str(16), random_str(16));
    }

    #[test]
    fn run_all_tests_ignores_documentation_changes() {
        assert!(run_all_tests(&[]));
        assert!(!run_all_tests(&[PathBuf::from("docs/design.md")]));
        assert!(!run_all_tests(&[PathBuf::from(".github/workflows/ci.yml")]));
        assert!(run_all_tests(&[PathBuf::from("src/main.rs")]));
        assert!(run_all_tests(&[
            PathBuf::from("docs/design.md"),
            PathBuf::from("tests/framework/defs.py"),
        ]));
    }

    #[test]
    fn ci_artifacts_change_mode_tracks_both_halves() {
        assert_eq!(ci_artifacts_change_mode(&[]), None);
        assert_eq!(
            ci_artifacts_change_mode(&[PathBuf::from("resources/rootfs/ubuntu.sh")]),
            Some("rootfs")
        );
        assert_eq!(
            ci_artifacts_change_mode(&[PathBuf::from(
                "resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config"
            )]),
            Some("kernels")
        );
        assert_eq!(
            ci_artifacts_change_mode(&[PathBuf::from("resources/patches/0001.patch")]),
            Some("kernels")
        );
        assert_eq!(
            ci_artifacts_change_mode(&[
                PathBuf::from("resources/rootfs/ubuntu.sh"),
                PathBuf::from("resources/patches/0001.patch"),
            ]),
            Some("all")
        );
        assert_eq!(
            ci_artifacts_change_mode(&[PathBuf::from("resources/rebuild.sh")]),
            Some("all")
        );
        assert_eq!(
            ci_artifacts_change_mode(&[PathBuf::from("src/main.rs")]),
            None
        );
    }
}
