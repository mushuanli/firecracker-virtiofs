// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generates Firecracker's Buildkite pipelines, replacing the
//! `.buildkite/pipeline_cross.py`, `pipeline_perf.py` and
//! `pipeline_cpu_template.py` entry points.
//!
//! ```text
//! fc-pipeline cross                                   # pipeline_cross.py
//! fc-pipeline perf --test block --test snapshot       # pipeline_perf.py --test ...
//! fc-pipeline cpu-template --test [...]
//! ```
//!
//! The JSON printed on stdout is byte-identical to what the python scripts emit
//! for the same flags; see `src/pipeline.rs` for the port itself.

use anyhow::Result;
use clap::{Parser, Subcommand};

use fc_harness::pipeline::{
    build_cpu_template_pipeline, build_cross_pipeline, build_perf_pipeline, AbRevisions,
    PipelineCli,
};

#[derive(Parser, Debug)]
#[command(
    name = "fc-pipeline",
    about = "Generate a Buildkite pipeline for the Firecracker test suite"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Cross-platform (cross-kernel) test pipeline.
    Cross {
        #[command(flatten)]
        args: PipelineCli,
    },
    /// Performance test pipeline, optionally restricted to specific tests.
    Perf {
        #[command(flatten)]
        args: PipelineCli,
        /// Only build the named performance tests.
        #[arg(long = "test", value_name = "NAME")]
        test: Vec<String>,
    },
    /// CPU template (snapshot/restore) pipeline, optionally restricted.
    CpuTemplate {
        #[command(flatten)]
        args: PipelineCli,
        /// Only build the named CPU template tests.
        #[arg(long = "test", value_name = "NAME")]
        test: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let pipeline = match cli.command {
        Command::Cross { args } => build_cross_pipeline(args.to_args()?)?,
        Command::Perf { args, test } => {
            let revisions = AbRevisions::from_env()?;
            build_perf_pipeline(args.to_args()?, &revisions, &test)?
        }
        Command::CpuTemplate { args, test } => build_cpu_template_pipeline(args.to_args()?, &test)?,
    };
    println!("{}", pipeline.to_json()?);
    Ok(())
}
