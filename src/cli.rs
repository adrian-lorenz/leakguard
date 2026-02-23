// Copyright (c) 2026 Adrian Lorenz <a.lorenz@noa-x.de>
// SPDX-License-Identifier: MIT

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "leakguard", about = "🔍 Fast secret scanner for your codebase", version = "0.2.0")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    Check {
        #[arg(short, long, default_value = ".")]
        source: PathBuf,
        #[arg(short, long, default_value = "pretty")]
        format: OutputFormat,
        #[arg(short, long)]
        verbose: bool,
        #[arg(long, default_value = "1024")]
        max_size: u64,
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Write a GitHub Actions Job Summary to $GITHUB_STEP_SUMMARY
        #[arg(long)]
        github_summary: bool,
        /// Show WARNING-level findings in detail (hidden by default)
        #[arg(long)]
        warnings: bool,
    },
    Rules,
    InitConfig,
}

#[derive(ValueEnum, Clone)]
pub(crate) enum OutputFormat {
    Pretty,
    Json,
    Sarif,
    Markdown,
}
