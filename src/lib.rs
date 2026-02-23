// Copyright (c) 2026 Adrian Lorenz <a.lorenz@noa-x.de>
// SPDX-License-Identifier: MIT

pub mod cli;
pub mod config;
pub mod output;
pub mod rules;
pub mod scanner;

use std::time::Instant;

pub fn run_main() -> i32 {
    run_main_with_args(std::env::args())
}

pub(crate) fn run_main_with_args(args: impl IntoIterator<Item = String>) -> i32 {
    match run_main_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

fn run_main_inner(args: impl IntoIterator<Item = String>) -> anyhow::Result<i32> {
    use clap::Parser as _;
    use colored::Colorize as _;

    use cli::{Cli, Commands, OutputFormat};
    use config::{Config, default_config_toml};
    use output::{print_json, print_markdown, print_pretty, print_sarif, write_github_summary};
    use rules::builtin_rules;
    use scanner::Scanner;

    let cli = Cli::parse_from(args);
    match cli.command {
        Commands::InitConfig => {
            let path = std::path::PathBuf::from("leakguard.toml");
            if path.exists() {
                eprintln!("{} leakguard.toml already exists", "Error:".red());
                return Ok(1);
            }
            std::fs::write(&path, default_config_toml())?;
            println!("{} Created leakguard.toml", "✅".green());
        }

        Commands::Rules => {
            println!("{}", "📋 leakguard — Built-in Detection Rules\n".bold());
            println!(
                "{:<35} {:<10} {:<46} {}",
                "ID".underline(),
                "SEVERITY".underline(),
                "DESCRIPTION".underline(),
                "TAGS".underline()
            );
            for rule in builtin_rules() {
                println!(
                    "{:<35} {:<10} {:<46} {}",
                    rule.id.cyan(),
                    rule.severity.to_string(),
                    rule.description,
                    rule.tags.join(", ").dimmed()
                );
            }
            println!("\n{} rules total", builtin_rules().len().to_string().yellow());
        }

        Commands::Check {
            source,
            format,
            verbose,
            max_size,
            config: config_path,
            github_summary,
            warnings,
        } => {
            let cfg = Config::load_auto(config_path.as_ref());
            let rules = builtin_rules();
            let rule_count = rules.len();
            let disabled = cfg.rules.disable.len();
            let scanner = Scanner::new(rules, max_size, &cfg)?;
            let ext_display = if cfg.scan.extensions.is_empty() {
                "all (except .env)".to_string()
            } else {
                cfg.scan.extensions.join(", ")
            };
            println!(
                "{}",
                format!(
                    "🔍 leakguard v{} — scanning '{}' | {} rules ({} disabled) | files: [{}]",
                    env!("CARGO_PKG_VERSION"),
                    source.display(),
                    rule_count,
                    disabled,
                    ext_display
                )
                .bold()
            );

            let start = Instant::now();
            let (mut findings, stats) = if source.is_dir() {
                scanner.scan_directory(&source, verbose)?
            } else {
                scanner.scan_file(&source)?
            };
            let elapsed = start.elapsed();

            findings.sort_by(|a, b| {
                fn sev_order(s: &str) -> u8 {
                    match s {
                        "CRITICAL" => 0,
                        "HIGH" => 1,
                        "MEDIUM" => 2,
                        "LOW" => 3,
                        _ => 4,
                    }
                }
                sev_order(&a.severity)
                    .cmp(&sev_order(&b.severity))
                    .then(a.file.cmp(&b.file))
                    .then(a.line_number.cmp(&b.line_number))
            });

            let visible: Vec<_> = findings
                .iter()
                .filter(|f| warnings || f.severity != "WARNING")
                .collect();

            match format {
                OutputFormat::Pretty => print_pretty(&findings, warnings),
                OutputFormat::Json => print_json(&visible)?,
                OutputFormat::Sarif => print_sarif(&visible)?,
                OutputFormat::Markdown => print_markdown(&visible),
            }

            if matches!(format, OutputFormat::Pretty | OutputFormat::Markdown) {
                let ms = elapsed.as_millis();
                let time_str = if ms < 1000 {
                    format!("{}ms", ms)
                } else {
                    format!("{:.2}s", elapsed.as_secs_f64())
                };
                eprintln!(
                    "\n{}",
                    format!("Scanned {} file(s), {} line(s) in {}", stats.files, stats.lines, time_str)
                        .dimmed()
                );
            }

            if github_summary {
                write_github_summary(&findings, &source)?;
                eprintln!("{} GitHub Job Summary written", "✅".green());
            }

            if findings
                .iter()
                .any(|f| matches!(f.severity.as_str(), "CRITICAL" | "HIGH" | "MEDIUM"))
            {
                return Ok(1);
            }
        }
    }
    Ok(0)
}

#[cfg(feature = "extension-module")]
mod python {
    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    use crate::config::Config;
    use crate::rules::builtin_rules;
    use crate::scanner::Scanner;

    #[pyclass(get_all)]
    #[derive(Clone)]
    pub struct PyFinding {
        pub rule_id: String,
        pub description: String,
        pub severity: String,
        pub line_number: usize,
        pub line: String,
        pub secret: String,
        pub secret_hash: String,
        pub tags: Vec<String>,
    }

    /// Scan text for secrets and return a list of findings.
    ///
    /// Arguments:
    ///   text: The text to scan for secrets.
    ///   disable_rules: Optional list of rule IDs to disable.
    ///   replace_secret_with: Optional placeholder to replace masked secret output.
    #[pyfunction]
    #[pyo3(signature = (text, disable_rules=None, replace_secret_with=None))]
    fn scan_text(
        text: &str,
        disable_rules: Option<Vec<String>>,
        replace_secret_with: Option<String>,
    ) -> PyResult<Vec<PyFinding>> {
        let mut cfg = Config::default();
        if let Some(disabled) = disable_rules {
            cfg.rules.disable = disabled;
        }
        let rules = builtin_rules();
        let scanner = Scanner::new(rules, u64::MAX, &cfg)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let findings = scanner.scan_text(text, "<text>");
        Ok(findings
            .into_iter()
            .map(|f| {
                let secret = replace_secret_with.clone().unwrap_or(f.secret);
                PyFinding {
                    rule_id: f.rule_id,
                    description: f.description,
                    severity: f.severity,
                    line_number: f.line_number,
                    line: f.line,
                    secret,
                    secret_hash: f.secret_hash,
                    tags: f.tags,
                }
            })
            .collect())
    }

    /// Scan text for secrets and return a list of plain dict objects.
    ///
    /// This is useful for direct Pydantic validation without `from_attributes=True`.
    ///
    /// Arguments:
    ///   text: The text to scan for secrets.
    ///   disable_rules: Optional list of rule IDs to disable.
    ///   replace_secret_with: Optional placeholder to replace masked secret output.
    #[pyfunction]
    #[pyo3(signature = (text, disable_rules=None, replace_secret_with=None))]
    fn scan_text_dict(
        py: Python<'_>,
        text: &str,
        disable_rules: Option<Vec<String>>,
        replace_secret_with: Option<String>,
    ) -> PyResult<Vec<Py<PyDict>>> {
        let mut cfg = Config::default();
        if let Some(disabled) = disable_rules {
            cfg.rules.disable = disabled;
        }
        let rules = builtin_rules();
        let scanner = Scanner::new(rules, u64::MAX, &cfg)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let findings = scanner.scan_text(text, "<text>");

        let mut out = Vec::with_capacity(findings.len());
        for f in findings {
            let secret = replace_secret_with.clone().unwrap_or(f.secret);
            let d = PyDict::new(py);
            d.set_item("rule_id", f.rule_id)?;
            d.set_item("description", f.description)?;
            d.set_item("severity", f.severity)?;
            d.set_item("line_number", f.line_number)?;
            d.set_item("line", f.line)?;
            d.set_item("secret", secret)?;
            d.set_item("secret_hash", f.secret_hash)?;
            d.set_item("tags", f.tags)?;
            out.push(d.unbind());
        }
        Ok(out)
    }

    /// Replace detected secrets in text and return sanitized text.
    ///
    /// Arguments:
    ///   text: The input text to sanitize.
    ///   disable_rules: Optional list of rule IDs to disable.
    ///   replacement: Replacement token used for every detected secret.
    #[pyfunction]
    #[pyo3(signature = (text, disable_rules=None, replacement="[REDACTED_SECRET]"))]
    fn replace_text(
        text: &str,
        disable_rules: Option<Vec<String>>,
        replacement: &str,
    ) -> PyResult<(String, bool)> {
        let mut cfg = Config::default();
        if let Some(disabled) = disable_rules {
            cfg.rules.disable = disabled;
        }
        let rules = builtin_rules();
        let scanner = Scanner::new(rules, u64::MAX, &cfg)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let (sanitized, count) = scanner.replace_text_with_stats(text, replacement);
        Ok((sanitized, count > 0))
    }

    /// Run the leakguard CLI. Exits the process with an appropriate exit code.
    #[pyfunction]
    fn run_cli() {
        // When invoked as a pip console script the process args are:
        //   [python_interpreter, /path/to/bin/leakguard, subcommand, ...]
        // Skip argv[0] (the interpreter) so clap sees [script_path, subcommand, ...]
        let args: Vec<String> = std::env::args().skip(1).collect();
        std::process::exit(crate::run_main_with_args(args));
    }

    #[pymodule]
    fn leakguard(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(scan_text, m)?)?;
        m.add_function(wrap_pyfunction!(scan_text_dict, m)?)?;
        m.add_function(wrap_pyfunction!(replace_text, m)?)?;
        m.add_function(wrap_pyfunction!(run_cli, m)?)?;
        m.add_class::<PyFinding>()?;
        Ok(())
    }
}
