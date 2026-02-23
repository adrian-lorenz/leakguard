// Copyright (c) 2026 Adrian Lorenz <a.lorenz@noa-x.de>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use colored::Colorize;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;
use walkdir::WalkDir;

use crate::config::Config;
use crate::rules::Rule;

#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub description: String,
    pub severity: String,
    pub file: String,
    pub line_number: usize,
    pub line: String,
    pub secret: String,
    pub tags: Vec<String>,
}

pub struct ScanStats {
    pub files: usize,
    pub lines: usize,
}

pub struct Scanner {
    rules: Vec<(Rule, Regex)>,
    max_size_bytes: u64,
    allowed_extensions: HashSet<String>,
    exclude_paths: Vec<String>,
    exclude_files: HashSet<String>,
}

const SUPPRESS_MARKERS: &[&str] = &["# leakguard-ignore", "# noqa-secrets", "# nosec-secrets"];
const SKIP_DIRS: &[&str] = &[".git","node_modules","target","vendor","__pycache__","dist","build",".eggs",".tox",".mypy_cache"];
// Any directory whose name starts with one of these prefixes is skipped (.venv, .venv2, venv, venv3, .virtualenv, …)
const SKIP_DIR_PREFIXES: &[&str] = &[".venv", "venv", ".virtualenv", "virtualenv"];

impl Scanner {
    pub fn new(rules: Vec<Rule>, max_size_kb: u64, cfg: &Config) -> Result<Self> {
        let disabled = cfg.disabled_rules();
        let compiled: Result<Vec<_>> = rules.into_iter()
            .filter(|r| !disabled.contains(r.id))
            .map(|rule| {
                let re = Regex::new(rule.pattern).with_context(|| format!("Bad regex in rule '{}'", rule.id))?;
                Ok((rule, re))
            })
            .collect();
        Ok(Self {
            rules: compiled?,
            max_size_bytes: max_size_kb.saturating_mul(1024),
            allowed_extensions: cfg.allowed_extensions(),
            exclude_paths: cfg.scan.exclude_paths.clone(),
            exclude_files: cfg.scan.exclude_files.iter().cloned().collect(),
        })
    }

    fn is_allowed_path(&self, path: &Path) -> bool {
        let fname = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
        if fname == ".env" || fname.starts_with(".env.") || fname.ends_with(".env") { return false; }
        let ext = path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).unwrap_or_default();
        if ext == "env" { return false; }
        if !self.allowed_extensions.is_empty() && !self.allowed_extensions.contains(&ext) { return false; }
        if self.exclude_files.contains(fname.as_ref()) { return false; }
        let path_str = path.to_string_lossy();
        for excl in &self.exclude_paths {
            if path_str.contains(excl.as_str()) { return false; }
        }
        true
    }

    pub fn scan_text(&self, text: &str, source_name: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (ln, line) in text.lines().enumerate() {
            if SUPPRESS_MARKERS.iter().any(|&m| line.contains(m)) { continue; }
            for (rule, regex) in &self.rules {
                for caps in regex.captures_iter(line) {
                    let secret = caps.get(rule.secret_group).map(|m| m.as_str().to_string()).unwrap_or_default();
                    if secret.is_empty() { continue; }
                    // Skip template variables: {VAR}, ${VAR}, %(var)s
                    if secret.contains('{') || secret.contains("%(") || secret.contains('$') { continue; }
                    // Skip variable/property references on RHS (e.g. settings.DB_PASSWORD, config.key)
                    if is_var_ref(&secret) { continue; }
                    if rule.id == "http-insecure-url" && (secret.contains("localhost") || secret.contains("127.0.") || secret.contains("0.0.0.0")) { continue; }
                    findings.push(Finding {
                        rule_id: rule.id.to_string(),
                        description: rule.description.to_string(),
                        severity: rule.severity.to_string(),
                        file: source_name.to_string(),
                        line_number: ln + 1,
                        line: truncate_line(line.trim()),
                        secret: redact_secret(&secret),
                        tags: rule.tags.iter().map(|t| t.to_string()).collect(),
                    });
                }
            }
        }
        findings
    }

    pub fn scan_file(&self, path: &Path) -> Result<(Vec<Finding>, ScanStats)> {
        if !self.is_allowed_path(path) { return Ok((vec![], ScanStats { files: 0, lines: 0 })); }
        let meta = std::fs::metadata(path)?;
        if meta.len() == 0 || meta.len() > self.max_size_bytes { return Ok((vec![], ScanStats { files: 1, lines: 0 })); }
        let content = std::fs::read(path)?;
        let sample = &content[..content.len().min(512)];
        if sample.iter().filter(|&&b| b < 7 || b == 127).count() * 100 / sample.len().max(1) > 30 { return Ok((vec![], ScanStats { files: 1, lines: 0 })); }
        let text = String::from_utf8_lossy(&content);
        let line_count = text.lines().count();
        let findings = self.scan_text(&text, &path.display().to_string());
        Ok((findings, ScanStats { files: 1, lines: line_count }))
    }

    pub fn scan_directory(&self, dir: &Path, verbose: bool) -> Result<(Vec<Finding>, ScanStats)> {
        let mut all = Vec::new();
        let mut stats = ScanStats { files: 0, lines: 0 };
        for entry in WalkDir::new(dir).follow_links(false).into_iter()
            .filter_entry(|e| {
                let n = e.file_name().to_string_lossy();
                !SKIP_DIRS.iter().any(|&s| n == s)
                    && !SKIP_DIR_PREFIXES.iter().any(|&p| n.starts_with(p))
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            if verbose {
                if self.is_allowed_path(path) { eprintln!("{} {}", "Scanning:".dimmed(), path.display().to_string().dimmed()); }
                else { eprintln!("{} {} (skipped)", "Ignored:".dimmed(), path.display().to_string().dimmed()); }
            }
            match self.scan_file(path) {
                Ok((f, s)) => { all.extend(f); stats.files += s.files; stats.lines += s.lines; }
                Err(e)     => { if verbose { eprintln!("{} {}: {}", "Warning:".yellow(), path.display(), e); } }
            }
        }
        Ok((all, stats))
    }
}

/// Returns true if the matched text looks like a variable/property reference
/// on the right-hand side of an assignment (e.g. `settings.DB_PASSWORD`, `config.key`).
fn is_var_ref(s: &str) -> bool {
    let val = s.find('=')
        .map(|i| s[i + 1..].trim())
        .unwrap_or("");
    !val.is_empty()
        && val.contains('.')
        && val.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

fn truncate_line(s: &str) -> String {
    let mut chars = s.chars();
    let head: String = chars.by_ref().take(200).collect();
    if chars.next().is_some() { format!("{head}…") } else { head }
}

fn redact_secret(s: &str) -> String {
    let len = s.len();
    if len <= 8 { return "*".repeat(len); }
    let v = len.min(4);
    format!("{}...[REDACTED]...{}", &s[..v], &s[len-v..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::rules::builtin_rules;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn default_scanner() -> Scanner {
        Scanner::new(builtin_rules(), 1024, &Config::default()).unwrap()
    }

    // ── redact_secret ────────────────────────────────────────────────────────

    #[test]
    fn redact_short_keeps_asterisks() {
        assert_eq!(redact_secret("abc"),      "***");
        assert_eq!(redact_secret("12345678"), "********");
    }

    #[test]
    fn redact_long_shows_prefix_and_suffix() {
        let r = redact_secret("AKIAIOSFODNN7EXAMPLE");
        assert!(r.starts_with("AKIA"));
        assert!(r.ends_with("MPLE"));
        assert!(r.contains("...[REDACTED]..."));
    }

    // ── is_allowed_path ──────────────────────────────────────────────────────

    #[test]
    fn blocks_dotenv_file() {
        let scanner = default_scanner();
        let dir = TempDir::new().unwrap();
        for name in &[".env", ".env.local", "production.env"] {
            let path = dir.path().join(name);
            std::fs::write(&path, "SECRET=hunter2\n").unwrap();
            let findings = scanner.scan_file(&path).unwrap().0;
            assert!(findings.is_empty(), "{name} should be blocked");
        }
    }

    #[test]
    fn extension_allowlist_filters_other_files() {
        let toml = r#"[scan]
extensions = ["rs"]
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let scanner = Scanner::new(builtin_rules(), 1024, &cfg).unwrap();

        let mut py_file = NamedTempFile::with_suffix(".py").unwrap();
        writeln!(py_file, "key = AKIAIOSFODNN7EXAMPLE1234").unwrap();
        let findings = scanner.scan_file(py_file.path()).unwrap().0;
        assert!(findings.is_empty(), ".py should be skipped when only rs is allowed");
    }

    // ── scan_file: detection ─────────────────────────────────────────────────

    #[test]
    fn detects_aws_access_key() {
        let scanner = default_scanner();
        let mut f = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(f, "aws_key = AKIAIOSFODNN7EXAMPLE1234").unwrap();
        let findings = scanner.scan_file(f.path()).unwrap().0;
        assert!(findings.iter().any(|f| f.rule_id == "aws-access-key"), "aws-access-key not detected");
    }

    #[test]
    fn detects_github_pat() {
        let scanner = default_scanner();
        let mut f = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(f, "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890").unwrap();
        let findings = scanner.scan_file(f.path()).unwrap().0;
        assert!(findings.iter().any(|f| f.rule_id == "github-pat"), "github-pat not detected");
    }

    #[test]
    fn detects_stripe_secret_key() {
        let scanner = default_scanner();
        let mut f = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(f, "STRIPE_KEY=sk_live_{}", "AbCdEfGhIjKlMnOpQrStUvWx").unwrap();
        let findings = scanner.scan_file(f.path()).unwrap().0;
        assert!(findings.iter().any(|f| f.rule_id == "stripe-secret"), "stripe-secret not detected");
    }

    #[test]
    fn detects_private_key_header() {
        let scanner = default_scanner();
        let mut f = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(f, "-----BEGIN RSA PRIVATE KEY-----").unwrap();
        let findings = scanner.scan_file(f.path()).unwrap().0;
        assert!(findings.iter().any(|f| f.rule_id == "private-key-header"), "private-key-header not detected");
    }

    // ── suppression ──────────────────────────────────────────────────────────

    #[test]
    fn leakguard_ignore_suppresses_finding() {
        let scanner = default_scanner();
        let mut f = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(f, "aws_key = AKIAIOSFODNN7EXAMPLE1234  # leakguard-ignore").unwrap();
        let findings = scanner.scan_file(f.path()).unwrap().0;
        assert!(findings.is_empty(), "# leakguard-ignore should suppress the finding");
    }

    #[test]
    fn noqa_secrets_suppresses_finding() {
        let scanner = default_scanner();
        let mut f = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(f, "aws_key = AKIAIOSFODNN7EXAMPLE1234  # noqa-secrets").unwrap();
        let findings = scanner.scan_file(f.path()).unwrap().0;
        assert!(findings.is_empty(), "# noqa-secrets should suppress the finding");
    }

    // ── disabled rules ───────────────────────────────────────────────────────

    #[test]
    fn disabled_rule_is_not_triggered() {
        let toml = r#"[rules]
disable = ["github-pat"]
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let scanner = Scanner::new(builtin_rules(), 1024, &cfg).unwrap();

        let mut f = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(f, "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890").unwrap();
        let findings = scanner.scan_file(f.path()).unwrap().0;
        assert!(!findings.iter().any(|f| f.rule_id == "github-pat"), "disabled rule should not fire");
    }

    // ── localhost exclusion ──────────────────────────────────────────────────

    #[test]
    fn localhost_http_url_not_flagged() {
        let scanner = default_scanner();
        let mut f = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(f, "url = http://localhost:8080/api").unwrap();
        let findings = scanner.scan_file(f.path()).unwrap().0;
        assert!(!findings.iter().any(|f| f.rule_id == "http-insecure-url"), "localhost http should not be flagged");
    }
}
