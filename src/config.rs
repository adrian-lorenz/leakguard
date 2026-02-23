// Copyright (c) 2026 Adrian Lorenz <a.lorenz@noa-x.de>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub rules: RulesConfig,
}

#[derive(Debug, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_extensions")]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default)]
    pub exclude_files: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self { extensions: default_extensions(), exclude_paths: vec![], exclude_files: vec![] }
    }
}

fn default_extensions() -> Vec<String> { vec![] }

#[derive(Debug, Deserialize, Default)]
pub struct RulesConfig {
    #[serde(default)]
    pub disable: Vec<String>,
}

impl Config {
    fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read config: {}", path.display()))?;
        let cfg: Config = toml::from_str(&content)
            .with_context(|| format!("Invalid TOML: {}", path.display()))?;
        Ok(cfg)
    }

    pub fn load_auto(explicit: Option<&PathBuf>) -> Config {
        let path = explicit.cloned().unwrap_or_else(|| PathBuf::from("leakguard.toml"));
        if path.exists() {
            match Config::load(&path) {
                Ok(c) => { eprintln!("{} {}", "Config:".dimmed(), path.display().to_string().dimmed()); c }
                Err(e) => { eprintln!("{} {}", "Config error:".red(), e); Config::default() }
            }
        } else { Config::default() }
    }

    pub fn allowed_extensions(&self) -> HashSet<String> {
        self.scan.extensions.iter().map(|e| e.trim_start_matches('.').to_lowercase()).collect()
    }

    pub fn disabled_rules(&self) -> HashSet<String> {
        self.rules.disable.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_empty() {
        let cfg = Config::default();
        assert!(cfg.scan.extensions.is_empty());
        assert!(cfg.scan.exclude_paths.is_empty());
        assert!(cfg.scan.exclude_files.is_empty());
        assert!(cfg.rules.disable.is_empty());
    }

    #[test]
    fn parse_full_toml() {
        let toml = r#"
[scan]
extensions = ["rs", "py"]
exclude_paths = ["target/", "dist/"]
exclude_files = ["secret.txt"]

[rules]
disable = ["jwt-token", "http-insecure-url"]
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.scan.extensions,    vec!["rs", "py"]);
        assert_eq!(cfg.scan.exclude_paths, vec!["target/", "dist/"]);
        assert_eq!(cfg.scan.exclude_files, vec!["secret.txt"]);
        assert_eq!(cfg.rules.disable,      vec!["jwt-token", "http-insecure-url"]);
    }

    #[test]
    fn allowed_extensions_strips_dots_and_lowercases() {
        let toml = r#"[scan]
extensions = [".RS", "Py", ".js"]
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let exts = cfg.allowed_extensions();
        assert!(exts.contains("rs"),  "'.RS' should become 'rs'");
        assert!(exts.contains("py"),  "'Py' should become 'py'");
        assert!(exts.contains("js"),  "'.js' should become 'js'");
        assert!(!exts.contains(".rs"), "dot prefix must be stripped");
    }

    #[test]
    fn disabled_rules_returns_set() {
        let toml = r#"[rules]
disable = ["jwt-token", "http-insecure-url"]
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let disabled = cfg.disabled_rules();
        assert!(disabled.contains("jwt-token"));
        assert!(disabled.contains("http-insecure-url"));
        assert!(!disabled.contains("aws-access-key"));
    }

    #[test]
    fn invalid_toml_returns_error() {
        let bad = "this is [ not valid toml!!!";
        let result: Result<Config, _> = toml::from_str(bad);
        assert!(result.is_err());
    }
}

pub fn default_config_toml() -> &'static str {
    r#"# leakguard.toml
[scan]
# Empty = scan all files (except .env and .git). Restrict with e.g.:
# extensions = ["py", "js", "ts", "go", "yaml", "toml"]
extensions = []
exclude_paths = []
exclude_files = []

[rules]
# disable = ["jwt-token", "http-insecure-url"]
disable = []
"#
}
