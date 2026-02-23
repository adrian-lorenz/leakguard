// Copyright (c) 2026 Adrian Lorenz <a.lorenz@noa-x.de>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;

use crate::rules::{severity_color, Severity};
use crate::scanner::Finding;

pub fn print_pretty(findings: &[Finding], show_warnings: bool) {
    let non_warn: Vec<_> = findings.iter().filter(|f| f.severity != "WARNING").collect();
    if findings.is_empty() || (!show_warnings && non_warn.is_empty()) {
        println!("{}", "✅ No secrets found!".green().bold());
        return;
    }
    let (crit,high,med,warn,low) = count_by_sev(findings);
    let warn_hint = if !show_warnings && warn > 0 {
        format!(" (use --warnings to show {} warning(s))", warn)
    } else { String::new() };
    println!("\n{} {} finding(s) — {} {} {} {} {}{}\n",
             "⚠️".yellow(), findings.len().to_string().yellow().bold(),
             format!("CRITICAL:{crit}").red().bold(), format!("HIGH:{high}").yellow(),
             format!("MEDIUM:{med}").cyan(), format!("WARN:{warn}").bright_yellow(), format!("LOW:{low}").white(),
             warn_hint.dimmed(),
    );
    let visible: Vec<_> = findings.iter()
        .filter(|f| show_warnings || f.severity != "WARNING")
        .collect();
    for f in visible {
        let sev = parse_sev(&f.severity);
        let is_warn = sev == Severity::Warning;
        println!("  {} {}", "─────────────────────────────────────────".dimmed(), severity_color(&sev));
        println!("  {} {}", "Rule:".bold(),        f.rule_id.cyan());
        println!("  {} {}", "Description:".bold(), f.description);
        println!("  {} {}:{}", "Location:".bold(), f.file.yellow(), f.line_number.to_string().yellow());
        if is_warn {
            println!("  {} {}", "Match:".bold(), f.secret.bright_yellow());
            println!("  {} {}", "Hint:".bold(),  "Add '# leakguard-ignore' to suppress".dimmed());
        } else {
            println!("  {} {}", "Secret:".bold(), f.secret.red());
        }
        println!("  {} {}", "Tags:".bold(), f.tags.join(", ").dimmed());
        println!("  {} {}", "Line:".bold(),  f.line.dimmed());
        println!();
    }
}

pub fn print_json(findings: &[&Finding]) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(findings)?);
    Ok(())
}

pub fn print_markdown(findings: &[&Finding]) {
    if findings.is_empty() {
        println!("✅ No secrets found.");
        return;
    }
    println!("| Severity | Rule | Description | Location | Secret | Tags |");
    println!("|----------|------|-------------|----------|--------|------|");
    for f in findings {
        let location = format!("{}:{}", f.file, f.line_number);
        let secret   = f.secret.replace('|', "\\|");
        let tags     = f.tags.join(", ");
        let desc     = f.description.replace('|', "\\|");
        println!("| {} | `{}` | {} | `{}` | `{}` | {} |",
            f.severity, f.rule_id, desc, location, secret, tags);
    }
}

pub fn print_sarif(findings: &[&Finding]) -> Result<()> {
    let sarif = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{ "tool": { "driver": { "name": "leakguard", "version": "0.2.0", "rules": [] } },
            "results": findings.iter().map(|f| serde_json::json!({
                "ruleId": f.rule_id,
                "level": match f.severity.as_str() { "CRITICAL"|"HIGH" => "error", "MEDIUM"|"WARNING" => "warning", _ => "note" },
                "message": { "text": format!("{}: {}", f.description, f.secret) },
                "locations": [{ "physicalLocation": { "artifactLocation": { "uri": f.file.clone() }, "region": { "startLine": f.line_number } } }]
            })).collect::<Vec<_>>()
        }]
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

pub fn write_github_summary(findings: &[Finding], source: &Path) -> Result<()> {
    let out_path = std::env::var("GITHUB_STEP_SUMMARY")
        .unwrap_or_else(|_| "/tmp/leakguard-summary.md".to_string());
    let content = build_github_summary(findings, source);
    std::fs::write(&out_path, &content)
        .with_context(|| format!("Cannot write GitHub summary to {out_path}"))?;
    if std::env::var("GITHUB_STEP_SUMMARY").is_err() {
        eprintln!("{} $GITHUB_STEP_SUMMARY not set — preview written to {}", "Note:".yellow(), out_path);
    }
    Ok(())
}

fn build_github_summary(findings: &[Finding], source: &Path) -> String {
    let mut md = String::new();
    if findings.is_empty() {
        md.push_str("## ✅ leakguard — No secrets found\n\n");
        md.push_str(&format!("> Scanned `{}`\n", source.display()));
        return md;
    }
    let (crit,high,med,warn,low) = count_by_sev(findings);

    md.push_str("## 🔍 leakguard Secret Scanner\n\n");
    md.push_str(&format!("> **{}** finding(s) detected in `{}`\n\n", findings.len(), source.display()));

    md.push_str("### Summary\n\n| Severity | Count |\n|----------|-------|\n");
    if crit > 0 { md.push_str(&format!("| 🔴 CRITICAL | **{crit}** |\n")); }
    if high > 0 { md.push_str(&format!("| 🟠 HIGH | **{high}** |\n")); }
    if med  > 0 { md.push_str(&format!("| 🟡 MEDIUM | **{med}** |\n")); }
    if warn > 0 { md.push_str(&format!("| ⚠️ WARNING | **{warn}** |\n")); }
    if low  > 0 { md.push_str(&format!("| 🔵 LOW | **{low}** |\n")); }
    md.push('\n');

    md.push_str("### All Findings\n\n");
    md.push_str("| # | Sev | Rule | File | Line | Preview |\n");
    md.push_str("|---|-----|------|------|------|---------|\n");
    for (i, f) in findings.iter().enumerate() {
        let preview = if f.line.len() > 72 { format!("{}…", &f.line[..72]) } else { f.line.clone() };
        let preview = preview.replace('|', "\\|").replace('`', "'");
        md.push_str(&format!("| {} | {} {} | `{}` | `{}` | {} | {} |\n",
                             i+1, severity_emoji(&f.severity), f.severity, f.rule_id, f.file, f.line_number, preview));
    }
    md.push('\n');

    for sev in &["CRITICAL","HIGH","MEDIUM","WARNING","LOW"] {
        let group: Vec<_> = findings.iter().filter(|f| f.severity == *sev).collect();
        if group.is_empty() { continue; }
        md.push_str(&format!("<details>\n<summary>{} {} — {} finding(s)</summary>\n\n",
                             severity_emoji(sev), sev, group.len()));
        for f in &group {
            md.push_str(&format!("#### `{}` — {}\n\n", f.rule_id, f.description));
            md.push_str(&format!("- **File:** `{}:{}`\n", f.file, f.line_number));
            md.push_str(&format!("- **Secret:** `{}`\n", f.secret));
            md.push_str(&format!("- **Tags:** {}\n", f.tags.join(", ")));
            md.push_str(&format!("- **Line:**\n```\n{}\n```\n\n", f.line));
        }
        md.push_str("</details>\n\n");
    }

    md.push_str("---\n> Generated by **leakguard** — add `# leakguard-ignore` to a line to suppress a finding.\n");
    md
}

fn count_by_sev(f: &[Finding]) -> (usize,usize,usize,usize,usize) {
    (f.iter().filter(|x| x.severity=="CRITICAL").count(),
     f.iter().filter(|x| x.severity=="HIGH").count(),
     f.iter().filter(|x| x.severity=="MEDIUM").count(),
     f.iter().filter(|x| x.severity=="WARNING").count(),
     f.iter().filter(|x| x.severity=="LOW").count())
}

fn parse_sev(s: &str) -> Severity {
    match s { "CRITICAL"=>"Critical", "HIGH"=>"High", "MEDIUM"=>"Medium", "WARNING"=>"Warning", _=>"Low" };
    match s { "CRITICAL" => Severity::Critical, "HIGH" => Severity::High, "MEDIUM" => Severity::Medium, "WARNING" => Severity::Warning, _ => Severity::Low }
}

fn severity_emoji(s: &str) -> &'static str {
    match s { "CRITICAL" => "🔴", "HIGH" => "🟠", "MEDIUM" => "🟡", "WARNING" => "⚠️", _ => "🔵" }
}

