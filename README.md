# leakguard
![img.png](img.png)

> **leakguard** — fast secret scanner for your codebase


A lightweight, zero-config secret scanner written in Rust — available as CLI tool **and** Python library. Scans source code for accidentally committed secrets, credentials, and sensitive data.

---

## Features

- **89 built-in detection rules** covering cloud providers, LLMs, databases, HTTP auth, and more
- **Multiple output formats** — pretty-printed, JSON, and SARIF
- **GitHub Actions integration** — writes a formatted Job Summary to `$GITHUB_STEP_SUMMARY`
- **Inline suppression** — annotate lines with `# leakguard-ignore` to silence known false positives
- **Configurable** via `leakguard.toml` — restrict file extensions, exclude paths, disable rules
- **Sorted output** — findings ordered by severity (CRITICAL → HIGH → MEDIUM → LOW → WARNING), then by file and line
- **Smart false-positive filtering** — skips template variables, shell variables, and attribute references
- **Binary-safe** — skips non-text files automatically
- **Respects `.env` files** — always excluded from scanning

---

## Installation

### From source

```bash
git clone https://github.com/adrian-lorenz/leakguard.git
cd leakguard
cargo install --path .
```

### via pip

```bash
pip install leakguard-secret-leaks
leakguard check .
```

### Pre-built binaries

Download the latest binary for your platform from the [Releases](https://github.com/adrian-lorenz/leakguard/releases/latest) page:

| Platform | File |
|----------|------|
| Linux x86_64 | `leakguard-linux-amd64` |
| Linux ARM64 | `leakguard-linux-arm64` |
| Windows x86_64 | `leakguard-windows-amd64.exe` |
| macOS Apple Silicon | `leakguard-macos-arm64` |

```bash
# Linux / macOS — make executable and move to PATH
chmod +x leakguard-linux-amd64
sudo mv leakguard-linux-amd64 /usr/local/bin/leakguard
```

---

## Python Library

After installing via `pip install leakguard-secret-leaks`, you can use leakguard directly from Python — e.g. to scan text before sending it to an LLM:

```python
from leakguard import scan_text

findings = scan_text("My API key is sk-proj-abc123xyz...")
for f in findings:
    print(f.rule_id, f.severity, f.secret)

# Disable specific rules:
findings = scan_text(text, disable_rules=["http-insecure-url"])
```

Each finding has the attributes: `rule_id`, `description`, `severity`, `line_number`, `line`, `secret`, `tags`.

---

## CLI Usage

```bash
# Scan the current directory
leakguard check

# Scan a specific path
leakguard check --source ./src

# JSON output (e.g. for piping)
leakguard check --format json

# SARIF output (e.g. for GitHub Code Scanning)
leakguard check --format sarif

# Verbose mode (shows every file scanned/skipped)
leakguard check --verbose

# Include WARNING-level findings in detail output
leakguard check --warnings

# Limit file size (default: 1024 KB)
leakguard check --max-size 512

# Use a custom config file
leakguard check --config /path/to/leakguard.toml

# Write a GitHub Actions Job Summary
leakguard check --github-summary

# List all built-in rules
leakguard rules

# Generate a default config file
leakguard init-config
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No findings (or only LOW/WARNING severity) |
| `1`  | At least one CRITICAL, HIGH, or MEDIUM finding |

---

## Warnings

WARNING-level findings (e.g. plain HTTP URLs) are counted in the summary but suppressed in the detail output by default to reduce noise. Use `--warnings` to display them:

```bash
leakguard check --warnings
```

The summary line always shows the WARNING count regardless of this flag.

---

## Configuration

Run `leakguard init-config` to create a `leakguard.toml` in the current directory:

```toml
[scan]
# Leave empty to scan all files (except .env and .git).
# Restrict to specific extensions:
# extensions = ["py", "js", "ts", "go", "yaml", "toml"]
extensions = []
exclude_paths = []
exclude_files = []

[rules]
# Disable specific rules by ID:
# disable = ["jwt-token", "http-insecure-url"]
disable = []
```

`leakguard.toml` is auto-loaded from the current directory if present.

---

## Suppression

Add a suppression comment to any line to skip it:

```python
api_url = "http://internal-service/api"  # leakguard-ignore
```

Supported markers: `# leakguard-ignore`, `# noqa-secrets`, `# nosec-secrets`

leakguard also automatically skips common false positives:

| Pattern | Example |
|---------|---------|
| Python f-strings / Jinja | `postgresql://{DB_USER}:{DB_PASSWORD}@...` |
| Shell variables | `$DB_PASSWORD` |
| Python `%`-format | `%(password)s` |
| Attribute references | `settings.DB_PASSWORD`, `config.secret_key` |
| localhost HTTP URLs | `http://localhost:8080` |

---

## Detection Coverage

| Category | Examples |
|----------|---------|
| **Cloud / VCS** | AWS keys, GitHub/GitLab PATs, Google API keys, Stripe, Slack, NPM, Docker Hub |
| **LLM / AI** | OpenAI, Anthropic, Cohere, Mistral, Hugging Face, Replicate, Groq, Perplexity |
| **Azure / M365** | Tenant/Client IDs, Storage keys, Service Bus, Cosmos DB, Teams webhooks, Graph API |
| **Frontend / SaaS** | Firebase, Mapbox, Sentry DSN, Contentful, Shopify, Algolia, Linear, Postman, PlanetScale, Cloudflare |
| **Databases** | PostgreSQL, MySQL, MongoDB, Redis, MSSQL, Elasticsearch, RabbitMQ, JDBC |
| **Observability** | Datadog, New Relic, Grafana, Honeycomb, Lightstep, OTLP endpoints |
| **HTTP Auth** | Basic Auth headers, Bearer tokens, credentials in URLs, curl commands |
| **Crypto** | PEM private keys (RSA, EC, DSA, OpenSSH) |
| **Generic** | High-entropy secrets matching common naming patterns, JWT tokens |

Run `leakguard rules` to see all 89 rules with IDs, severity levels, and tags.

---

## Severity Levels

| Level | Description |
|-------|-------------|
| `CRITICAL` | Direct credential exposure — rotate immediately |
| `HIGH` | Sensitive token or key with significant access |
| `MEDIUM` | Potentially sensitive, context-dependent |
| `LOW` | Low-risk exposure (e.g. publishable keys) |
| `WARNING` | Best-practice violation (e.g. plain HTTP URLs) — shown with `--warnings` |

---

## GitHub Actions

### Use leakguard in your own pipeline

Add this job to any workflow to scan for secrets and write the results to the GitHub Job Summary:

```yaml
jobs:
  leakguard:
    name: leakguard secret scan
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Install leakguard
        run: |
          curl -sSfL \
            https://github.com/adrian-lorenz/leakguard/releases/latest/download/leakguard-linux-amd64 \
            -o /usr/local/bin/leakguard
          chmod +x /usr/local/bin/leakguard

      - name: Run scan
        run: leakguard check --format markdown >> "$GITHUB_STEP_SUMMARY"
```

Or install via pip:

```yaml
      - name: Install leakguard
        run: pip install leakguard-secret-leaks

      - name: Run scan
        run: leakguard check --format markdown >> "$GITHUB_STEP_SUMMARY"
```

---

Two ready-to-use workflows are also included in `.github/workflows/`.

### Secret scan on every push — `scan.yml`

Runs `leakguard check` on every push and pull request, uploads results to GitHub Code Scanning as SARIF.

> Replace `YOUR_USERNAME` in `scan.yml` with your GitHub username before pushing.


---

## License

MIT — Copyright (c) 2026 Adrian Lorenz &lt;a.lorenz@noa-x.de&gt;
