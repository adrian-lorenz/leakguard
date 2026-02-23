#!/usr/bin/env bash
# Copyright (c) 2026 Adrian Lorenz <a.lorenz@noa-x.de>
# SPDX-License-Identifier: MIT
#
# Cross-compiles leakguard for all supported platforms.
# Requires: cargo, cross (https://github.com/cross-rs/cross), Docker
# macOS target requires a macOS host.

set -euo pipefail

BINARY="leakguard"
DIST="dist"
VERSION=$(cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; RESET="\033[0m"; BOLD="\033[1m"

info()  { echo -e "${BOLD}[leakguard]${RESET} $*"; }
ok()    { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()  { echo -e "${YELLOW}  ⚠${RESET} $*"; }
error() { echo -e "${RED}  ✗${RESET} $*"; }

# ── Prerequisites ─────────────────────────────────────────────────────────────
info "leakguard v${VERSION} — cross-compilation"
echo ""

if ! command -v cargo &>/dev/null; then
    error "cargo not found — install Rust via https://rustup.rs"
    exit 1
fi

if ! command -v cross &>/dev/null; then
    warn "cross not found — installing..."
    cargo install cross --git https://github.com/cross-rs/cross
fi

if ! command -v docker &>/dev/null; then
    error "Docker not found — required by cross for Linux/Windows targets"
    exit 1
fi

mkdir -p "$DIST"

# ── Targets ──────────────────────────────────────────────────────────────────
# Format: "rust-target  output-name  extension  tool"
TARGETS=(
    "x86_64-unknown-linux-musl     linux-amd64      ''    cross"
    "aarch64-unknown-linux-musl    linux-arm64      ''    cross"
    "x86_64-pc-windows-gnu         windows-amd64    .exe  cross"
    "aarch64-pc-windows-gnullvm    windows-arm64    .exe  cross"
    "aarch64-apple-darwin          macos-arm64      ''    cargo"
)

BUILT=()
SKIPPED=()
FAILED=()

# ── Build loop ────────────────────────────────────────────────────────────────
for entry in "${TARGETS[@]}"; do
    read -r target name ext tool <<< "$entry"
    ext="${ext//\''/}"   # strip the shell quoting for empty string

    echo ""
    info "Building ${name} (${target})..."

    # macOS targets can only be built on macOS
    if [[ "$target" == *"apple"* && "$(uname)" != "Darwin" ]]; then
        warn "Skipping ${name} — macOS target requires macOS host"
        SKIPPED+=("$name")
        continue
    fi

    # Add the Rust target if not present
    if ! rustup target list --installed | grep -q "^${target}$"; then
        rustup target add "$target"
    fi

    if "$tool" build --release --target "$target" 2>&1; then
        out="${DIST}/${BINARY}-${name}${ext}"
        cp "target/${target}/release/${BINARY}${ext}" "$out"
        size=$(du -sh "$out" | cut -f1)
        ok "${out}  (${size})"
        BUILT+=("$name")
    else
        error "Failed to build ${name}"
        FAILED+=("$name")
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}─────────────────────────────────────────${RESET}"
echo -e "${BOLD}Summary${RESET}"
echo ""

for name in "${BUILT[@]:-}";   do ok   "built:   ${name}"; done
for name in "${SKIPPED[@]:-}"; do warn "skipped: ${name}"; done
for name in "${FAILED[@]:-}";  do error "failed:  ${name}"; done

echo ""
if [[ ${#BUILT[@]} -gt 0 ]]; then
    info "Binaries in ${DIST}/:"
    ls -lh "${DIST}/"
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
    exit 1
fi
