#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --jobs 2 -- -D warnings
cargo test --workspace --locked --jobs 2
cargo build --workspace --locked --jobs 2
