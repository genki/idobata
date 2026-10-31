#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
cargo build --locked --release --target wasm32-unknown-unknown -p idobata-scanner
cp target/wasm32-unknown-unknown/release/idobata_scanner.wasm crates/scanner/artifacts/scanner.wasm
cargo build --locked --release -p idobata
