#!/bin/bash
# ProgramBench-style build: must produce ./executable at the repo root.
set -e
cd "$(dirname "$0")"
cargo build --release
cp "target/release/zip-password-finder" executable
