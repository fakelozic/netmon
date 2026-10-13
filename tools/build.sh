#!/bin/sh
# Build the page before compiling Rust so its files are embedded in the binary.
# Run from any directory; Cargo uses four jobs and writes to this checkout's target.
set -eu

project_dir=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
cd "$project_dir"
(
    cd web
    nub install
    nub run build
)
cargo build --release --offline --jobs 4 --target-dir "$project_dir/target"

binary="$project_dir/target/release/netmon"
size=$(wc -c < "$binary")
printf 'Binary: %s\nSize: %s bytes\n' "$binary" "$size"
