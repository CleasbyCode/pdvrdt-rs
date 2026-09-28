#!/usr/bin/env bash
# Reuse the C++ behavior fixtures against the Rust CLI.
set -euo pipefail

RUST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
CPP_TESTS="${PDVRDT_CPP_TESTS:-$RUST_ROOT/../src/tests}"
RS_BIN="${PDVRDT_RS_BIN:-$RUST_ROOT/target/release/pdvrdt-rs}"
if [[ "$RS_BIN" != /* ]]; then
  RS_BIN="$(pwd -P)/${RS_BIN#./}"
fi
if [[ ! -x "$RS_BIN" ]]; then
  echo "Build with cargo build --release --locked or set PDVRDT_RS_BIN." >&2
  exit 1
fi

bash "$CPP_TESTS/run_golden_tests.sh" --bin "$RS_BIN"
bash "$CPP_TESTS/run_roundtrip_tests.sh" --bin "$RS_BIN"
bash "$CPP_TESTS/run_image_regression_tests.sh" --bin "$RS_BIN"
python3 "$CPP_TESTS/run_recovery_path_tests.py" --bin "$RS_BIN"
python3 "$RUST_ROOT/src/tests/run_terminal_regressions.py" \
  --bin "$RS_BIN" --fixtures "$CPP_TESTS"
