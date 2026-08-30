#!/usr/bin/env bash
set -euo pipefail

RUST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CALLER_PWD="$(pwd -P)"
WORK_DIR=""

cleanup() {
  local status=$?
  [[ -z "$WORK_DIR" ]] || rm -rf -- "$WORK_DIR"
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

absolute_from_caller() {
  local path="$1"
  if [[ "$path" == /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$CALLER_PWD" "${path#./}"
  fi
}

rust_binary_from_cargo() {
  local target_dir
  target_dir="$({
    cd "$RUST_ROOT"
    cargo metadata --format-version 1 --no-deps
  } | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
  printf '%s/release/pdvrdt-rs\n' "$target_dir"
}

resolve_rust_binary() {
  if [[ -n "${PDVRDT_RS_BIN:-}" ]]; then
    RS_BIN="$(absolute_from_caller "$PDVRDT_RS_BIN")"
  else
    need_cmd cargo
    echo "[1/3] Building pdvrdt-rust"
    (
      cd "$RUST_ROOT"
      cargo build --release --locked
    )
    RS_BIN="$(rust_binary_from_cargo)"
  fi

  if [[ ! -x "$RS_BIN" ]]; then
    echo "Rust binary not found or not executable: $RS_BIN" >&2
    echo "Set PDVRDT_RS_BIN=/path/to/pdvrdt-rs to use an existing binary." >&2
    exit 1
  fi
}

make_cover_png() {
  python3 - "$WORK_DIR/cover.png" <<'PY'
import binascii
import struct
import sys
import zlib
from pathlib import Path

def chunk(kind, body):
    crc = binascii.crc32(kind + body) & 0xFFFFFFFF
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", crc)

width = height = 96
rows = []
for y in range(height):
    row = bytearray([0])
    for x in range(width):
        row.extend(((x * 3 + y) & 0xFF, (y * 5 + x) & 0xFF,
                    (x + y * 2) & 0xFF, 255))
    rows.append(row)

signature = b"\x89PNG\r\n\x1a\n"
ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
Path(sys.argv[1]).write_bytes(
    signature + chunk(b"IHDR", ihdr) +
    chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) +
    chunk(b"IEND", b""))
PY
}

run_mode() {
  local mode_name="$1"
  local mode_arg="$2"
  local secret="secret_${mode_name}.txt"
  local reference="${secret}.reference"
  local conceal_output recover_output pin output_image recovered_file

  printf 'pdvrdt rust smoke payload for mode=%s\nline2\n' "$mode_name" >"$secret"
  cp -- "$secret" "$reference"

  if [[ -n "$mode_arg" ]]; then
    if ! conceal_output=$("$RS_BIN" conceal "$mode_arg" cover.png "$secret" 2>&1); then
      echo "FAIL: conceal command failed for $mode_name" >&2
      printf '%s\n' "$conceal_output" >&2
      return 1
    fi
  elif ! conceal_output=$("$RS_BIN" conceal cover.png "$secret" 2>&1); then
    echo "FAIL: conceal command failed for $mode_name" >&2
    printf '%s\n' "$conceal_output" >&2
    return 1
  fi

  pin=$(printf '%s\n' "$conceal_output" | sed -n 's/.*Recovery PIN: \[\*\*\*\([0-9][0-9]*\)\*\*\*\].*/\1/p' | tail -n 1)
  output_image=$(printf '%s\n' "$conceal_output" | sed -n 's/^Saved "file-embedded" PNG image: \([^ ]*\) (.*/\1/p' | tail -n 1)

  if [[ -z "$pin" || -z "$output_image" || ! -f "$output_image" ]]; then
    echo "FAIL: unable to parse conceal output for $mode_name" >&2
    printf '%s\n' "$conceal_output" >&2
    return 1
  fi

  rm -f -- "$secret"
  if ! recover_output=$(printf '%s\n' "$pin" | "$RS_BIN" recover "$output_image" 2>&1); then
    echo "FAIL: recover command failed for $mode_name" >&2
    printf '%s\n' "$recover_output" >&2
    return 1
  fi

  recovered_file=$(printf '%s\n' "$recover_output" | sed -n 's/^Extracted hidden file: \([^ ]*\) (.*/\1/p' | tail -n 1)
  if [[ -z "$recovered_file" || ! -f "$recovered_file" ]]; then
    echo "FAIL: unable to parse recover output for $mode_name" >&2
    printf '%s\n' "$recover_output" >&2
    return 1
  fi

  if ! cmp -s -- "$reference" "$recovered_file"; then
    echo "FAIL: payload mismatch for $mode_name" >&2
    wc -c -- "$reference" "$recovered_file" >&2
    return 1
  fi

  echo "PASS $mode_name : $output_image -> $recovered_file"
}

main() {
  need_cmd cmp
  need_cmd python3
  need_cmd sed

  resolve_rust_binary
  if [[ -n "${PDVRDT_RS_BIN:-}" ]]; then
    echo "[1/3] Using Rust binary override: $RS_BIN"
  fi

  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pdvrdt-rust-smoke.XXXXXX")"

  echo "[2/3] Generating deterministic PNG cover fixture"
  make_cover_png

  echo "[3/3] Running smoke round-trips"
  (
    cd "$WORK_DIR"
    run_mode default ""
    run_mode mastodon "-m"
    run_mode reddit "-r"
  )

  echo "ALL_RUST_SMOKE_TESTS_PASSED"
}

main "$@"
