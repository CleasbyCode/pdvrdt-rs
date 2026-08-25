#!/usr/bin/env bash
# Cross-interop gate: conceal with binary A and recover with binary B, both ways,
# across default/Mastodon/Reddit text and binary payloads, plus a pre-compressed
# default payload. Output PNG bytes are intentionally not compared because the
# encryption and codec pipelines are randomized; recovered payload bytes are.
set -euo pipefail

RUST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CALLER_PWD="$(pwd -P)"
WORK=""

cleanup() {
  local status=$?
  [[ -z "$WORK" ]] || rm -rf -- "$WORK"
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
    RS="$(absolute_from_caller "$PDVRDT_RS_BIN")"
  else
    need_cmd cargo
    echo "Building Rust release binary..."
    (
      cd "$RUST_ROOT"
      cargo build --release --locked
    )
    RS="$(rust_binary_from_cargo)"
  fi

  if [[ ! -x "$RS" ]]; then
    echo "Rust binary not found or not executable: $RS" >&2
    echo "Set PDVRDT_RS_BIN=/path/to/pdvrdt-rs to use an existing binary." >&2
    exit 1
  fi
}

resolve_cpp_binary() {
  if [[ -n "${PDVRDT_CPP_BIN:-}" ]]; then
    CPP="$(absolute_from_caller "$PDVRDT_CPP_BIN")"
  elif [[ -x "$RUST_ROOT/../src/pdvrdt" ]]; then
    CPP="$(cd "$RUST_ROOT/../src" && pwd -P)/pdvrdt"
  elif command -v pdvrdt >/dev/null 2>&1; then
    CPP="$(command -v pdvrdt)"
  else
    CPP="$RUST_ROOT/../src/pdvrdt"
  fi

  if [[ ! -x "$CPP" ]]; then
    echo "C++ binary not found or not executable: $CPP" >&2
    echo "Build the C++ source or set PDVRDT_CPP_BIN=/path/to/pdvrdt." >&2
    exit 1
  fi
}

make_fixtures() {
  python3 - "$WORK/cover.png" "$WORK/p_text.txt" "$WORK/p_bin.bin" "$WORK/p_stored.gz" <<'PY'
import binascii
import gzip
import struct
import sys
import zlib
from pathlib import Path

cover_path, text_path, binary_path, stored_path = map(Path, sys.argv[1:])

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
cover_path.write_bytes(
    signature + chunk(b"IHDR", ihdr) +
    chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) +
    chunk(b"IEND", b""))

text_path.write_bytes(b"pdvrdt interop payload\n")
binary = bytes(range(256)) * 16
binary_path.write_bytes(binary)
stored_path.write_bytes(gzip.compress(binary * 2, compresslevel=9, mtime=0))
PY
}

extract_pin() {
  sed -n 's/.*Recovery PIN: \[\*\*\*\([0-9][0-9]*\)\*\*\*\].*/\1/p' "$1" | tail -n 1
}

extract_image() {
  sed -n 's/.*Saved "file-embedded" PNG image: \([^ ]*\) (.*/\1/p' "$1" | tail -n 1
}

extract_recovered_file() {
  sed -n 's/.*Extracted hidden file: \([^ ]*\) (.*/\1/p' "$1" | tail -n 1
}

show_log() {
  local label="$1" log="$2"
  echo "--- $label ($log) ---" >&2
  sed -n '1,80p' "$log" >&2
}

PASSES=0
FAILS=0

run_case() { # encoder option cover payload decoder tag
  local encoder="$1" option="$2" cover="$3" payload="$4" decoder="$5" tag="$6"
  local case_dir="$WORK/$tag"
  local payload_name
  payload_name="$(basename -- "$payload")"

  mkdir -p -- "$case_dir"
  cp -- "$cover" "$case_dir/cover.png"
  cp -- "$payload" "$case_dir/$payload_name"

  if [[ -n "$option" ]]; then
    if ! (cd "$case_dir" && "$encoder" conceal "$option" cover.png "$payload_name" >conceal.log 2>&1); then
      echo "FAIL[$tag]: conceal command failed" >&2
      show_log "conceal output" "$case_dir/conceal.log"
      FAILS=$((FAILS + 1))
      return 0
    fi
  elif ! (cd "$case_dir" && "$encoder" conceal cover.png "$payload_name" >conceal.log 2>&1); then
    echo "FAIL[$tag]: conceal command failed" >&2
    show_log "conceal output" "$case_dir/conceal.log"
    FAILS=$((FAILS + 1))
    return 0
  fi

  local pin image_name image_path
  pin="$(extract_pin "$case_dir/conceal.log")"
  image_name="$(extract_image "$case_dir/conceal.log")"
  image_path="$case_dir/$image_name"
  if [[ -z "$pin" || -z "$image_name" || ! -f "$image_path" ]]; then
    echo "FAIL[$tag]: unable to parse PIN/output image or image is missing" >&2
    show_log "conceal output" "$case_dir/conceal.log"
    FAILS=$((FAILS + 1))
    return 0
  fi

  local recover_dir="$case_dir/recover"
  mkdir -p -- "$recover_dir"
  cp -- "$image_path" "$recover_dir/input.png"
  cp -- "$payload" "$recover_dir/original"

  if ! (cd "$recover_dir" && printf '%s\n' "$pin" | "$decoder" recover input.png >recover.log 2>&1); then
    echo "FAIL[$tag]: recover command failed" >&2
    show_log "recover output" "$recover_dir/recover.log"
    FAILS=$((FAILS + 1))
    return 0
  fi

  local recovered_name recovered_path
  recovered_name="$(extract_recovered_file "$recover_dir/recover.log")"
  recovered_path="$recover_dir/$recovered_name"
  if [[ -z "$recovered_name" || ! -f "$recovered_path" ]]; then
    echo "FAIL[$tag]: unable to parse recovered filename or file is missing" >&2
    show_log "recover output" "$recover_dir/recover.log"
    FAILS=$((FAILS + 1))
    return 0
  fi

  if ! cmp -s -- "$recovered_path" "$recover_dir/original"; then
    echo "FAIL[$tag]: recovered payload bytes differ" >&2
    wc -c -- "$recovered_path" "$recover_dir/original" >&2
    FAILS=$((FAILS + 1))
    return 0
  fi

  echo "PASS[$tag]"
  PASSES=$((PASSES + 1))
}

main() {
  need_cmd cmp
  need_cmd python3
  need_cmd sed

  resolve_rust_binary
  resolve_cpp_binary

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/pdvrdt-interop.XXXXXX")"

  make_fixtures

  local cover
  if [[ -n "${COVER:-}" ]]; then
    cover="$(absolute_from_caller "$COVER")"
    if [[ ! -f "$cover" ]]; then
      echo "Cover PNG not found: $cover" >&2
      exit 2
    fi
  else
    cover="$WORK/cover.png"
  fi

  run_case "$CPP" ""   "$cover" "$WORK/p_text.txt"  "$RS"  default_text_cpp_to_rs
  run_case "$RS"  ""   "$cover" "$WORK/p_text.txt"  "$CPP" default_text_rs_to_cpp
  run_case "$CPP" ""   "$cover" "$WORK/p_bin.bin"   "$RS"  default_binary_cpp_to_rs
  run_case "$RS"  ""   "$cover" "$WORK/p_bin.bin"   "$CPP" default_binary_rs_to_cpp
  run_case "$CPP" ""   "$cover" "$WORK/p_stored.gz" "$RS"  default_stored_cpp_to_rs
  run_case "$RS"  ""   "$cover" "$WORK/p_stored.gz" "$CPP" default_stored_rs_to_cpp

  run_case "$CPP" "-m" "$cover" "$WORK/p_text.txt"  "$RS"  mastodon_text_cpp_to_rs
  run_case "$RS"  "-m" "$cover" "$WORK/p_text.txt"  "$CPP" mastodon_text_rs_to_cpp
  run_case "$CPP" "-m" "$cover" "$WORK/p_bin.bin"   "$RS"  mastodon_binary_cpp_to_rs
  run_case "$RS"  "-m" "$cover" "$WORK/p_bin.bin"   "$CPP" mastodon_binary_rs_to_cpp

  run_case "$CPP" "-r" "$cover" "$WORK/p_text.txt"  "$RS"  reddit_text_cpp_to_rs
  run_case "$RS"  "-r" "$cover" "$WORK/p_text.txt"  "$CPP" reddit_text_rs_to_cpp
  run_case "$CPP" "-r" "$cover" "$WORK/p_bin.bin"   "$RS"  reddit_binary_cpp_to_rs
  run_case "$RS"  "-r" "$cover" "$WORK/p_bin.bin"   "$CPP" reddit_binary_rs_to_cpp

  echo "----"
  echo "passed=$PASSES failed=$FAILS"
  if [[ "$PASSES" -eq 14 && "$FAILS" -eq 0 ]]; then
    echo "ALL INTEROP CASES PASSED (14/14)"
  else
    echo "INTEROP FAILURE: expected 14 passes" >&2
    exit 1
  fi
}

main "$@"
