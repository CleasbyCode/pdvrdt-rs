#!/usr/bin/env bash
# Compare the C++ and Rust --info text while allowing the Rust-specific build
# instructions and executable name to differ.
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

normalize() { # file, fold pdvrdt-rs to pdvrdt (0 or 1)
  python3 - "$1" "$2" <<'PY'
import sys

path, fold_program_name = sys.argv[1], sys.argv[2] == "1"
with open(path, encoding="utf-8") as stream:
    lines = stream.read().split("\n")

if fold_program_name:
    lines = [line.replace("pdvrdt-rs", "pdvrdt") for line in lines]
lines = [line.rstrip() for line in lines]

def section_index(name):
    try:
        return next(i for i, line in enumerate(lines) if line.strip() == name)
    except StopIteration:
        raise SystemExit(f"{path}: missing --info section: {name}")

build_titles = ("Build & install (Linux)", "Compile & run (Linux)")
try:
    build = next(section_index(title) for title in build_titles
                 if any(line.strip() == title for line in lines))
except StopIteration:
    raise SystemExit(f"{path}: missing Rust/C++ build section")

platform = section_index("Platform compatibility & size limits")
if build == 0 or platform == 0 or platform <= build:
    raise SystemExit(f"{path}: invalid --info section ordering")

# Drop the build and usage presentation. Keep the shared banner/description and
# everything from the platform section's divider onward.
sys.stdout.write("\n".join(lines[:build - 1] + lines[platform - 1:]))
PY
}

main() {
  need_cmd diff
  need_cmd python3

  # Build the default Rust target before checking whether its executable exists.
  # Explicit binary overrides intentionally skip that unrelated local build.
  resolve_rust_binary
  resolve_cpp_binary

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/pdvrdt-parity.XXXXXX")"

  if ! "$CPP" --info >"$WORK/cpp.txt"; then
    echo "C++ --info command failed: $CPP" >&2
    exit 1
  fi
  if ! "$RS" --info >"$WORK/rust.txt"; then
    echo "Rust --info command failed: $RS" >&2
    exit 1
  fi

  normalize "$WORK/cpp.txt" 0 >"$WORK/cpp-normalized.txt"
  normalize "$WORK/rust.txt" 1 >"$WORK/rust-normalized.txt"

  if diff -u "$WORK/cpp-normalized.txt" "$WORK/rust-normalized.txt"; then
    echo "PASS: shared --info content matches (build/usage presentation and program name intentionally differ)."
  else
    echo "DIFF: shared --info content mismatch." >&2
    exit 1
  fi
}

main "$@"
