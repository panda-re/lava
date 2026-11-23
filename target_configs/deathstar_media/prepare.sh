#!/usr/bin/env bash
# Source/dependency/input provenance and cache behavior are in prepare.py.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/prepare.py" "$@"
