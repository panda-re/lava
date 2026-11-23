#!/usr/bin/env bash
# Add the local adapter to the raw source tree; keep instrumented copies intact.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/prepare.py" --setup-tree "$PWD" --install-dir "$1"
