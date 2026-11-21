#!/usr/bin/env bash
# Self-contained libxml2 preparation; provenance is in fuzzbench_prepare.py.
# LAVA discovers this script automatically. Manual use: --tar-dir DIR [--inputs-dir DIR].
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/fuzzbench_prepare.py" "$@"
