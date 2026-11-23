#!/usr/bin/env bash
set -euo pipefail
# nginx has its own configure system: pass the selected phase flags explicitly.
python3 - "$1" <<'PY'
import os, shlex, subprocess, sys
link = shlex.join([flag for flag in shlex.split(os.environ.get('LDFLAGS','')) if flag != '-all-static'])
subprocess.run(['./configure', '--prefix='+sys.argv[1], '--with-cc='+os.environ['CC'],
                '--with-cc-opt='+os.environ.get('CFLAGS',''), '--with-ld-opt='+link,
                '--without-http_rewrite_module', '--without-http_gzip_module',
                '--without-http_auth_basic_module'], check=True)
PY
