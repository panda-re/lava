#!/usr/bin/env bash
# Feature choices: pinned libpng contrib/oss-fuzz/build.sh at cd0ea2a7f53b603d3d9b5b891c779c430047b39a.
# Called from the extracted source; inherit the phase's compiler/linker flags.
set -euo pipefail
prefix=$1
if ! grep -q 'option STDIO disabled' scripts/pnglibconf.dfa; then
  sed -e 's/option STDIO/option STDIO disabled/' \
      -e 's/option WARNING /option WARNING disabled/' \
      -e 's/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/' \
      scripts/pnglibconf.dfa > scripts/pnglibconf.dfa.temp
  mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa
fi
autoreconf -fi
./configure --prefix="$prefix" --with-libpng-prefix=OSS_FUZZ_
