# Build the four pinned FuzzBench targets from a terminal

These instructions build the library **and the upstream harness used by
FuzzBench**, download/package its default seeds, and run one input. Start with
the common setup, then run any target section independently. No Docker,
PANDA, PostgreSQL, or LAVA instrumentation is needed for these native builds.

Recipe reference: FuzzBench commit
`3234e151d70f6093272a9b4155e68ee57faf986c`. Commands target x86-64 Ubuntu
22.04/24.04, Bash, and Clang 14. Package versions can differ across systems;
the commands record installed versions rather than claiming a frozen OS image.

| Section | FuzzBench benchmark | Upstream revision | Version label at that revision | Output |
|---|---|---|---|---|
| [OpenSSL](#openssl-x509) | `openssl_x509` | `b0593c086dd303af31dc1e30233149978dd613c4` | `3.0.0-dev` | `out/x509` |
| [SQLite](#sqlite-ossfuzz) | `sqlite3_ossfuzz` | `c78cbf2e86850cc6882d3f0bd5415f6e731c3c675ffe77bb343682c619cb8cd9` | `3.33.0` development snapshot | `out/ossfuzz` |
| [libxml2](#libxml2-xml) | `libxml2_xml` | `c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e` | `2.11.0` development snapshot | `out/xml` |
| [libpng](#libpng-libpng_read_fuzzer) | `libpng_libpng_read_fuzzer` | `cd0ea2a7f53b603d3d9b5b891c779c430047b39a` | `1.6.40.git` | `out/libpng_read_fuzzer` |

## What comes from where?

There are three separate pieces:

1. **Pinned upstream source:** contains the actual library, harness and harness
   support files. Keep the whole tree, including generated configuration files.
2. **FuzzBench integration:** supplies source pins, configure/build choices and
   seed packaging rules. We save the exact recipes from the reference commit
   for inspection. SQLite also uses FuzzBench's `ossfuzz.dict`.
3. **Execution engine:** normally supplies `main`. For analysis we provide a
   small file-reading `main` that calls the unchanged harness.

| Target | Harness files from upstream | Extra FuzzBench files to compile the harness |
|---|---|---|
| OpenSSL | `fuzz/x509.c`, `fuzz/driver.c`, `fuzz/rand.inc`, `fuzz/fuzzer.h` | None; configure choices are from its `build.sh` |
| SQLite | `test/ossfuzz.c`, generated `bld/sqlite3.h`, generated library amalgamation | None; copy `ossfuzz.dict` for fuzzing |
| libxml2 | `fuzz/xml.c`, `fuzz/fuzz.c`, `fuzz/fuzz.h`; `fuzz/genSeed.c` packages seeds | None; **do not substitute** FuzzBench's adjacent `target.cc` |
| libpng | `contrib/oss-fuzz/libpng_read_fuzzer.cc`, generated configuration/prefix headers | None; use upstream build logic explained in its section |

“Same harness” here means the same pinned callback/support source and the
listed feature configuration. These native builds are not byte-identical to
FuzzBench's containers: host libraries, compiler, optimization, sanitizer and
engine versions can differ. The standalone driver runs only one callback
per process and replaces the fuzzing engine's `main`.

## Common setup: run once before any target section

### Install common tools and locate the recipe checkout

Run on the build machine, not inside the PANDA guest. Per-library packages are
listed again in their own sections. An HPC user without sudo can use a suitably
provisioned environment instead; these commands do not assume cluster modules.

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang-14 \
  git curl ca-certificates python3 zip unzip file

export FB="$HOME/fuzzbench"
export FB_COMMIT=3234e151d70f6093272a9b4155e68ee57faf986c
# If ~/fuzzbench does not exist, clone the checkout used by this repository:
if [ ! -d "$FB/.git" ]; then
  git clone https://github.com/AndrewQuijano/fuzzbench.git "$FB"
fi
git -C "$FB" cat-file -e "$FB_COMMIT^{commit}"
```

If the last command fails, fetch that commit from the same origin before
continuing: `git -C "$FB" fetch origin "$FB_COMMIT"`. We use `git show` at this
commit, so there is no need to change your current FuzzBench branch or discard
local edits. No FuzzBench Python packages are required.

### Choose a fresh build directory

Use a fresh `ROOT` for a clean rebuild. Target sections deliberately stop if
their source directory already exists rather than reusing changed objects.

```bash
set -euo pipefail
export ROOT="$HOME/lava/fuzzbench-manual/standalone"
export CC=clang-14 CXX=clang++-14 JOBS=8
export CFLAGS='-O0 -g -gdwarf-2 -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION'
export CXXFLAGS="$CFLAGS"
mkdir -p "$ROOT/common"
test "$(uname -m)" = x86_64
```

Eight build workers are a conservative default, independent of how many
exploration workers you later launch. These flags intentionally retain symbols,
disable optimization and omit ASan/UBSan. They suit initial analysis and LAVA
preparation; they do not reproduce a sanitizer-based FuzzBench evaluation build.

### Supply `main`, without rewriting any target harness

The standalone driver reads `argv[1]` unchanged, calls the optional harness
initializer once, then calls the fuzz callback once. An OpenSSL initializer
return value is not treated as an application failure.

```bash
cat > "$ROOT/common/driver.c" <<'EOF'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
extern int LLVMFuzzerInitialize(int *, char ***) __attribute__((weak));
extern int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int main(int argc, char **argv) {
    if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
    if (argc != 2) { fprintf(stderr, "usage: %s INPUT\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    if (fseek(f, 0, SEEK_END)) return 2;
    long length = ftell(f);
    if (length < 0 || fseek(f, 0, SEEK_SET)) return 2;
    size_t size = (size_t)length;
    uint8_t *data = malloc(size ? size : 1);
    if (!data) return 2;
    if (fread(data, 1, size, f) != size) return 2;
    fclose(f);
    LLVMFuzzerTestOneInput(data, size);
    free(data);
    return 0;
}
EOF

$CC $CFLAGS -c "$ROOT/common/driver.c" -o "$ROOT/common/driver.o"
ar rcs "$ROOT/common/libStandaloneEngine.a" "$ROOT/common/driver.o"
export ENGINE="$ROOT/common/libStandaloneEngine.a"
```

### Small shared helpers for recipes, seeds and smoke tests

Paste this block once in the same Bash session. Each target block runs in a
subshell, so its configure flags and working directory do not leak into the
next target. `begin_target` sets `WORK`, `SRC`, `OUT`, and `SEEDS` for that target.

`prepare_seeds` reads the original ZIP, discards files larger than 1 MiB and
deduplicates/renames content by SHA-1, matching the generic FuzzBench runner's
size/content policy. It also writes a SHA-256 manifest linking original ZIP
entry names to extracted inputs. It does not mutate the ZIP or seed contents.

```bash
begin_target() {
  export WORK="$ROOT/$1" SRC="$ROOT/$1/src"
  export OUT="$ROOT/$1/out" SEEDS="$ROOT/$1/seeds"
  if [ -e "$SRC" ]; then
    echo "Source already exists: $SRC; choose a fresh ROOT for a clean build." >&2
    return 1
  fi
  mkdir -p "$SRC" "$OUT" "$WORK/recipe"
  for name in Dockerfile benchmark.yaml; do
    git -C "$FB" show "$FB_COMMIT:benchmarks/$1/$name" > "$WORK/recipe/$name"
  done
  if git -C "$FB" cat-file -e "$FB_COMMIT:benchmarks/$1/build.sh" 2>/dev/null; then
    git -C "$FB" show "$FB_COMMIT:benchmarks/$1/build.sh" > "$WORK/recipe/build.sh"
  fi
  {
    printf 'fuzzbench=%s\nCC=%s\nCXX=%s\nCFLAGS=%s\nCXXFLAGS=%s\nENGINE=%s\n' \
      "$FB_COMMIT" "$CC" "$CXX" "$CFLAGS" "$CXXFLAGS" "$ENGINE"
    "$CC" --version
    uname -a
  } > "$WORK/build-info.txt"
}

prepare_seeds() {
  python3 - "$1" "$SEEDS" "$WORK/seed-manifest.tsv" <<'PY'
import hashlib, pathlib, sys, zipfile
archive, destination, manifest = map(pathlib.Path, sys.argv[1:])
destination.mkdir(exist_ok=False)
entries = retained = 0
with zipfile.ZipFile(archive) as z, manifest.open('w') as out:
    out.write('sha256\tbytes\tstatus\tseed_name\tarchive_entry\n')
    for info in sorted(z.infolist(), key=lambda i: i.filename):
        if info.is_dir():
            continue
        entries += 1
        if info.file_size > 1048576:
            out.write(f'-\t{info.file_size}\ttoo_large\t-\t{info.filename}\n')
            continue
        data = z.read(info)
        name = hashlib.sha1(data).hexdigest()
        digest = hashlib.sha256(data).hexdigest()
        path = destination / name
        if path.exists():
            assert path.read_bytes() == data, 'SHA-1 collision'
            status = 'duplicate'
        else:
            path.write_bytes(data)
            retained += 1
            status = 'retained'
        out.write(f'{digest}\t{len(data)}\t{status}\t{name}\t{info.filename}\n')
print(f'ZIP entries: {entries}; unique inputs <= 1 MiB: {retained}')
assert retained > 0, 'No usable seeds extracted'
PY
}

finish_target() {
  local binary="$OUT/$1" first
  first=$(python3 - "$SEEDS" <<'PY'
import pathlib, sys
print(next(iter(sorted(p for p in pathlib.Path(sys.argv[1]).iterdir() if p.is_file()))))
PY
  )
  "$binary" "$first"
  file "$binary"
  ldd "$binary" > "$WORK/linked-libraries.txt"
  sha256sum "$binary" "$OUT/"*.zip > "$WORK/SHA256SUMS"
  dpkg-query -W > "$WORK/installed-packages.txt"
  printf 'Smoke test passed. Binary: %s\nSeeds: %s\n' "$binary" "$SEEDS"
}
```

The seed counts below are reference measurements, not a reason to ignore errors.
Investigate unexpected differences using the entry manifest and
[the earlier seed inventories](../docs/fuzzbench-seeds/README.md). Source ZIP
entry paths and compression timestamps can differ while input contents match.

## OpenSSL: `x509`

**Source and version.** Git revision
`b0593c086dd303af31dc1e30233149978dd613c4`, `VERSION` label `3.0.0-dev`.
The Dockerfile initially clones tag `openssl-3.0.7`, but FuzzBench's later
`checkout_commit.py` checks out the benchmark YAML revision above. Build this
revision, not the current LAVA `openssl-3.0.7.tar.gz` target.

**Harness.** `fuzz/driver.c` exports `LLVMFuzzerInitialize` and
`LLVMFuzzerTestOneInput`, forwarding to `fuzz/x509.c`; that file includes
`fuzz/rand.inc` and uses libcrypto. Initialization, certificate decoding,
printing to a null BIO and DER re-encoding remain upstream code. No harness
source is copied from FuzzBench.

**Seeds.** The pinned Git tree directly contains `fuzz/corpora/x509/*`:
2,241 files, all unique and below 1 MiB. **Use Git**, because `.gitattributes`
excludes this corpus from GitHub source archives using `export-ignore`.
The newer separate `openssl/fuzz-corpora` repository is unnecessary here.

**Install, fetch, build, package, test:**

```bash
(
  sudo apt-get install -y perl
  begin_target openssl_x509
  git -C "$SRC" init
  git -C "$SRC" remote add origin https://github.com/openssl/openssl.git
  git -C "$SRC" fetch --depth=1 origin b0593c086dd303af31dc1e30233149978dd613c4
  git -C "$SRC" checkout --detach FETCH_HEAD
  test "$(git -C "$SRC" rev-parse HEAD)" = b0593c086dd303af31dc1e30233149978dd613c4
  git -C "$SRC" rev-parse HEAD > "$WORK/source-revision.txt"
  cd "$SRC"
  cat VERSION

  ./config --debug enable-fuzz-libfuzzer -DPEDANTIC \
    -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared enable-tls1_3 \
    enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-ssl3 \
    enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers \
    --with-fuzzer-lib="$ENGINE" $CFLAGS -fno-sanitize=alignment
  make -j"$JOBS" build_generated
  make -j"$JOBS" fuzz/x509 LDCMD="$CXX $CXXFLAGS"
  cp fuzz/x509 "$OUT/x509"
  cp fuzz/oids.txt "$OUT/x509.dict"
  zip -j "$OUT/x509_seed_corpus.zip" fuzz/corpora/x509/*
  prepare_seeds "$OUT/x509_seed_corpus.zip"
  finish_target x509
)
```

Expected binary: `$ROOT/openssl_x509/out/x509`; ready inputs:
`$ROOT/openssl_x509/seeds/`. Standalone usage is `x509 INPUT`, where INPUT
contains DER bytes, including malformed DER fuzz cases. It is not the
`openssl x509 -in INPUT` CLI and does not expect PEM text.

**For LAVA later.** Install this `x509` harness executable under the target's
prefix and set the command to `{install_dir}/bin/x509 {input_file}`. Preserve
the driver and upstream initializer; the driver owns `main`. Instrument the
libcrypto C units reached by the harness as well as relevant harness units.
OpenSSL's generated headers and providers/build rules must be retained.
Assembly is still enabled in this recipe; disabling it is an explicit
configuration change to apply consistently in mining and comparison builds.

## SQLite: `ossfuzz`

**Source and version.** Fossil revision
`c78cbf2e86850cc6882d3f0bd5415f6e731c3c675ffe77bb343682c619cb8cd9`;
`VERSION` reads `3.33.0`. FuzzBench downloads the short revision in its
Dockerfile; its YAML commit is empty, so there is no later Git checkout.

**Harness.** Upstream `test/ossfuzz.c` links to `bld/sqlite3.o`, compiled from
the generated amalgamation. It needs the generated `bld/sqlite3.h` too.
The only extra data copied from FuzzBench is `ossfuzz.dict`. Its `build.sh`
supplies the six limit/debug defines retained below.

**Seeds.** FuzzBench packages every upstream `*.test` file verbatim, including
Tcl scripts; it does not extract SQL statements from them. Reference counts:
1,265 ZIP files, 1,263 after the size policy. Some inputs consequently reject
early; preserve the documented baseline before trying alternative SQL corpora.

**Install, fetch, build, package, test:**

```bash
(
  sudo apt-get install -y autoconf automake libtool tcl tcl-dev zlib1g-dev
  begin_target sqlite3_ossfuzz
  curl -fL --retry 2 \
    'https://sqlite.org/src/tarball/sqlite.tar.gz?r=c78cbf2e86850cc6' \
    -o "$WORK/sqlite.tar.gz"
  sha256sum "$WORK/sqlite.tar.gz" > "$WORK/source-archive.sha256"
  tar xzf "$WORK/sqlite.tar.gz" --strip-components=1 -C "$SRC"
  test "$(cat "$SRC/manifest.uuid")" = c78cbf2e86850cc6882d3f0bd5415f6e731c3c675ffe77bb343682c619cb8cd9
  cp "$SRC/manifest.uuid" "$WORK/source-revision.txt"
  cat "$SRC/VERSION"
  git -C "$FB" show \
    "$FB_COMMIT:benchmarks/sqlite3_ossfuzz/ossfuzz.dict" > "$OUT/ossfuzz.dict"
  find "$SRC" -type f -name '*.test' -print0 | \
    sort -z | xargs -0 zip "$OUT/ossfuzz_seed_corpus.zip"

  cd "$SRC"
  mkdir bld
  cd bld
  export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=128000000 \
    -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 \
    -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 \
    -DSQLITE_MAX_PAGE_COUNT=16384"
  ../configure
  make -j"$JOBS"
  make sqlite3.c
  $CC $CFLAGS -I. -c ../test/ossfuzz.c -o ossfuzz.o
  $CXX $CXXFLAGS ossfuzz.o -o "$OUT/ossfuzz" "$ENGINE" \
    ./sqlite3.o -pthread -ldl -lz
  prepare_seeds "$OUT/ossfuzz_seed_corpus.zip"
  finish_target ossfuzz
)
```

Expected binary: `$ROOT/sqlite3_ossfuzz/out/ossfuzz`; ready inputs:
`$ROOT/sqlite3_ossfuzz/seeds/`. Standalone usage is `ossfuzz INPUT` with SQL
bytes. The harness optionally consumes a selector byte followed by newline,
then runs SQL against an in-memory database. A SQLite database file passed to
the SQLite shell's `.dump` command is a different workload.

**For LAVA later.** Install the harness as `bin/ossfuzz`; use
`{install_dir}/bin/ossfuzz {input_file}`. Generate `sqlite3.c`/`sqlite3.h` before
query instrumentation and keep that amalgamation fixed across instrumented
builds: regeneration can discard injected edits. Instrument the amalgamation
and `test/ossfuzz.c`, retaining these compile defines. Do not reuse the current
shell-based LAVA `main_file`/command as if it were the fuzz harness.

## libxml2: `xml`

**Source and version.** Git revision
`c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e`; `configure.ac` identifies a
`2.11.0` development snapshot. The GitHub URL below is the GNOME upstream
mirror; FuzzBench's Dockerfile clones GNOME's GitLab repository. Both identify
the same Git commit. This section uses the normal `libxml2_xml` benchmark,
not the separately pinned `libxml2_xml_e85b9b` bug benchmark.

**Harness.** The recipe compiles upstream `fuzz/xml.c` and `fuzz/fuzz.c`.
`fuzz/xml.c` initializes the parser and fuzz entity loader, then exercises
pull parsing, serialization, push parsing and the reader. The FuzzBench
directory's `target.cc` is unused: copying that file would build a different,
smaller workload. `fuzz/genSeed.c` plus `fuzz/Makefile.am` create the corpus.

**Seeds.** `make seed/xml.stamp` generates bundles from upstream tests. A bundle
contains a native `int` of parser options followed by escaped URL/content pairs,
possibly including DTDs and external entities. On x86-64 the integer is four
little-endian bytes. It is not a raw XML file. Reference counts: 308 ZIP entries,
307 retained after the size policy, with the documented host configuration.

**Install, fetch, build, package, test:**

```bash
(
  sudo apt-get install -y autoconf automake libtool pkg-config \
    zlib1g-dev liblzma-dev
  automake --version                  # must be >= 1.16.3
  begin_target libxml2_xml
  curl -fL --retry 2 \
    https://github.com/GNOME/libxml2/archive/c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e.tar.gz \
    -o "$WORK/libxml2.tar.gz"
  printf '%s  %s\n' \
    082fdf8d09c08e069de6d6bc3651a441229863fe8b4c2aeeb65067f85dc94c9c \
    "$WORK/libxml2.tar.gz" | sha256sum -c -
  tar xzf "$WORK/libxml2.tar.gz" --strip-components=1 -C "$SRC"
  printf '%s\n' c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e > "$WORK/source-revision.txt"
  cd "$SRC"
  ./autogen.sh --disable-shared --without-debug --without-ftp --without-http \
    --without-legacy --without-python
  make -j"$JOBS"
  cd fuzz
  make clean-corpus
  make fuzz.o xml.o
  $CXX $CXXFLAGS xml.o fuzz.o -o "$OUT/xml" "$ENGINE" \
    ../.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic
  make seed/xml.stamp
  zip -j "$OUT/xml_seed_corpus.zip" seed/xml/*
  cp xml.dict xml.options "$OUT/"
  prepare_seeds "$OUT/xml_seed_corpus.zip"
  finish_target xml
)
```

The checksum is the archive observed during the earlier audit. If an upstream
archive is regenerated and its bytes change, stop and verify its content/commit
before updating this expected checksum; do not simply delete the check.
Only native 64-bit dependency packages are required here; the Dockerfile's
additional i386 packages support other build architectures.

Expected binary: `$ROOT/libxml2_xml/out/xml`; ready inputs:
`$ROOT/libxml2_xml/seeds/`. Standalone usage is `xml ENCODED_INPUT`.
`--without-debug` disables the library's debug feature; the compiler's `-g`
still preserves debugging information for analysis.

**For LAVA later.** Install as `bin/xml`; use
`{install_dir}/bin/xml {input_file}` and the encoded corpus above. Preserve the
upstream initializer and `fuzz.c` entity/data helpers. Mine the same enabled
parser/library features rather than the current `xmllint` configuration.
Retain static zlib/lzma archives for this link; a missing archive cannot be
fixed by silently removing that dependency from the benchmark build.

## libpng: `libpng_read_fuzzer`

**Source and version.** Git revision
`cd0ea2a7f53b603d3d9b5b891c779c430047b39a`, version `1.6.40.git`.

**Harness.** Upstream `contrib/oss-fuzz/libpng_read_fuzzer.cc`, compiled against
generated libpng headers and `libpng16.a`. It reads from memory, applies
transforms, uses an allocation limit, relaxes checksum handling and reads rows
and end information. This is not `pngtest`.

**Integration detail.** FuzzBench has no benchmark-local `build.sh` here. Its
Dockerfile copies upstream `contrib/oss-fuzz/build.sh` before checking out the
library pin, so the copied script depends on clone-time HEAD. These commands
freeze the build logic from the **pinned source's** script, saved in `recipe/`.
Exact reproduction of a historical container's copied script requires that
image or archived script; the source pin alone does not establish its identity.

That pinned script links `-lz` and does not build the zlib clone, even though
the Dockerfile clones zlib v1.2.13 and a script comment mentions building it.
We explicitly use host `zlib1g-dev`, record the package list and shared-library
resolution, and do not claim it is zlib 1.2.13. The Dockerfile's separately
downloaded dictionary is also unpinned; below we retain the pinned upstream
`png.dict`/options. Dictionaries affect mutation, not which harness is linked.

**Seeds.** All source-tree `*.png` files whose paths do not contain `crashers`.
Reference counts: 169 ZIP entries, 156 unique retained inputs. FuzzBench also
copies benchmark-local `seeds/seed.png` into `/opt/seeds`, but the inspected
upstream script/generic runner does not add it to this default corpus ZIP.

**Install, fetch, build, package, test:**

```bash
(
  sudo apt-get install -y autoconf automake libtool zlib1g-dev
  begin_target libpng_libpng_read_fuzzer
  curl -fL --retry 2 \
    https://github.com/glennrp/libpng/archive/cd0ea2a7f53b603d3d9b5b891c779c430047b39a.tar.gz \
    -o "$WORK/libpng.tar.gz"
  printf '%s  %s\n' \
    aaf3b337bc96e0a788bea8f3ceb31351ae7228ee43c24421dc82d8b052f359de \
    "$WORK/libpng.tar.gz" | sha256sum -c -
  tar xzf "$WORK/libpng.tar.gz" --strip-components=1 -C "$SRC"
  printf '%s\n' cd0ea2a7f53b603d3d9b5b891c779c430047b39a > "$WORK/source-revision.txt"
  cd "$SRC"
  cp contrib/oss-fuzz/build.sh "$WORK/recipe/upstream-build.sh"
  sed -e 's/option STDIO/option STDIO disabled/' \
      -e 's/option WARNING /option WARNING disabled/' \
      -e 's/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/' \
      scripts/pnglibconf.dfa > scripts/pnglibconf.dfa.temp
  mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa
  autoreconf -fi
  ./configure --with-libpng-prefix=OSS_FUZZ_
  make -j"$JOBS" libpng16.la
  $CXX $CXXFLAGS -std=c++11 -I. contrib/oss-fuzz/libpng_read_fuzzer.cc \
    -o "$OUT/libpng_read_fuzzer" "$ENGINE" .libs/libpng16.a -lz
  find "$SRC" -type f -name '*.png' ! -path '*crashers*' -print0 | \
    sort -z | xargs -0 zip "$OUT/libpng_read_fuzzer_seed_corpus.zip"
  cp contrib/oss-fuzz/*.dict contrib/oss-fuzz/*.options "$OUT/"
  prepare_seeds "$OUT/libpng_read_fuzzer_seed_corpus.zip"
  finish_target libpng_read_fuzzer
)
```

Expected binary: `$ROOT/libpng_libpng_read_fuzzer/out/libpng_read_fuzzer`;
ready inputs: `$ROOT/libpng_libpng_read_fuzzer/seeds/`. Standalone usage is
`libpng_read_fuzzer INPUT.png`. Fresh sources are important: reapplying the
`sed` edits can duplicate the word `disabled`.

**For LAVA later.** Install as `bin/libpng_read_fuzzer`; use
`{install_dir}/bin/libpng_read_fuzzer {input_file}`. Keep the `OSS_FUZZ_`
prefix, generated headers and disabled STDIO/WARNING/WRITE features. The
library is C, but the harness is C++: retain `clang++` for the final link and
validate LAVA's C++ preprocessing/instrumentation path before assuming this
target is ready. Linking an injected C library still needs a working shared
LAVA storage definition and consistent harness/driver support.

## Running the resulting binaries

Select any file under the target's `seeds/` directory:

```text
$ROOT/openssl_x509/out/x509                         INPUT
$ROOT/sqlite3_ossfuzz/out/ossfuzz                    INPUT
$ROOT/libxml2_xml/out/xml                           INPUT
$ROOT/libpng_libpng_read_fuzzer/out/libpng_read_fuzzer INPUT
```

These are silent on many successful runs; exit zero means the callback
completed, including possible early parser rejection. `finish_target` also
checks binary format and saves linkage/package information. Its one-input
smoke test is not a deep-coverage check.

These executables accept one input filename. The dictionaries are retained
alongside them for future fuzzing integration; they are not needed for replay.

## Adapting these builds to LAVA

The commands above establish a working native starting point. New LAVA target
variants should package the same sources, the common standalone driver, a
small build/install wrapper and the selected seeds. Prefer new names such as
`fuzzbench_openssl_x509` so existing CLI targets and their mining databases
remain distinguishable. The wrapper must perform the native configure/generate,
compile, link and prefix-local install steps, with engine/flags supplied for
the appropriate LAVA phase instead of hard-coded host paths.

Before mining, verify these contracts:

* `command` invokes the file-input harness executable, and the driver is
  recorded as the owner of `main`; upstream harness initializers still run.
* Required generated source/headers exist before query instrumentation and
  survive later rebuilds. The link includes the library units actually mined.
* Host exploration and PANDA guest builds use compatible source/configuration
  and input framing. These native ELF files still depend on host runtime
  libraries; do not assume they are portable, fully static guest binaries.
* If assembly, dependencies, address width or features change for the guest,
  record and validate that change. Reuse of CLI-based mining does not establish
  harness compatibility.
* Validate generated triggers through the standalone driver and the final
  fuzz harness. Persistent fuzzing requires resetting per-input LAVA state;
  a fresh native process per input does not test that reset.

For coverage measurements, create another clean build and add
`-fprofile-instr-generate -fcoverage-mapping` to both compile and link flags.
Use the standalone driver to collect one profile per input. For Magmalyze,
configure the executable/input command to use these harnesses, not the existing
OpenSSL/SQLite/libxml2/libpng CLI configurations. These instructions do not
change those configurations or implement the LAVA wrappers.

See [the compatibility audit](../docs/fuzzbench-compatibility.md),
[the coverage-selection plan](../docs/lava-corpus-selection-plan.md), and
[the original audit/build notes](../docs/fuzzbench-compile.md).

## Validation record

On 2026-11-14, all four targets were fetched into fresh source directories,
compiled with the standalone driver, packaged, and passed the documented
one-seed smoke test. The ready-seed counts were:

| Target | ZIP entries | Ready unique inputs <= 1 MiB |
|---|---:|---:|
| OpenSSL | 2,241 | 2,241 |
| SQLite | 1,265 | 1,263 |
| libxml2 | 308 | 307 |
| libpng | 169 | 156 |

Verification outputs and logs are under
`/tmp/fuzzbench-manual-verify/standalone/`, with `ROOT` changed to that path.
Prerequisites were already installed except `zip`, whose Ubuntu package was
extracted into `/tmp` for verification; the guide explicitly installs it.
All Bash examples passed syntax checks. The earlier full-corpus standalone
replays are recorded in [the original audit](../docs/fuzzbench-compile.md).
These checks establish native compilation and replay, not LAVA/PANDA or angr
integration, and do not establish historical container binary identity.
