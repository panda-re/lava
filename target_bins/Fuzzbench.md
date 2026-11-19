# FuzzBench sources, standalone builds, and inputs

Follow the pinned [FuzzBench checkout](https://github.com/google/fuzzbench/tree/3234e151d70f6093272a9b4155e68ee57faf986c)
when choosing the source revision, harness, feature flags and seed rule. Each
benchmark's `benchmark.yaml`, `Dockerfile` and `build.sh` explain those choices.
The commands below translate those recipes into ordinary native builds.
Each target has two subsections: `target_bins` for source/build provenance, and
`target_configs` for seed provenance/preparation. Seed commands use a separate
staging directory when you want to inspect a corpus separately. The existing
`openssl`, `sqlite`, `libxml2`, and `libpng` JSONs now select these harnesses.

| Target / version | Raw upstream download → filename in `target_bins/` | FuzzBench recipe | Installed executable under `lava-install/` |
|---|---|---|---|
| OpenSSL `3.0.0-dev` | [b0593c0 source](https://github.com/openssl/openssl/archive/b0593c086dd303af31dc1e30233149978dd613c4.tar.gz) → `openssl-fuzzbench-b0593c0.tar.gz` | [openssl_x509](https://github.com/google/fuzzbench/tree/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/openssl_x509) | `bin/x509-test` |
| SQLite `3.33.0` snapshot | [c78cbf2 source](https://sqlite.org/src/tarball/sqlite.tar.gz?r=c78cbf2e86850cc6) → `sqlite-fuzzbench-c78cbf2e86850cc6.tar.gz` | [sqlite3_ossfuzz](https://github.com/google/fuzzbench/tree/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/sqlite3_ossfuzz) | `bin/ossfuzz` |
| libxml2 `2.11.0` snapshot | [c7260a4 source](https://github.com/GNOME/libxml2/archive/c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e.tar.gz) → `libxml2-fuzzbench-c7260a4.tar.gz` | [libxml2_xml](https://github.com/google/fuzzbench/tree/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/libxml2_xml) | `bin/xml` |
| libpng `1.6.40.git` | [cd0ea2a source](https://github.com/glennrp/libpng/archive/cd0ea2a7f53b603d3d9b5b891c779c430047b39a.tar.gz) → `libpng-fuzzbench-cd0ea2a.tar.gz` | [libpng_libpng_read_fuzzer](https://github.com/google/fuzzbench/tree/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/libpng_libpng_read_fuzzer) | `bin/libpng_read_fuzzer` |

## What belongs in the tarball?

**Only the downloaded upstream source.** Keep its original top-level directory;
`LavaPaths` infers that root from the tar listing. Do not bundle compiled objects,
installed libraries, a second project, or our adapter into the tarball. Extra
support files and input-fetching scripts live in `target_configs/`.

The SQLite archive already present in `target_bins/` was previously checked
against the official download. The other filenames distinguish the pinned
snapshots from the newer CLI sources previously used by these configurations.
All four existing project JSONs now use the pinned harnesses below. Their old
CLI seed fixtures are preserved in each `inputs-cli-backup/` directory.

## Build through Magmalyze or collect coverage

Use the existing JSONs and the `generation_dir` from `host.json`:

```bash
cd "$HOME/lava"
source venv/bin/activate
magmalyze -p openssl --build-only
magmalyze -p sqlite --build-only
magmalyze -p libxml2 --build-only
magmalyze -p libpng --build-only
# Build with LLVM coverage instrumentation and run the prepared seed corpus:
lava-coverage -p openssl
```

Substitute any of the four names for `lava-coverage`. `--build-only` prepares,
builds, installs and copies seeds, then stops before symbolic exploration.
Installed executables are under
`<generation_dir>/<project>/<upstream-root>/lava-install/bin/`, with the copied
corpus in the adjacent `inputs/`. A regular `magmalyze -p <project>` rebuilds
and starts exploration; `--no-build` reuses an existing build. Use `--output-dir`
for generated inputs so the original corpus remains separate.

`lava-coverage` performs a fresh coverage build in that same project's generation
folder. Re-run `magmalyze --build-only` when you want an ordinary analysis build
there again. The JSONs retain the library configuration and flags in both modes.
This is native generation/coverage support; LAVA query/static/injection behavior
for these new workloads remains unvalidated.

**Why any extra driver?** A fuzz callback is not a C `main`. The fuzzer normally
provides `main`, initialization and input delivery. For file-based LAVA/angr
runs, something must read the file and call that callback. OpenSSL already has
that runner (`fuzz/test-corpus.c`), so this guide uses its `x509-test` target.
SQLite, libxml2 and libpng each have a project-local `fuzzbench_driver.c`
in `target_configs/<target>/`. OpenSSL also carries a copy for a self-contained
configuration bundle, but uses its upstream runner instead.
It supplies only file reading and optional initialization; the target harness
stays upstream code. Previously this was generated inline; that boilerplate is
now a normal, reviewable support file.

These are the same pinned harness workloads, with a file-based runner. They
are not historical container binaries: host compiler, optimization, sanitizers
and dependencies can differ. The seed fetchers implement the inspected default
packaging rules, not any particular experiment's evolved/custom corpus.

## Common setup

Run these commands once in Bash on x86-64 Ubuntu, then choose a target section.
Each section starts from a freshly unpacked upstream tree. Package dependencies
are listed per target; `clang++-14` comes with `clang-14`.

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang-14 git curl ca-certificates python3
cd "$HOME/lava"
export LAVA="$PWD"
export CC=clang-14 CXX=clang++-14
export CFLAGS='-O0 -g -gdwarf-2 -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION'
export CXXFLAGS="$CFLAGS"
export JOBS=8
mkdir -p "$LAVA/target_bins"
```

The commands unpack into `target_bins/` for manual work; LAVA itself later
unpacks these same tarballs into its configured work directories. For a rebuild,
use a fresh extraction directory rather than mixing previously instrumented or
configured sources. To save a source download under the intended filename, use
`curl -fL RAW_DOWNLOAD_URL -o "$LAVA/target_bins/FILENAME"`.

## OpenSSL

### target_bins: source provenance and compilation

**Source:** pin `b0593c086dd303af31dc1e30233149978dd613c4`. FuzzBench's Dockerfile
initially clones 3.0.7, but its later YAML-driven checkout selects this older
revision. The harness is `fuzz/x509.c`; upstream `fuzz/test-corpus.c` calls the
same `FuzzerInitialize`/`FuzzerTestOneInput` that its fuzz-engine adapter calls.
No extra C source or dictionary is required to replay files.

**Reviewer check:** [benchmark.yaml](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/openssl_x509/benchmark.yaml)
names this revision; [checkout_commit.py](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/docker/benchmark-builder/checkout_commit.py)
explains why it overrides the Dockerfile's initial tag. Upstream
[fuzz/build.info](https://github.com/openssl/openssl/blob/b0593c086dd303af31dc1e30233149978dd613c4/fuzz/build.info)
defines `x509-test` from `x509.c` and `test-corpus.c`. The downloaded archive
is saved unchanged under the filename shown below.

```bash
sudo apt-get install -y perl
cd "$LAVA/target_bins"
curl -fL https://github.com/openssl/openssl/archive/b0593c086dd303af31dc1e30233149978dd613c4.tar.gz \
  -o openssl-fuzzbench-b0593c0.tar.gz
tar xzf openssl-fuzzbench-b0593c0.tar.gz
cd openssl-b0593c086dd303af31dc1e30233149978dd613c4
./config --debug enable-fuzz-libfuzzer -DPEDANTIC \
  -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared enable-tls1_3 \
  enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-ssl3 \
  enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers \
  $CFLAGS -fno-sanitize=alignment
make -j"$JOBS" build_generated
make -j"$JOBS" fuzz/x509-test LDCMD="$CXX $CXXFLAGS"
# Replay any input file:
# ./fuzz/x509-test /absolute/path/to/input
```

We build only the upstream file runner, so no fuzzing-engine archive is needed.
The input format is DER bytes, including malformed DER; the PEM-oriented
`openssl x509` CLI is a different workload.

### target_configs: seed provenance and preparation

**Seeds:** `fuzz/corpora/x509/*` at the same pin: 2,241 unique inputs. GitHub
archives omit this directory via `export-ignore`. If absent, the input script
fetches the exact pinned Git corpus into a temporary directory, copies the
inputs and removes the temporary checkout. It does not use today's corpus.

**Reviewer check:** FuzzBench's pinned
[build.sh](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/openssl_x509/build.sh)
zips `fuzz/corpora/${fuzzer}/*`; `fuzzer=x509` gives exactly this directory.
Our [fuzzbench_inputs.py](../target_configs/openssl/fuzzbench_inputs.py) selects it at
the same Git revision. Its absence from an archive is explained by upstream
[.gitattributes](https://github.com/openssl/openssl/blob/b0593c086dd303af31dc1e30233149978dd613c4/.gitattributes),
not by an invented replacement corpus.

```bash
python3 "$LAVA/target_configs/openssl/fuzzbench_inputs.py" \
  "$LAVA/target_bins/openssl-b0593c086dd303af31dc1e30233149978dd613c4" \
  --output "$LAVA/target_configs/openssl/fuzzbench-inputs"
```

## SQLite

### target_bins: source provenance and compilation

**Source:** Fossil `c78cbf2e86850cc6882d3f0bd5415f6e731c3c675ffe77bb343682c619cb8cd9`;
the script checks `manifest.uuid`. The harness is upstream `test/ossfuzz.c`,
linked with generated `sqlite3.o`. FuzzBench's `ossfuzz.dict` is optional mutation
data, not necessary for compilation or standalone replay.

**Reviewer check:** the [Dockerfile](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/sqlite3_ossfuzz/Dockerfile)
contains the exact Fossil tarball URL; its YAML `commit` is empty, so there is
no subsequent revision override. [build.sh](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/sqlite3_ossfuzz/build.sh)
compiles `test/ossfuzz.c` and lists the limit/debug defines below. The archive's
`manifest.uuid` records the full Fossil revision.

```bash
sudo apt-get install -y autoconf automake libtool tcl tcl-dev zlib1g-dev
cd "$LAVA/target_bins"
# Skip this download if the matching raw archive is already present.
curl -fL 'https://sqlite.org/src/tarball/sqlite.tar.gz?r=c78cbf2e86850cc6' \
  -o sqlite-fuzzbench-c78cbf2e86850cc6.tar.gz
tar xzf sqlite-fuzzbench-c78cbf2e86850cc6.tar.gz
cd sqlite
(
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
  cp "$LAVA/target_configs/sqlite/fuzzbench_driver.c" .
  $CC $CFLAGS -c fuzzbench_driver.c -o fuzzbench_driver.o
  $CXX $CXXFLAGS ossfuzz.o fuzzbench_driver.o sqlite3.o \
    -o ossfuzz -pthread -ldl -lz
)
# ./bld/ossfuzz /absolute/path/to/input
```

### target_configs: seed provenance and preparation

**Seeds:** all upstream `*.test` files verbatim, as in FuzzBench's Dockerfile.
Reference: 1,265 files, 1,263 retained after its size policy. These include Tcl
scripts; no SQL extraction is performed. The harness consumes SQL bytes (with
an optional selector/newline prefix) and uses an in-memory database. Database
files supplied to the SQLite CLI are a different interface. Preserve generated
`sqlite3.c`/`sqlite3.h` when eventually instrumenting: regeneration loses edits.

**Reviewer check:** the pinned
[Dockerfile](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/sqlite3_ossfuzz/Dockerfile)
uses `find ... -name "*.test"` to create the corpus. Our
[fuzzbench_inputs.py](../target_configs/sqlite/fuzzbench_inputs.py) applies that same
file rule after checking the Fossil revision. It can run immediately after
extraction; building SQLite first is unnecessary for seeds.

```bash
python3 "$LAVA/target_configs/sqlite/fuzzbench_inputs.py" \
  "$LAVA/target_bins/sqlite" \
  --output "$LAVA/target_configs/sqlite/fuzzbench-inputs"
```

## libxml2

### target_bins: source provenance and compilation

**Source:** `c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e`. Use upstream `fuzz/xml.c`
plus `fuzz/fuzz.c`/`fuzz/fuzz.h`. FuzzBench's adjacent `target.cc` is unused by
its build recipe. This is `libxml2_xml`, not its separately pinned bug variant.

**Reviewer check:** [benchmark.yaml](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/libxml2_xml/benchmark.yaml)
sets the revision, and [build.sh](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/libxml2_xml/build.sh)
explicitly compiles/links `xml.o` and `fuzz.o` with the library. The raw download
is from GNOME's GitHub mirror at that same commit; the Dockerfile uses GNOME
GitLab. The extra file-reading adapter is copied from this repository after
extraction, not hidden inside the upstream archive.

```bash
sudo apt-get install -y autoconf automake libtool pkg-config zlib1g-dev liblzma-dev
# automake must be >= 1.16.3.
cd "$LAVA/target_bins"
curl -fL https://github.com/GNOME/libxml2/archive/c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e.tar.gz \
  -o libxml2-fuzzbench-c7260a4.tar.gz
tar xzf libxml2-fuzzbench-c7260a4.tar.gz
cd libxml2-c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e
./autogen.sh --disable-shared --without-debug --without-ftp --without-http \
  --without-legacy --without-python
make -j"$JOBS"
(
  cd fuzz
  make fuzz.o xml.o
  cp "$LAVA/target_configs/libxml2/fuzzbench_driver.c" .
  $CC $CFLAGS -c fuzzbench_driver.c -o fuzzbench_driver.o
  $CXX $CXXFLAGS xml.o fuzz.o fuzzbench_driver.o -o xml \
    ../.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic
)
# ./fuzz/xml /absolute/path/to/input
```

### target_configs: seed provenance and preparation

**Seeds:** the script runs upstream `make -C fuzz seed/xml.stamp`, which packages
tests using `fuzz/genSeed.c`. Configure/build the library first as above.
Reference: 308 bundles, 307 retained. Inputs encode parser options and
URL/content entity pairs; raw XML documents are not equivalent. Keep the
initializer/entity loader: this harness exercises several parser interfaces
and serialization. Static zlib/lzma archives are required by the link above.

**Reviewer check:** FuzzBench's pinned
[build.sh](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/libxml2_xml/build.sh)
calls `make seed/xml.stamp`. The actual test globs and generator command are in
upstream [fuzz/Makefile.am](https://github.com/GNOME/libxml2/blob/c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e/fuzz/Makefile.am);
[fuzz/genSeed.c](https://github.com/GNOME/libxml2/blob/c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e/fuzz/genSeed.c)
implements the encoding. Our [fuzzbench_inputs.py](../target_configs/libxml2/fuzzbench_inputs.py)
runs that upstream rule rather than reimplementing its serialization.

```bash
# Requires the configured/built library from the compilation subsection.
python3 "$LAVA/target_configs/libxml2/fuzzbench_inputs.py" \
  "$LAVA/target_bins/libxml2-c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e" \
  --output "$LAVA/target_configs/libxml2/fuzzbench-inputs"
```

## libpng

### target_bins: source provenance and compilation

**Source:** `cd0ea2a7f53b603d3d9b5b891c779c430047b39a`. The upstream harness is
`contrib/oss-fuzz/libpng_read_fuzzer.cc`. The following feature edits and prefix
come from that pin's `contrib/oss-fuzz/build.sh`.

**Reviewer check:** [benchmark.yaml](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/libpng_libpng_read_fuzzer/benchmark.yaml)
sets the revision; the pinned upstream
[build.sh](https://github.com/glennrp/libpng/blob/cd0ea2a7f53b603d3d9b5b891c779c430047b39a/contrib/oss-fuzz/build.sh)
contains the feature edits, prefix and harness link command below. This is a
raw libpng archive; zlib is a separately installed dependency, and the adapter
comes explicitly from `target_configs/`. See the provenance limits below.

```bash
sudo apt-get install -y autoconf automake libtool zlib1g-dev
cd "$LAVA/target_bins"
curl -fL https://github.com/glennrp/libpng/archive/cd0ea2a7f53b603d3d9b5b891c779c430047b39a.tar.gz \
  -o libpng-fuzzbench-cd0ea2a.tar.gz
tar xzf libpng-fuzzbench-cd0ea2a.tar.gz
cd libpng-cd0ea2a7f53b603d3d9b5b891c779c430047b39a
sed -e 's/option STDIO/option STDIO disabled/' \
    -e 's/option WARNING /option WARNING disabled/' \
    -e 's/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/' \
    scripts/pnglibconf.dfa > scripts/pnglibconf.dfa.temp
mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa
autoreconf -fi
./configure --with-libpng-prefix=OSS_FUZZ_
make -j"$JOBS" libpng16.la
cp "$LAVA/target_configs/libpng/fuzzbench_driver.c" .
$CC $CFLAGS -c fuzzbench_driver.c -o fuzzbench_driver.o
$CXX $CXXFLAGS -std=c++11 -I. contrib/oss-fuzz/libpng_read_fuzzer.cc \
  fuzzbench_driver.o .libs/libpng16.a -lz -o libpng_read_fuzzer
# ./libpng_read_fuzzer /absolute/path/to/input
```

Two provenance limits in the original integration: the Dockerfile copies the
upstream build script before its pinned checkout, and clones zlib v1.2.13 but
the inspected pinned script simply links host `-lz`. This guide freezes the
pinned script's logic and uses installed zlib. An archived image/script is
needed to establish the exact historical script/dependency versions.

### target_configs: seed provenance and preparation

**Seeds:** all source-tree `*.png`, excluding paths containing `crashers`:
169 source files, 156 unique retained inputs. FuzzBench's extra
`seeds/seed.png` copied to `/opt/seeds` is not included by this packaging rule.
The harness's memory reader, transformations and checksum handling differ from
`pngtest`; keep its generated headers and `OSS_FUZZ_` symbol prefix.


**Reviewer check:** the pinned upstream
[build.sh](https://github.com/glennrp/libpng/blob/cd0ea2a7f53b603d3d9b5b891c779c430047b39a/contrib/oss-fuzz/build.sh)
uses `find ... -name "*.png" | grep -v crashers`. Our
[fuzzbench_inputs.py](../target_configs/libpng/fuzzbench_inputs.py) uses that same rule;
it does not substitute the Dockerfile's extra `/opt/seeds` file. It can run
on the unbuilt raw source tree.

```bash
python3 "$LAVA/target_configs/libpng/fuzzbench_inputs.py" \
  "$LAVA/target_bins/libpng-cd0ea2a7f53b603d3d9b5b891c779c430047b39a" \
  --output "$LAVA/target_configs/libpng/fuzzbench-inputs"
```

## Project-local preparation and seeds

Each project directory contains its own `prepare.sh`, `fuzzbench_prepare.py`,
`fuzzbench_inputs.py`, and `fuzzbench_driver.c`. Copying that directory is enough
for its preparation code; no imports, shell helpers or drivers are read from a
parent/sibling configuration directory. Their docstrings cite the pinned
FuzzBench source/build and seed-packaging evidence. The old `fetch_inputs.sh`
entry points and consolidated helpers have been removed.

`prepare.sh` orchestrates raw-source verification/download and seed generation.
`fuzzbench_inputs.py` contains only the seed rule/copying logic and can be run
separately against a pinned source, as shown in the seed subsections above.
Both apply the pinned
[runner.py](https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/experiment/runner.py)
policy: discard files larger than 1 MiB and deduplicate/name content by SHA-1.
A SHA-256/provenance manifest is written next to the corpus, not inside it.
There is no coverage-based reduction at this preparation step.

For manual preparation, explicitly pass the archive location; the script does
not guess where a parent repository lives:

```bash
bash "$LAVA/target_configs/sqlite/prepare.sh" \
  --tar-dir "$LAVA/target_bins" \
  --inputs-dir "$LAVA/target_configs/sqlite/fuzzbench-inputs"
```

The four scripts have the same options. `--tarfile` accepts an explicit archive
filename instead of `--tar-dir`. `--source-only` only verifies/downloads the raw
archive. `--setup-tree /absolute/source/path` only copies the local adapter if
absent; an existing modified/possibly instrumented copy is preserved. Source
archives stay untouched. Required OS packages are listed per target; scripts
do not run sudo. libxml2 builds its seed generator in scratch space, then repeat
calls with verified outputs skip extraction/build/generation.

The current JSONs now select these harnesses and use their prepared `inputs/`.
The previous CLI fixtures remain in `inputs-cli-backup/`. Unexpected/mixed input
files are still rejected rather than overwritten. Manual `--inputs-dir` is useful
for a separate audit/staging corpus. Coverage-based selection before PANDA
remains a separate [step](../docs/lava-corpus-selection-plan.md).

## LAVA integration: supported now

`parse_vars()` automatically runs `<config_dir>/prepare.sh` when present, using
Bash with the project configuration directory as the working directory. This
happens before `LavaPaths` lists the tarball. No `prepare` JSON field or executable
permission bit is needed. Preparation failure stops project loading; projects
without the script keep their existing behavior. LAVA passes absolute paths in
`LAVA_PROJECT_CONFIG`, `LAVA_CONFIG_DIR`, `LAVA_TARFILE`, `LAVA_TAR_DIR`, and
`LAVA_INPUTS_DIR`. The script itself decides what work is needed on each call.

The four scripts check the selected source filename and harness executable.
All four current JSONs match, so automatic preparation populates their harness
corpora. Restoring a legacy CLI JSON causes its script to skip FuzzBench work.
The adapter setup is invoked by the JSON's `pre_make` where needed; no new
post-extraction hook is added. Configure/make/install commands now also accept
`{config_dir}`, allowing libpng's target-local configure script to run from the
extracted tree. The ordinary compilation database captures the harness/main and
library sources for each target.

Project JSON now accepts trusted flag additions:

```json
{
  "build_flags": {
    "CFLAGS": ["-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"],
    "CXXFLAGS": ["-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"],
    "LDFLAGS": []
  }
}
```

The loader validates these string arrays and appends them to `default`, `panda`,
`inject`, and `llvm_cov`, retaining each phase's existing defaults and printing
the resulting flags. Target additions come last, with normal compiler option
ordering; there is no optimization/conflict policy. C and C++ flags stay separate.
Configure/make/install already receive their selected phase environment. Custom
recipes must still honor it and include `LDFLAGS` in custom link commands.
Do not replace these defaults by hard-coding a second set in scripts.

See [the preparation and flags interface](../docs/lava-target-preparation-plan.md)
for lifecycle details and the distinction between preparation and a completed
FuzzBench/LAVA target migration.

## Verification

The pinned native harness builds and baseline seed inventories were verified
on 2026-11-12 and 2026-11-14. The self-contained preparation copies are tested
for checksum validation, seed size/deduplication rules, repeat-call skipping,
modified-driver preservation and execution after relocation without parent
helpers. Configuration tests check all four phase flag environments and verify
that preparation can create a missing archive before tarball inspection and
that failures stop loading. The four existing JSONs now build the FuzzBench
harnesses for native generation and coverage; their old CLI inputs are retained in backup directories.
Native preparation/replay tests do not establish full LAVA/PANDA/angr integration.

The four current JSONs were also built with `magmalyze --build-only` into the
configured `/home/ubuntu/lava/target_generation`. Each installed executable
passed native input replay and its compilation database contains the expected
harness/main sources. All four `lava-coverage` builds and corpus runs completed
using an isolated temporary generation directory. Logs and a native build
report are under `/tmp/magmalyze-fuzzbench-build/`; coverage profiles/reports
are under `/tmp/magmalyze-fuzzbench-coverage/generation/`. The normal analysis
binaries in the configured generation directory were preserved. The focused
configuration/preparation/build-CLI suite passed 42 tests, with 3 SQLite-only
cases skipped for other targets. This does not claim successful deep symbolic
exploration or LAVA injection.
