# Target Programs
This folder has the list of binaries used in publications.

## FuzzBench harness targets

See [Fuzzbench.md](Fuzzbench.md) for pinned OpenSSL, SQLite, libxml2 and libpng
sources, per-target dependencies, terminal build commands, default seed corpora,
and notes on adapting the harness executables to LAVA.

## Deathstar Bench

### Target binary

Target name: **`deathstar_media`**. This builds a bounded file-backed RPC entry
into the real Social Network **MediaService**, not just its argument decoder:

`request file -> Thrift BinaryProtocol -> upstream MediaServiceProcessor -> upstream MediaHandler::ComposeMedia -> serialized reply`

The raw source is [DeathStarBench at commit
6ecb09706140f8730b5385c08f1386c654c3c526](https://github.com/delimitrou/DeathStarBench/tree/6ecb09706140f8730b5385c08f1386c654c3c526).
Download: [the raw source archive](https://codeload.github.com/delimitrou/DeathStarBench/tar.gz/6ecb09706140f8730b5385c08f1386c654c3c526).
`target_bins/deathstarbench-6ecb09706140.tar.gz` has SHA-256
`1042fe02a980d4c8bd191b80a822182e3a9fcb682580874d32a2d0d7b5b72628`.
It is the full upstream archive, without repacked adapters or prebuilt libraries.

Reviewer entry points are the pinned upstream
[handler](https://github.com/delimitrou/DeathStarBench/blob/6ecb09706140f8730b5385c08f1386c654c3c526/socialNetwork/src/MediaService/MediaHandler.h),
[generated processor](https://github.com/delimitrou/DeathStarBench/blob/6ecb09706140f8730b5385c08f1386c654c3c526/socialNetwork/gen-cpp/MediaService.cpp),
and [original server](https://github.com/delimitrou/DeathStarBench/blob/6ecb09706140f8730b5385c08f1386c654c3c526/socialNetwork/src/MediaService/MediaService.cpp).
The local [driver](../target_configs/deathstar_media/lava_media_driver.cpp) calls
that processor and handler; it does not implement their business logic itself.
The handler is compiled in a separate `lava-media/media_handler.cpp` unit. A
future live RPC entry point must link that same instrumented object/translation
unit. LAVA flattens headers during preprocessing, so rebuilding a pristine
`MediaHandler.h` in another server would not automatically carry its injections.

The additional source dependencies are **Thrift 0.12.0**, matching the generated
code, **OpenTracing C++ 1.5.1**, matching the upstream container build pin, and
**Boost 1.69.0 headers** for Thrift. URLs and full archive hashes are recorded in
[pins.json](../target_configs/deathstar_media/pins.json).
Preparation builds the two static runtime archives locally under
`target_configs/deathstar_media/.target-prepare/`; it does not install system
packages or alter a separate DeathStarBench checkout. Install these host tools:

```bash
sudo apt-get install build-essential clang-14 cmake curl python3
export LAVA="$HOME/lava"
cd "$LAVA"
export PATH="$LAVA/venv/bin:$PATH"
magmalyze --project deathstar_media --build-only
```

Run the command with the LAVA virtual environment active (or prepend
`$LAVA/venv/bin` to `PATH`). The normal project JSON discovers `prepare.sh`, which
verifies/downloads sources, prepares dependencies and seeds, then the normal
configure/make/install pipeline builds the executable. The installed binary is:

```text
target_generation/deathstar_media/DeathStarBench-6ecb09706140f8730b5385c08f1386c654c3c526/lava-install/bin/lava_media_driver
```

To reproduce outside Magmalyze, using the same build recipe:

```bash
bash "$LAVA/target_configs/deathstar_media/prepare.sh" --tar-dir "$LAVA/target_bins"
mkdir -p /tmp/deathstar-media-review
tar xzf "$LAVA/target_bins/deathstarbench-6ecb09706140.tar.gz" -C /tmp/deathstar-media-review
cd /tmp/deathstar-media-review/DeathStarBench-6ecb09706140f8730b5385c08f1386c654c3c526
bash "$LAVA/target_configs/deathstar_media/configure.sh" "$PWD/lava-install"
make -j4 CXX=clang++-14 CXXFLAGS='-O0 -g -gdwarf-2 -fno-omit-frame-pointer -std=c++14'
make install
./lava-install/bin/lava_media_driver "$LAVA/target_configs/deathstar_media/inputs/media.bin"
```

The setup step adds `lava-media/` and a focused Makefile to the extracted tree.
`MediaHandler.h`, generated RPC code and IDL remain byte-for-byte upstream.
`lava-media/source-manifest.json` records the relevant source and adapter hashes.
Existing adapter files are preserved on subsequent configure calls so later
instrumentation is not overwritten.

This profile uses the real OpenTracing **no-op tracer** in place of Jaeger
startup/export. The adapter bypasses upstream logger/tracer startup definitions
and copies the upstream `TextMapReader`/`TextMapWriter` classes unchanged. All
handler code, including tracing API calls, remains unchanged. This is a
documented telemetry adaptation, not the original full service deployment.
The harness accepts one frame up to 1 MiB, with protocol string/container limits
of 1 MiB/65,536 entries. It starts no network server. The protocol is **Apache
Thrift RPC, not gRPC**.

### Inputs

There is no claimed official MediaService fuzzing corpus here. The four fixtures
are locally authored [example arguments](../target_configs/deathstar_media/examples)
encoded by [make_seeds.py](../target_configs/deathstar_media/make_seeds.py).
The authoritative schema is the pinned upstream
[social_network.thrift](https://github.com/delimitrou/DeathStarBench/blob/6ecb09706140f8730b5385c08f1386c654c3c526/socialNetwork/social_network.thrift):
ComposeMedia fields 1–4 are `req_id: i64`, `media_types: list<string>`,
`media_ids: list<i64>`, and `carrier: map<string,string>`.

Each file contains a four-byte big-endian frame length followed by a strict
BinaryProtocol `ComposeMedia` CALL. These are application RPC bytes, without
Ethernet/IP/TCP headers. The fixtures cover two returned media objects, a tracing
carrier, empty lists, and mismatched list lengths that produce the handler's
declared service exception. Reproduce them independently with:

```bash
python3 "$LAVA/target_configs/deathstar_media/make_seeds.py"
# Also check the generated wire messages against the actual processor/handler:
python3 "$LAVA/target_configs/deathstar_media/make_seeds.py" --validate-binary \
  "$LAVA/target_generation/deathstar_media/DeathStarBench-6ecb09706140f8730b5385c08f1386c654c3c526/lava-install/bin/lava_media_driver"
```

The same command is called automatically by `prepare.sh`. It records example
hashes, exact seed hashes/sizes and expected handler responses in
`target_configs/deathstar_media/inputs.manifest.json`. Existing differing seeds
cause an error rather than being overwritten. The old decoder-only files under
`draft/` are historical scaffolding; the active JSON uses the real-handler driver.

## Nginx (Modern)

### Target Binary

Target name: **`nginx_current`**, pinned to the existing **nginx 1.30.6** source.
This is a fixed modern comparison target, not a floating latest-version target.
Source:
[official nginx-1.30.6.tar.gz](https://nginx.org/download/nginx-1.30.6.tar.gz), saved
unchanged as `target_bins/nginx-1.30.6.tar.gz`, SHA-256
`3cf46f5ed7504d460125866b7bea99fb357f31d887e2e63b35503310e9b8b6c8`.

[prepare.py](../target_configs/nginx_current/prepare.py) checks/downloads the raw
archive and prepares fixtures. The normal project configuration uses nginx's
own configure/make/install, passing LAVA's selected compiler and phase flags
explicitly. The libtool-only linker option `-all-static` is filtered out because
it belongs to libtool; `-static` and other selected linker flags are retained.
The initial profile disables rewrite/PCRE, gzip/zlib and HTTP basic auth. TLS,
HTTP/2 and third-party modules are not enabled. This reduced profile is declared
explicitly rather than presented as a full production deployment.

```bash
sudo apt-get install build-essential clang-14 curl python3
export LAVA="$HOME/lava"
cd "$LAVA"
export PATH="$LAVA/venv/bin:$PATH"
magmalyze --project nginx_current --build-only
```

Installed binary:
`target_generation/nginx_current/nginx-1.30.6/lava-install/sbin/nginx`.
For an independent terminal build:

```bash
bash "$LAVA/target_configs/nginx_current/prepare.sh" --tar-dir "$LAVA/target_bins"
mkdir -p /tmp/nginx-modern-review
tar xzf "$LAVA/target_bins/nginx-1.30.6.tar.gz" -C /tmp/nginx-modern-review
cd /tmp/nginx-modern-review/nginx-1.30.6
export CC=clang-14 CFLAGS='-O0 -g -gdwarf-2 -fno-omit-frame-pointer' LDFLAGS=''
bash "$LAVA/target_configs/nginx_current/configure.sh" "$PWD/lava-install"
make -j4
make install
./lava-install/sbin/nginx -t -q -p "$PWD/lava-install/" \
  -c "$LAVA/target_configs/nginx_current/inputs/minimal.conf"
```

The source archive needs no added C driver. Its real `src/core/nginx.c` main
remains the entry point. The generated `objs/` files are excluded from
query insertion because configure rewrites them; nginx C sources remain in scope.

On 2026-11-22, `lava -qm nginx_current` also passed: 117 C sources contain
52,143 query calls, and the installed analysis binary is static x86-64 with
DWARF 2. Three native configuration checks passed. That binary is at
`target_injections/nginx_current/nginx-1.30.6/lava-install/sbin/nginx`.
This verifies query insertion and compilation; no PANDA recording, tainting or
injection was run. [Network preparation](../target_configs/nginx_current/network/README.md)
documents the mock-tested plugin selection and the missing network recording
and packet-to-seed mapping support.

### Inputs

The three locally authored [fixtures](../target_configs/nginx_current/fixtures)
are `minimal.conf`, `headers.conf`, and `map.conf`. They exercise normal
configuration loading, headers/content settings and variable-map configuration.
`prepare.sh` verifies/copies them into `target_configs/nginx_current/inputs/` and
writes `inputs.manifest.json` with source URL/archive hash and exact input hashes.
Existing differing inputs are preserved by stopping with an error.

The active command is `nginx -t -q -p PREFIX/ -c INPUT`: these are configuration
parser inputs, **not HTTP requests**. They establish a file-backed native build
target. HTTP/proxy workload integration and network-input exploration require a
later execution adapter and are not supplied by `--build-only`.

For both targets, build-only stops before concolic exploration. Successful native
builds do not establish C++ query-insertion support, PANDA recording/tainting,
bug injection, or container/network deployment. Those are separate milestones.

### Build-only validation (2026-11-22)

Both `magmalyze --project TARGET --build-only` commands completed successfully
with the shared project JSONs. Their compilation databases retain `-O0` and
`-gdwarf-2` for every recorded compilation:

| Target | Compiler records | Native input checks |
| --- | ---: | --- |
| `deathstar_media` | 4 C++ units | 4/4 expected processor/handler responses |
| `nginx_current` | 118 C units | 3/3 configurations accepted by `nginx -t` |

The MediaService binary contains the actual handler and generated dispatch
symbols. Its handler, IDL and generated sources match the raw pinned archive.
Normal, traced and empty-list requests return their expected media values;
the mismatched-list fixture returns the expected serialized service exception
with exit code 0. That exception is an ordinary RPC error response, not a crash.
Installed seed copies match their source manifests. The dependency libraries are
linked from static archives; the native executables are not claimed to be fully
static PANDA builds. The local artifact report and logs are under
`/tmp/lava-service-bootstrap/`. No concolic exploration, query insertion,
PANDA recording/tainting, bug injection or live network service was run.
The focused preparation/configuration/build-only regression suite passed
13 tests and 8 subtests. It checks cached-archive integrity, seed protection and
preservation of instrumented adapters on repeated setup.

## Misc binaries
* The [original toy](https://github.com/AndrewQuijano/toy/) source code.
* [Graphland](https://github.com/moyix/graphland/), albeit slightly modified to work on run-time
* labyrinth was generated with AI, but this was used to confirm that Angr is in fact using the KLEE random search algorithm

## Chaff Bugs paper
The [Chaff Bugs](https://arxiv.org/pdf/1808.00659) paper has used three targets:

The copies were obtained from here:
* [nginx-1.13.1](https://nginx.org/download/nginx-1.13.1.tar.gz)
  * Reduced-module native/static build and prefix-local installation verified;
    configuration-parser target and benign HTTP fixtures are in
    [target_configs/nginx](../target_configs/nginx/README.md). Network taint still
    needs input-identity and packet-to-seed label mapping; see the
    [nginx/DeathStarBench plan](../docs/nginx-deathstar-taint-plan.md).
  * 1.13.1 is the historical paper baseline, not a current-release security baseline.
* [file-5.30](https://www.astron.com/pub/file/file-5.30.tar.gz)
    * Unfortunately, to pre-process file, it requires "magic.h", but it is not generated in "configure". So we manually generate and stick magic.h into src/.
    * Currently, there is an issue on dwarf2 output where it says `src/src` meaning debug symbols can't be found in recording.
* [libflac-1.3.2](https://ftp.osuosl.org/pub/xiph/releases/flac/flac-1.3.2.tar.xz)
  * Haven't tested building this yet.

## LAVA-M Dataset
To replicate building the LAVA-M data using version 8.24 as specified in the paper, run the following

```bash
wget https://ftp.gnu.org/gnu/coreutils/coreutils-8.24.tar.xz
tar -xf coreutils-8.24.tar.xz
cd coreutils-8.24/src/
```
