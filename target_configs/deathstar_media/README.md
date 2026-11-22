# DeathStarBench MediaService: native and query/static builds

The active target is `deathstar_media`. It reads a framed Thrift BinaryProtocol
request file, invokes the upstream generated MediaServiceProcessor and the real
MediaHandler::ComposeMedia, and prints a decoded reply summary. It starts no
network server. This is Apache Thrift RPC, not gRPC.

See [target_bins/README.md](../../target_bins/README.md#deathstar-bench) for source
URLs/hashes, dependencies, independent terminal build commands and input provenance.
`pins.json` is the source/dependency lock file. `prepare.sh` is automatically run
by LAVA's existing configuration loader and can also be invoked manually:

```bash
bash target_configs/deathstar_media/prepare.sh --tar-dir "$PWD/target_bins"
magmalyze --project deathstar_media --build-only
```

Host prerequisites: Python 3.12+, curl, cmake, make, clang/clang++ 14 and a C++
development toolchain. Dependencies are built under `.target-prepare/`, without
system package installation. Boost supplies headers; the focused target links
static Thrift 0.12.0 and OpenTracing 1.5.1 runtime archives. Startup uses the
OpenTracing no-op tracer rather than Jaeger export/logging initialization.

The raw full upstream archive is never repacked. Setup adds a focused Makefile
and `lava-media/` adapter files, preserving any existing adapter source so future
instrumentation is not overwritten. The original handler, IDL and generated RPC
files remain unchanged. `lava-media/source-manifest.json` records their hashes.
The handler is compiled separately from the file entry point so a future RPC
entry point can reuse the same instrumented implementation. Merely rebuilding
a pristine header in the original server would not preserve flattened-source
injections.

Four locally authored examples generate the baseline: normal media, a tracing
carrier, empty lists and a declared list-length exception. To verify wire format
and real handler responses after building:

```bash
python3 target_configs/deathstar_media/make_seeds.py --validate-binary /absolute/path/to/lava_media_driver
```

`inputs.manifest.json` records exact bytes/hashes, example provenance and expected
responses. The `draft/` decoder-only target and `prepare_source.py` are retained
as historical scaffolding; neither is used by the active JSON.

## Query/static build

With the normal LAVA environment and `host.json` configured, build the updated
tools locally and select them ahead of an older system installation:

```bash
export LAVA="$HOME/lava"
cd "$LAVA"
cmake --build tools/build --target lavaTool -j4
export PATH="$LAVA/tools/build/lavaTool/src:$LAVA/venv/bin:$PATH"
lava -qm deathstar_media
```

The source pin, adapter and four compilation units are the same as the native
build. LAVA snapshots the flattened `.cpp` files, inserts query probes and
rebuilds with the `panda` static/debug environment. The analysis binary is:

```text
target_injections/deathstar_media/DeathStarBench-6ecb09706140f8730b5385c08f1386c654c3c526/lava-install/bin/lava_media_driver
```

Verified on 2026-11-22: a fresh combined `-qm` completed, producing a static
x86-64 executable with DWARF 2 and 5,279 query calls across four translation
units, including flattened headers. The actual `MediaHandler::ComposeMedia`
body contains 17 queries, and `MediaServiceProcessor::process_ComposeMedia`
contains 36. All four native fixture responses match their expected results,
including the declared exception for mismatched lengths. Repeat this check by
passing the analysis binary above to `make_seeds.py --validate-binary`.

This is a focused C++14 query profile. It skips constexpr/template-dependent
functions, template instantiations, implicit/defaulted/deleted functions,
non-block function bodies, constant-expression contexts and synthesized
range-for initializers. Explicit runtime handler/processor code remains in
scope. C++ expression probes preserve types and reference categories; null
pointer constants and callback addresses are left intact. C retains its existing
probe form. The language regression tests compile and execute both results.

The project-only `-Wno-invalid-constexpr` flag accommodates libstdc++ math
declarations after `-E -P` removes their system-header status. It does not remove
`constexpr` from the source. The original tarball and configuration-side source
adapters are not rewritten by query insertion.

PANDA guest execution, C++ variable/type introspection, tainting, bug injection,
live RPC orchestration and container deployment remain unverified. The active
file-backed harness retains file taint; a future live network profile requires
its own request recording and packet-to-input mapping. No VM, tainting,
injection or network traffic was run for this build validation.
