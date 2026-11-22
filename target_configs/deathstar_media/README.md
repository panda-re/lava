# DeathStarBench MediaService: native build-only target

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

This milestone establishes native build/install, compiler-command capture and
file-backed application execution. C++ query insertion, PANDA replay/taint,
bug injection, live RPC orchestration and container deployment remain separate
validation tasks. No network-input generation is implemented.
