# Modern nginx: pinned native build-only target

The active `nginx_current` target pins **1.30.6**, the modern archive already
available in this workspace. It is deliberately not a moving latest-release
alias. The historical `nginx` 1.13.1 target is unchanged.

See [target_bins/README.md](../../target_bins/README.md#nginx-modern) for the
archive URL/checksum, dependency installation, standalone build commands and
input provenance. Run with the LAVA Python environment active:

```bash
magmalyze --project nginx_current --build-only
```

`prepare.sh` verifies/downloads the unmodified nginx archive and verifies/copies
three authored `.conf` fixtures into `inputs/`; hashes are recorded in
`inputs.manifest.json`. It requires explicit archive paths when run manually:

```bash
bash target_configs/nginx_current/prepare.sh --tar-dir "$PWD/target_bins"
```

`configure.sh` explicitly forwards the selected compiler, CFLAGS and LDFLAGS to
nginx's configure system. Rewrite/PCRE, gzip and HTTP basic auth are disabled in
this reduced profile. Generated `objs/` source is excluded from later query
insertion. The compiler-only build preserves static linker flags when that phase
is selected, while dropping the libtool-only `-all-static` option.

The configured execution command is **nginx -t**, so the seeds exercise
configuration parsing, not HTTP request processing. Build-only performs no
concolic exploration, network traffic, PANDA recording, tainting or injection.
Native HTTP/proxy work is a later milestone with its own request-delivery and
input provenance requirements. Existing HTTP prototype notes are in the
[earlier plan](../../docs/nginx-deathstar-taint-plan.md).
