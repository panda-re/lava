# Target Programs
This folder has the list of binaries used in publications.

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