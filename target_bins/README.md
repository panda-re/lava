# Target Programs
This folder has the list of binaries used in publications.

# Misc binaries
* The [original toy](https://github.com/moyix/toy/tree/main) source code.
* [Graphland](https://github.com/moyix/graphland/), albeit slightly modified to work on run-time
* labyrinth was generated with AI, but this was used to confirm that Angr is in fact using the KLEE random search algorithm

## Chaff Bugs paper
The [Chaff Bugs](https://arxiv.org/pdf/1808.00659) paper has used three targets:

The copies were obtained from here:
* [nginx-1.13.1](https://nginx.org/download/nginx-1.13.1.tar.gz)
  * Working on figuring out how LAVA can work with installation requirements
* [file-5.30](https://www.astron.com/pub/file/file-5.30.tar.gz)
    * Unfortunately, to pre-process file, it requires "magic.h", but it is not generated in "configure". So we manually generate and stick magic.h into src/.
    * Currently, there is an issue on dwarf2 output where it says `src/src` meaning debug symbols can't be found in recording.
* [libflac-1.3.2](https://ftp.osuosl.org/pub/xiph/releases/flac/flac-1.3.2.tar.xz)
  * Haven't tested building this yet.