# Target Programs
This folder has the list of binaries used in publications.

## Chaff Bugs paper
The [Chaff Bugs](https://arxiv.org/pdf/1808.00659) paper has used three targets:

The copies were obtained from here:
* [nginx-1.13.1](https://nginx.org/download/nginx-1.13.1.tar.gz)
* [file-5.30](https://www.astron.com/pub/file/file-5.30.tar.gz)
    * Unfortunately, to pre-process file, it requires "magic.h", but it is not generated in "configure". So we manually generate and stick magic.h into src/.
* [libflac-1.3.2](https://ftp.osuosl.org/pub/xiph/releases/flac/flac-1.3.2.tar.xz)