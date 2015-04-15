Source to Source Transformations
================================

Assuming you have some program source in directory `foo`.

1. Compile `libsw-btrace.so` by going into btrace and running `./compile.sh`
2. Place `sw-btrace` and `sw-btrace-to-compiledb` into `~/btrace/bin` and `libsw-btrace.so` into `~/btrace/libexec`
3. Go into `foo` and configure, then run `~/btrace/bin/sw-btrace make`
4. Run `~/btrace/bin/sw-btrace-to-compiledb ~/git/llvm/Debug+Asserts/lib/clang/3.6.1/include/` to generate `compile_commands.json`
5. Place `pirate_mark.h` in each subdirectory of `foo` that contains source code.
6. Make a backup of the source dir `foo` so that we have a copy of the unmodified source.
7. Do the source-to-source transformation:

        ./get_c_files.py <foo> | while read line; do /path/to/build/lavaTaintQueryTool -p=foo $line; done

8. Go back to the source directory and run `make clean` and finally `make` to build the modified source.

