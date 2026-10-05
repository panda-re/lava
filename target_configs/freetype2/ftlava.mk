# Wrapper so one "make" (under compiledb) builds libfreetype AND the ftlava
# driver, and ftlava.c gets its own compile_commands.json entry (it's the LAVA
# main_file). A rule can't be appended to FreeType's own Makefile: its
# config.mk redefines CC/CFLAGS (CFLAGS there contains -c). Here CC, CFLAGS
# and LDFLAGS are LAVA's, from the environment (LDFLAGS has -static for -m).
# Copied into the source tree by freetype2.json's pre_make.
.PHONY: all lib
all: ftlava

# ANSIFLAGS= : FreeType's configure adds -pedantic -std=c99, and strict ISO C
# has no "asm" keyword, which the LAVA hypercall headers (libhc) need.
lib:
	$(MAKE) -f Makefile ANSIFLAGS=

# Separate compile and link, so compile_commands.json gets a plain
# single-source "-c" entry for ftlava.c.
ftlava.o: lib ftlava.c
	$(CC) $(CFLAGS) -I include -c ftlava.c -o ftlava.o

ftlava: ftlava.o
	$(CC) $(CFLAGS) ftlava.o -o ftlava objs/.libs/libfreetype.a -lm $(LDFLAGS)
