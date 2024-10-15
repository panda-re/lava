
# How to get a new target working with LAVA

# Prerequsites
* Target can be compiled on Linux
* Target is written in c

# Disclaimer
I assume your project is a `configure` / `make` / `make install` type beast.
If not, you may want to modify it so it can be built with `make`.


#Instructions

1. Make sure to configure and make for a 32-bit target.  You want
any conditionally compiled src specific to 32-bit to be chosen.
Easiest way to ensure this is to `configure` / `make` inside the
lava32 docker container (enter container with `scripts/docker-shell.sh`)

2. Obtain pre-processed versions of all the source required to compile
your target. For now, this step must be done manually. You may simply be able
to rewrite a makefile such that this is automatically done
(see file-5.22-pre/src/Makefile, be sure to set the correct CFLAGS) or you
can take the following approach:

First, I run make (maybe V=1 make for verbose output) and collect the output to a
file. Maybe something like

```
V=1 make >& make.out
```

Second, grep that make.out for gcc and ar lines.  These transform
with sed to turn them into new lines that, instead of compiling object
files, create preprocessed code.  Collect all these lines into a
shell script that creates pre-processed versions of every source file.
So, to be explicit, a line like this collected from the build of file


```
libtool: compile:  gcc -DHAVE_CONFIG_H -I. -I.. -DMAGIC=\"/usr/local/share/misc/magic\" -fvisibility=hidden -Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wmissing-declarations -Wredundant-decls -Wnested-externs -Wsign-compare -Wreturn-type -Wswitch -Wshadow -Wcast-qual -Wwrite-strings -Wextra -Wunused-parameter -Wformat=2 -g -O2 -MT cdf.lo -MD -MP -MF .deps/cdf.Tpo -c cdf.c  -fPIC -DPIC -o .libs/cdf.o
```

would be translated either manually or by sed into the following

```
gcc -DHAVE_CONFIG_H -I. -I.. -DMAGIC=\"/usr/local/share/misc/magic\" -fvisibility=hidden -Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wmissing-declarations -Wredundant-decls -Wnested-externs -Wsign-compare -Wreturn-type -Wswitch -Wshadow -Wcast-qual -Wwrite-strings -Wextra -Wunused-parameter -Wformat=2 -E cdf.c  -o cdf-pre.c
```

Notes: 

2.1. Discarded all the -MT -MD -mP -MF garbage

2.2. New output file is of the form -pre.c 

2.3. Get rid of -c and replace with -E

2.4. -O2 and -g meaningless since we are just using this to create preprocessed source

Usually, I try to create a script that can recreate all the
preprocessed source files.  This script starts off as the transformed
versions of those lines from make.out, and common flags are placed in
variables etc.  

2.5 Now you need to initialize all variables in your target. Otherwise we may identify
an unitialized variable as being attacker controlled when that only happens probabilisitcally.
Fortunately, we've created a tool to help with this process- `lavaInitTool`.

2.5.1 Start a shell in the docker container, and cd into your project

2.5.2 run `path-to-lava/tools/btrace/sw-btrace make` to build btrace.log

2.5.3 run `path-to-lava/tools/btrace/sw-btrace-to-compiledb .` to build `compile_commands.json`

2.5.4 run `path-to-lava/tools/install/bin/lavaInitTool src/*-pre.c` where the arguments are all
the preprocessed c files.

2.5.5 In each directory with your source code, run
`/usr/lib/llvm-11/bin/clang-apply-replacements .`

2.5.6 If you search through your code for `={0};` you should see variables that were previously
unitialized now being initialized to null.

3. Once I have all the -pre.c files needed to create the executable we
want, I write a super simple makefile that will compile all the -pre.c
files into -pre.o objects and link them.  Often, if the project
creates libraries I'll ignore that and just statically link all of the
.o files into the executable.  Simple is king.  See
file-5.22-pre.tar.gz in target_bins for an example.

Notes:

3.0. Try 'compiling away' gnu attributes and extensions.  By adding
something like this to the top of every .c file input to your
preprocessing script.

```
#define __attribute__(x)
#define __extension__(x)
```

Note that this may or may not work.  Many gcc attributes and
extensions are optional, even the ones that tell the compiler which of
the args is the format string in a printf-like fn.  Sadly, others are
not optional, such as the extension `__transparent_union__`.  I've seen
this used in the wait() libc call and I'm mad about it.  But you may
get lucky!  If you can compile away attributes and extensions your
life will just plain be easier.

3.1. There should be NO `#anything` in any of the -pre.c files.  Not
even `#line` or `#file` or anything.  Grep for `^#` and make sure!

3.2. Your simple makefile __must__ compile with `-g -gdwarf-2`.  Otherwise PRI
won't work under PANDA and you'll never get any DUAs or attack points.

3.3. Your makefile should also compile with `-O0`.  This is very imporant
since otherwise code might get inlined which causes a mismatch wrt
when PANDA and PRI try to figure out what local variables are in
scope.  Trust me.  This is very hard to figure out later.  Just use
`-O0`.

3.4. Your makefile has to have at least `make`, `make clean`, and `make
install`.  `make install` should create a `lava-install/` directory and beneath
that a `bin` directory at least which is where the compiled program gets
installed.

4. The result of all of 1-3 should be a tarball like the ones in 
[target_bins](target_bins/)

5. Now create a config json file for the target.  Crib from
`target_config/file/file.json`.  If your target is called _foo_, put it in
`target_config/foo/foo.json`.

5. At this point you should have something that will get you through
everything except `inject.py`.  That is, if you were doing this for
file, you would now be able to run the following

```./scripts/lava.sh -ak file```

which will use lavaTool to add pri queries, then run PANDA's taint
analysis to collect a pandalog, then read that pandalog containing the
results of taint queries, and use it to populate the SQL db with
potential bug info.  If all of this works, you will see something like
the following near the end of your output.  

```
psql file_tleek -U postgres -c 'select count(*), type from bug group by type order by type'
  count  | type
---------+------
 2390944 |    0
 1012998 |    1
  111673 |    2
(3 rows)
```

This indicates that `bug_mining.py` actually found a number of potential
bugs for injection!

If you got NO bugs at this point, this is probably because of a problem
with PRI in PANDA.  Make sure your target is compiled with `-g -gdwarf-2` (so that
dwarf info and symbols are in there).  Take a look at the bug_mining output log and make sure the main executable
and any libraries you have compiled are actually being intercepted by
PRI to load symbols.  When that works, it looks like the following:

```
monitoring asid 5ba9000
[ensure_main_exec_initialized] Trying to load symbols for /home/tleek/git/lava-mdb-last/target_injections/file/file-5.22/lava-install/bin/file at 0x8048000.
[ensure_main_exec_initialized] access(/home/tleek/git/lava-mdb-last/target_injections/file/file-5.22/lava-install/bin/file, F_OK): 0
elf_get_baseaddr /home/tleek/git/lava-mdb-last/target_injections/file/file-5.22/lava-install/bin/file file
read_debug_info /home/tleek/git/lava-mdb-last/target_injections/file/file-5.22/lava-install/bin/file
line_range_list.size() = 10313
Processed 27 Compilation Units
Successfully loaded debug symbols for file
Number of address range to line mappings: 10313 num globals: 262
[ensure_main_exec_initialized] SUCCESS
```

If you see something like `line_range_list.size() = 0` for the thing you
really want PRI to have worked for, you have a problem.

6. The next step is to get injection to work.  That means running, e.g.

```
./scripts/lava.sh -i 1 file
```

This possibly won't work.  Sadly, even though everything through
bug_mining (panda pri taint analysis and postprocess with
find_bug_inj.cpp) works reliably, you may still have problems with
injection.  This is because injection is where we add code to implement the
bug.  That is a tricky modification of the source, especially if you
enable data_flow which tries to add an extra argument to every user
defined function. That often fails because of function pointers.

You have three options at this point.  

### OPTION 1
You can try to fiddle with the Clang src-to-src transform to get
things to work.  That's hard.  Generally, I only do this when I've
identified a problem that I see in many targets and its worth modifying
clang to fix for a lot of targets.  

### OPTION 2
You can sometimes make a problem go away by hacking the
pre-processed source.  For example, I fixed the annoying __transparent_union__ extension
mentioned above by figuring out how it works and hand editing the src to no longer use it.
See file-5.22-pre.tar.gz.  Note that if you do this you need to re-make the tar file
and stick it in target_bins.

### OPTION 3
You can start writing sed rules to fix up the source so that it
works and can compile. For instance, function defs with no params can
be written as follows 

```void foo(void)```

and our data_flow stuff gets confused and perpetrates the following

```void foo(int *data_flowvoid)```

which is horrifying.  But easy to fix with a sed rule.  See
`target_configs/file/file_fixups.sh`. This shell script is run over the
src *after* inject.py to correct these kinds of bloomers.  It's 
often easier than changing lavaTool.

After you get through injection, everything should work! In the
`target_injections/your_target/bugs/0/your_target/` directory, a git repo
will be initialized containing a branch for each set of bugs you injected.

If you have any issues, feel free to open a pull request asking for help.
