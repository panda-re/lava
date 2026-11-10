The LAVA target is `pngtest`. Keep `bin_PROGRAMS=` and
`check_PROGRAMS=pngtest` on both the build and install commands: Automake's
install target can build programs too.

During injection, `main_file: ["pngtest.c"]` makes that translation unit own
the shared `lava_val`, `lava_extra`, and `lava_state` arrays. Instrumented
libpng code references those arrays through extern declarations. Other
libpng executables (such as `pngfix` and `pngvalid`) do not link `pngtest.o`
and therefore fail to link against the injected library. The make overrides
build the library and its intended LAVA driver without those executables.

Install `pngtest` through `./libtool --mode=install`, rather than copying it
with plain `install`. In a shared build, the top-level `pngtest` is a shell
wrapper for `.libs/pngtest`. Copying that wrapper into `lava-install/bin`
leaves it looking for a nonexistent `lava-install/bin/.libs/pngtest`.
Libtool installs the executable with the installed library search path.

Disabling only the auxiliary tools still leaves the other test executables.
Giving each library translation unit private storage would break propagation
of siphoned values between translation units.
