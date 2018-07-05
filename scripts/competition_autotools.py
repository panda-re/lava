######
#### If we can assume autotools for building, we just set prefix and everything is cleaner.
#### competition.py is not making this assumption and instead just copying out the lava-install dir
#####

build_sh = join(corpdir, "build.sh")
with open(build_sh, "w") as build:
    build.write("""#!/bin/bash
    pushd `pwd`
    cd {bugs_build}
    make distclean
    make clean
    {configure} --prefix="{outdir}"
    {make}
    rm -rf "{outdir}"
    {install}
    popd
    """.format(configure=project['configure'],
        bugs_install=lp.bugs_install,
        bugs_build=bd,
        make=project['make'],
        install=project['install'],
        outdir=join(corpdir, "lava-install")))

log_build_sh = join(corpdir, "log_build.sh")
with open(log_build_sh, "w") as build:
    build.write("""#!/bin/bash
    pushd `pwd`
    cd {bugs_build}

    # Build internal version
    make distclean
    {configure} --prefix="{internal_builddir}"
    {make} CFLAGS+="-DLAVA_LOGGING"
    rm -rf "{internal_builddir}"
    {install}

    # Build public version
    make distclean
    {configure} --prefix="{public_builddir}"
    {make}
    rm -rf "{public_builddir}"
    {install}

    popd
    """.format(configure=project['configure'],
        bugs_install = lp.bugs_install,
        bugs_build=bd,
        make = project['make'],
        install = project['install'],
        internal_builddir = join(corpdir, "lava-install-internal"),
        public_builddir = join(corpdir, "lava-install")
        ))

trigger_all_crashes = join(corpdir, "trigger_crashes.sh")
with open(trigger_all_crashes, "w") as build:
    build.write("""#!/bin/bash
    pushd `pwd`
    cd {corpdir}

    for fname in {inputdir}/*-fuzzed-*; do
        LD_LIBRARY_PATH={librarydir} {command}
    done

    popd
    """.format(command = project['command'].format(**{"install_dir": join(corpdir, "lava-install-internal"), "input_file": "$fname"}), # This syntax is weird but only thing that works?
        corpdir = corpdir,
        librarydir = join(corpdir, "lava-install-internal", "lib"),
        inputdir = join(corpdir, "inputs")
        ))
