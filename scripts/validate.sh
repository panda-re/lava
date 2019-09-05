#!/bin/bash
# Target validation script - Ensure your program builds and exits cleanly on all provided inputs
#
# Takes one required argument: the project name
# That json file must contain all of the following
#
# name         name for project, usually the name of the software (binutils-2.25, openssh-2.1, etc)
# directory    directory in which src-2-src query injection will occur -- should be somewhere on the nas
# tarfile      path to software tar file
# configure    how to configure the software (./configure plus arguments) (will just use /bin/true if not present)
# make         how to make the software (make might have args or might have FOO=bar required precursors)
# install      how to install the software (note that configure will be run with --prefix ...lava-install)
#
# script proceeds to untar the software, make it and run it on each input

# Load lava-functions and vars
. `dirname $0`/funcs.sh

USAGE() {
    echo "Usage: $1 ProjectName"
}

set -e # Exit on error
#set -x # Debug mode

if [ $# -ne 1 ]; then
  USAGE $0
  exit 1
else
  project_name=$1
fi

lava="$(dirname $(dirname $(readlink -f $0)))"
. `dirname $0`/vars.sh

progress "validate" 0  "Entering $directory/$name."
mkdir -p "$directory/$name"
cd "$directory/$name"

progress "validate" 0  "Untarring $tarfile..."
source=$(tar tf "$tarfile" | head -n 1 | cut -d / -f 1)

source_v="${source}_validate"

cachefile_tar=".cache_tar_$(sha1sum $tarfile| awk '{ print $1 }')"
cachefile_config=".cache_config_$(sha1sum $json| awk '{ print $1 }')"

if [ -d "$source_v" ]; then
    # If validate dir exists already, check if we can cache old result
    # Check hashes of tarball, config, and inputs
    valid_cache=1

    if [ ! -e "$source_v/$cachefile_tar" ]; then
        echo "Cache miss tar"
        valid_cache=0
    fi
    if [ ! -e "$source_v/$cachefile_config" ]; then
        echo "Cache miss config"
        valid_cache=0
    fi
    for input_file in $inputs_arr; do
        full_input="$config_dir/$input_file"
        input_cache=$(echo ".cache_input_$(sha1sum $full_input| awk '{ print $1 }')")
        if [ ! -e "$source_v/$input_cache" ]; then
            echo "Cache miss input: $full_input"
            valid_cache=0;
        fi
    done

    if [ $valid_cache -eq 1 ]; then
        progress "validate" 0 "Target already validated"
        exit 0
    else
        echo "Removing outdated validate directory"
        rm -rf "$source_v" 
    fi
fi

if [ -e "$source" ]; then
  progress "validate" 0  "Deleting old $directory/$name/$source..."
  rm -rf "$directory/$name/$source"
fi
tar xf "$tarfile"


mv $source $source_v
progress "validate" 0  "Entering $source_v."
cd "$source_v"

# Store info for cache
touch "$cachefile_tar"
touch "$cachefile_config"

# CONFIGURE
progress "validate" 0  "Configuring..."
mkdir -p lava-install
$configure_cmd --prefix=$(pwd)/lava-install
exit_c=$?
if [ $exit_c -eq 0 ]; then
    progress "validate" 0 "Configure OK"
else
    progress "validate" 0 "Bad exit code for configure: $exit_c"
    exit 1
fi

# MAKE
# Note we no longer support multiple make commands
progress "Validate" 0  "Making"
bash -c "$makecmd"
exit_c=$?
if [ $exit_c -eq 0 ]; then
    progress "validate" 0 "Make OK"
else
    progress "validate" 0 "Bad exit code for make command: '${ARGS[@]}': returned $exit_c"
    exit 1
fi


# INSTALL
progress "validate" 0  "Installing..."
install=${install/\$config_dir/$config_dir}
echo "Install with '$install'"
bash -c "$install"
exit_c=$?
if [ $exit_c -eq 0 ]; then
    progress "validate" 0 "Install OK"
else
    progress "validate" 0 "Bad exit code for install: $exit_c"
    exit 1
fi

install_dir="$(pwd)/lava-install"

# Substitute install_dir, then pull out up to the first space for the binary path
binpath=${runcmd/\$install_dir/$install_dir}
binpath=$(echo $binpath | awk '{print $1}')
file_results=$(file $binpath)

# Analyze the produced binary and ensure the following properties:
# * It's 32 bits
if [[ $file_results != *"ELF 32-bit LSB"* ]]; then
    echo $file_results
    echo "Error: Target binary ($binpath) is not 32 bit"
    exit 1
fi
# * It has debugging symbols
if [[ $file_results != *"not stripped"* ]]; then
    echo $file_results
    echo "Error: Target binary ($binpath) missing debug symbols"
    exit 1
fi
# * Debugging symbols are dwarf version 2 (CFLAGS had -gdwarf-2) for PRI
gdwarf_versions=$(readelf --debug-dump=info $binpath | grep -A 2 'Compilation Unit @' | grep Version | awk '{ print $2 }' | sort -u)
if [[ "$gdwarf_versions" != "2" ]]; then
    echo "Error: Target binary ($binpath) compiled with unsupported gdwarf version. Expected 2, got $gdwarf_versions"
    exit 1
fi

progress "validate" 0  "Target binary looks okay"


for input_file in $inputs_arr; do
    progress "everything" 1 "Validating input '$input_file'"
    # Substitute variable strings with real values
    full_input="$config_dir/$input_file"
    this_runcmd=${runcmd/\$install_dir/$install_dir}
    this_runcmd=${this_runcmd/\$input_file/$full_input}

    if [ ! -e $full_input ]; then
        echo "Missing input $full_input"
        exit 1
    fi

    /bin/sh -c "$this_runcmd" > /dev/null # Run the command
    exit_c=$?
    if [ $exit_c -eq 0 ]; then
        echo "OK"
    else
        echo "Bad exit code for input $input_file:\n\tCommand $raw_cmd\n\tReturned $exit_c"
        exit 1
    fi

    input_cache=$(echo ".cache_input_$(sha1sum $full_input| awk '{ print $1 }')")
    touch "$input_cache"
done
