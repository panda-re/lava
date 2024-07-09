#!/bin/bash
#
# A script to run all of lava.
#
# Lava consists of three main steps.
#
# Step Q: Add taint and attack point queries to source.
# Step M: Make the source with the queries
# Step T: Use panda & fbi to populate db with prospective bugs
# Step I: Try injecting bugs.
#
# Here is what everything consists of.
#
# Erases postgres db for this target.
# Uses lavatool to inject queries.
# Compiles resulting program.
# Runs that program under PANDA taint analysis
# Runs fbi on resulting pandalog and populates postgres db with prospective bugs to inject
# Tries injecting a single bug.
#
# Json file required params
#
# lava:        directory of lava repository
# db:          database name
# tarfile:     tar file of source
# directory:   where you want source to build
# name:        a name for this project (used to create directories)
# inputs:      a list of inputs that will be used to find potential bugs (think coverage)
# buildhost:   what remote host to build source on
# pandahost:   what remote host to run panda and postgres on
# testinghost: what host to test injected bugs on
# fixupscript: script to run after add_query to fix up src before make
#

version="2.0.0"
trap '' PIPE
set -e # Exit on error

USAGE() {
  echo "$0 version $version"
  echo "USAGE: $0 [options] [ProjectConfig]"
  echo "ProjectConfig should be a path to a json file or simply the target name if the config exists in target_configs/name/name.json"

  echo 
  echo "== Common Options =="
  echo "   -a | --all     Run all lava steps and inject $many bugs over 3 trials"
  echo "   -k | --force   Delete old data without confirmation"
  echo "   -n [num_bugs] | --count [num_bugs]   Specify number of bugs to be injected at once"
  echo "   -y [bug_types] | --bug-types [bug_types]   Specify a comma seperated list of bug types: " # TODO never used?
  echo "   -b [atp_type] | --atp-type [atp_type]   Specify a single ATP type. One of mem_read, fn_arg, or mem_write"

  echo
  echo "== Specify Steps to Run =="
  echo "   -r | --reset         Run reset step"
  echo "   -c | --clean         Run clean step"
  echo "   -q | --add-queries   Run add queries step"
  echo "   -m | --make          Run make step"
  echo "   -t | --taint         Run taint step"
  echo "   -i [num_trials] | --inject [num_trials]         Run inject step with specified number of trials"

  echo
  echo "== Expert only options =="
  echo "  --demo                        Run lava demo"
  echo "  --test-data-flow              Only inject data-flow argument, no bugs"
  echo "  --curtail [count]             Curtail bug-finding after count bugs"
  echo "  --enable-knob-trigger [knob]  Enable knob trigger with specified knob" # TODO: what does that mean? Maybe disable this entirely
  echo
  exit 1
}

if [ $# -eq 0 ]; then
    USAGE
fi

# Load lava-functions
. `dirname $0`/funcs.sh
lava=$(dirname $(dirname $(readlink -f "$0")))

# defaults
ok=0
reset=0
reset_db=0
add_queries=0
make=0
taint=0
inject=0
num_trials=0
kt=""
demo=0
curtail=0
ATP_TYPE=""
# default bugtypes
bugtypes="ptr_add,rel_write,malloc_off_by_one"
# default # of bugs to be injected at a time
many=50

source `dirname $0`/arg_parse.sh
parse_args $@

# Parse args initialzes all our variables and project_name
if [ -z "$project_name" ]; then
    USAGE
fi
. `dirname $0`/vars.sh

if [[ $demo -eq 1 ]]
then
    gnome-terminal --geometry=90x40  -x bash -c "python $(dirname $0)/demo.py $json; read" &
fi

progress "everything" 1 "JSON file is $json"

if [ ! -f "$tarfile" ]; then
    echo -e "\nFATAL ERROR: Specified tarfile ($tarfile) does not exit\n";
    exit 1;
fi

source=$(tar tf "$tarfile" | head -n 1 | cut -d / -f 1 2>/dev/null)

if [ -z "$source" ]; then
    echo -e "\nFATAL ERROR: could not get directory name from tarfile. Tar must unarchive and create directory\n";
    exit 1;
fi

sourcedir="$directory/$name/$source"
bugsdir="$directory/$name/bugs"
logs="$directory/$name/logs"

/bin/mkdir -p "$logs"

RESET_DB() {
    lf="$logs/dbwipe.log"
    truncate "$lf"
    progress "everything" 1  "Resetting lava db -- logging to $lf"
    run_remote "$buildhost" "dropdb -U postgres -h database $db || true" "$lf"
    run_remote "$buildhost" "createdb -U postgres -h database $db || true" "$lf"
    run_remote "$buildhost" "psql -d $db -h database -f $lava/tools/lavaODB/generated/lava.sql -U postgres" "$lf"
    run_remote "$buildhost" "echo dbwipe complete" "$lf"
}

if [ $reset -eq 1 ]; then
    tick
    deldir "$sourcedir"
    deldir "$bugsdir"
    deldir "$directory/$name/inputs"
    deldir "$directory/$name/"'*rr-*'
    # remove all plog files in the directory
    deldir "$directory/$name/*.plog"
    progress "everything" 0 "Truncating logs..."
    for i in $(ls "$logs" | grep '.log$'); do
        truncate "$logs/$i"
    done
    RESET_DB
    tock
    echo "reset complete $time_diff seconds"
fi




if [ $add_queries -eq 1 ]; then
    tick
    progress "everything" 1  "Add queries step -- btrace lavatool and fixups"
    lf="$logs/add_queries.log"
    truncate "$lf"
    progress "everything" 1 "Adding queries to source -- logging to $lf"
    run_remote "$buildhost" "$scripts/add_queries.sh $ATP_TYPE $project_name" "$lf"
    if [ "$fixupscript" != "null" ]; then
        lf="$logs/fixups.log"
        truncate "$lf"
        progress "everything" 1 "Fixups -- logging to $lf"
        run_remote "$buildhost" "( $fixupscript )" "$lf"
    else
        progress "everything" 1 "No fixups"
    fi
    tock
    echo "add queries complete $time_diff seconds"
fi


if [ $make -eq 1 ]; then
    tick
    progress "everything" 1 "Make step -- making 32-bit version with queries"
    lf="$logs/make.log"
    truncate "$lf"
    run_remote "$buildhost" "cd $sourcedir && CC=/usr/lib/llvm-11/bin/clang CXX=/usr/lib/llvm-11/bin/clang++ CFLAGS='-O0 -m32 -DHAVE_CONFIG_H -g -gdwarf-2 -fno-stack-protector -D_FORTIFY_SOURCE=0 -I. -I.. -I../include -I./src/' $makecmd" "$lf"
    
    run_remote "$buildhost" "cd $sourcedir && rm -rf lava-install" "$lf"
    if [ "$install_simple" == "null" ]; then
        run_remote "$buildhost" "cd $sourcedir && $install" "$lf"
    else 
        run_remote "$buildhost" "cd $sourcedir && $install_simple" "$lf"
    fi
    if [ "$post_install" != "null" ]; then
        run_remote "$buildhost" "cd $sourcedir && $post_install" "$lf"
    fi
    tock
    echo "make complete $time_diff seconds"
    echo "make complete $time_diff seconds" >> "$lf"
fi

if [ $reset_db -eq 1 ]; then
    RESET_DB
fi


if [ $taint -eq 1 ]; then
    tick

    if [ $reset_db -eq 0 ]; then
        # If we didn't just reset the DB, we need clear out any existing taint labels before running FBI
        progress "everything" 1 "Clearing taint data from DB"
        lf="$logs/dbwipe_taint.log"
        run_remote "$buildhost" "psql -U postgres -h database -c \"delete from dua_viable_bytes; delete from labelset;\" $db" "$lf"
    fi
    progress "everything" 1 "Taint step -- running panda and fbi"
    for input in $inputs
    do
        i=`echo $input | sed 's/\//-/g'`
        lf="$logs/bug_mining-$i.log"
        truncate "$lf"
        progress "everything" 1 "PANDA taint analysis prospective bug mining -- input $input -- logging to $lf"
        run_remote "$buildhost" "$python $scripts/bug_mining.py $hostjson $project_name $input $curtail" "$lf"
        echo -n "Num Bugs in db: "
        bug_count=$(run_remote "$buildhost" "psql -At $db -U postgres -h database -c 'select count(*) from bug'")
        if [ "$bug_count" = "0" ]; then
            echo "FATAL ERROR: no bugs found"
            exit 1
        fi
        echo "Found $bug_count bugs"
        echo
        run_remote "$buildhost" "psql $db -U postgres -h database -c 'select count(*), type from bug group by type order by type'"
    done
    tock
    echo "bug_mining complete $time_diff seconds"
fi

if [ $inject -eq 1 ]; then
    progress "everything" 1 "Injecting step -- $num_trials trials"
    if [ "$exitCode" = "null" ]; then
        exitCode="0";
    fi
    for i in `seq $num_trials`
    do
        lf="$logs/inject-$i.log"
        truncate "$lf"
        progress "everything" 1 "Trial $i -- injecting $many bugs logging to $lf"
        fix=""
        if [ "$injfixupsscript" != "null" ]; then
            fix="--fixupsscript='$injfixupsscript'"
        fi
        run_remote "$testinghost" "$python $scripts/inject.py -t $bugtypes -m $many -e $exitCode $kt $fix $hostjson $project_name" "$lf"
    grep yield "$lf"  | grep " real bugs "
    done
fi

progress "everything" 1 "Everything finished."

