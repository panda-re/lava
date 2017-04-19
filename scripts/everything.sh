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
# -q, -m, -t and -i: use these to turn on each of the three steps
# -z [knobSize]: use this to make inject step use knob trigger bugs
#                and knobSize changes how origFile is mutated
# -b [bugType] : use this to specify attact point type: [mem_write|mem_read|fn_arg]
#
# everything -a -d -r -q -m -t -i [numSims] -b [bug_type] -z [knobSize] JSONfile"
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

trap '' PIPE

set -e # Exit on error

USAGE() {
  echo "USAGE: $0 -a -d -r -q -m -t -i [numSims] -b [bug_type] -z [knobSize] JSONfile"
  echo "       . . . or just $0 -ak JSONfile"
  exit 1
}

if [ $# -lt 2 ]; then
    USAGE
fi



progress() {
  echo
  if [ $1 -eq 1 ]; then
      date
  fi
  echo -e "\e[32m[everything]\e[0m \e[1m$2\e[0m"
}


# start timer
function tick() {
    ns=$(date +%s%N)
    START=$(echo "scale=2; $ns/1000000000" | bc)
}

function tock() {
    ns=$(date +%s%N)
    END=$(echo "scale=2; $ns/1000000000" | bc)
    time_diff=$(echo "scale=2; $END-$START" | bc)
}

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
ATP_TYPE=""
# -s means skip everything up to injection
# -i 15 means inject 15 bugs (default is 1)
echo
progress 0 "Parsing args"
while getopts  "arcqmtb:i:z:kd" flag
do
  if [ "$flag" = "a" ]; then
      reset=1
      add_queries=1
      make=1
      taint=1
      inject=1
      num_trials=4
      progress 0 "All steps will be executed"
  fi
  if [ "$flag" = "r" ]; then
      reset=1
      progress 0 "Reset step will be executed"
  fi
  if [ "$flag" = "c" ]; then
      # note, this step, or option is not executed with -a flag
      reset_db=1
      progress 0 "Reset (clean) just databse step will be executed"
  fi
  if [ "$flag" = "q" ]; then
      add_queries=1
      progress 0 "Add queries step will be executed"
  fi
  if [ "$flag" = "m" ]; then
      make=1
      progress 0 "Make step will be executed"
  fi
  if [ "$flag" = "t" ]; then
      taint=1
      progress 0 "Taint step will be executed"
  fi
  if [ "$flag" = "i" ]; then
      inject=1
      num_trials=$OPTARG
      progress 0 "Inject step will be executed: num_trials = $num_trials"
  fi
  if [ "$flag" = "z" ]; then
      knob=$OPTARG
      kt="--knobTrigger $knob"
      progress 0 "Inject step will be executed with knob trigger: knob = $knob"
  fi
  if [ "$flag" = "b" ]; then
      # -b [bugType] : use this to specify attact point type: [mem_write|mem_read|fn_arg]
      ATP_TYPE="$OPTARG"
      if [ "$ATP_TYPE" != "mem_read" -a "$ATP_TYPE" != "fn_arg" -a "$ATP_TYPE" != "mem_write" ]; then
          echo "ATP Type ($ATP_TYPE) is not valid must specify:"
          echo "    -b [mem_write|mem_read|fn_arg]"
          echo "Exiting . . ."
          exit 1
      fi
      progress 0 "Query step will be executed with bug type: atp = $ATP_TYPE"
  fi
  if [ "$flag" = "k" ]; then
      ok=1
      progress 0 "-k: Okaying through deletes"
  fi
  if [ "$flag" = "d" ]; then
      demo=1
      progress 0 "-d: demo mode"
  fi
done
shift $((OPTIND -1))

# if $1 is the empty string then json file was not declared and we exit
if [ -z "$1" ]; then
    USAGE
fi
json="$(realpath $1)"

# how many bugs will be injected at  time
many=100

if [[ $demo -eq 1 ]]
then
    gnome-terminal --geometry=90x40  -x bash -c "python $(dirname $0)/demo.py $json; read" &
fi

deldir () {
    deldir=$1
    progress 0 "Deleting $deldir.    Type ok to go ahead."
    if [[ $ok -eq 0 ]]
    then
        # they have to actually type 'ok'
        read ans
    else
        ans=ok
    fi
    if [[ "$ans" = "ok" ]]
    then
        echo "...deleting"
        rm -rf $deldir || true
    else
        echo "exiting"
        exit
    fi
}

run_remote() {
    remote_machine=$1
    command=$2
    logfile=$3
    if [ -z "$logfile" ]; then
        logfile=/dev/stdout
    fi
    set +e
    docker_map_args="-v $lava:$lava -v $tarfiledir:$tarfiledir"

    if [ "$extradockerargs" = "null" ]; then
        extradockerargs="";
    fi

    if [[ "$directory" = "$tarfiledir"* ]]; then true; else
        docker_map_args="$docker_map_args -v $directory:$directory"
    fi
    if [ "$remote_machine" == "localhost" ]; then
        echo "$command"
        bash -c "$command" >> "$logfile" 2>&1
    elif [ "$remote_machine" == "docker" ]; then
        echo docker run $dockername sh -c "$command"
        docker run --rm -it \
            -e "HTTP_PROXY=$HTTP_PROXY" \
            -e "HTTPS_PROXY=$HTTPS_PROXY" \
            -e "http_proxy=$http_proxy" \
            -e "https_proxy=$https_proxy" \
            -v /var/run/postgresql:/var/run/postgresql \
            -v "$HOME/.pgpass:$HOME/.pgpass" \
            -v /etc/passwd:/etc/passwd:ro \
            -v /etc/group:/etc/group:ro \
            -v /etc/shadow:/etc/shadow:ro \
            -v /etc/gshadow:/etc/gshadow:ro \
            --security-opt seccomp=unconfined \
            $docker_map_args \
            $extradockerargs \
            $dockername sh -c "trap '' PIPE; su -l $(whoami) -c \"$command\"" \
            >> "$logfile" 2>&1
    else
        echo "ssh $remote_machine $command"
        ssh $remote_machine $command 2>&1 >> "$logfile"
    fi
    ret_code=$?
    if [ $ret_code != 0 ]; then
        echo "command failed! exit code was $ret_code"
        echo "========== end of logfile $lf: ========== "
        echo
        tail -n 30 "$lf"
        exit $ret_code
    fi
    set -e
}

truncate() {
    echo -n > "$1"
}

progress 1 "JSON file is $json"
dockername="lava32"

lava=$(dirname $(dirname $(readlink -f "$0")))
db="$(jq -r .db $json)"
extradockerargs="$(jq -r .extra_docker_args $json)"
exitCode="$(jq -r .expected_exit_code $json)"
tarfile="$(jq -r .tarfile $json)"
tarfiledir="$(dirname $tarfile)"
directory="$(jq -r .directory $json)"
name="$(jq -r .name $json)"
inputs=`jq -r '.inputs' $json  | jq 'join (" ")' | sed 's/\"//g' `
buildhost="$(jq -r '.buildhost // "docker"' $json)"
pandahost="$(jq -r '.pandahost // "localhost"' $json)"
testinghost="$(jq -r '.testinghost // "docker"' $json)"
fixupscript="$(jq -r .fixupscript $json)"
makecmd="$(jq -r .make $json)"
container="$(jq -r .docker $json)"
install=$(jq -r .install $json)
scripts="$lava/scripts"
python="/usr/bin/python"
source=$(tar tf "$tarfile" | head -n 1 | cut -d / -f 1)
sourcedir="$directory/$name/$source"
bugsdir="$directory/$name/bugs"
logs="$directory/$name/logs"

/bin/mkdir -p "$logs"

if [ $reset -eq 1 ]; then
    tick
    deldir "$sourcedir"
    deldir "$bugsdir"
    deldir "$directory/$name/inputs"
    deldir "$directory/$name/*rr-*"
    # remove all plog files in the directory
    deldir "$directory/$name/*.plog"
    progress 0 "Truncating logs..."
    for i in $(ls "$logs" | grep '.log$'); do
        truncate "$logs/$i"
    done
    lf="$logs/dbwipe.log"
    truncate "$lf"
    progress 1  "Setting up lava db -- logging to $lf"
    run_remote "$pandahost" "dropdb --if-exists -U postgres $db" "$lf"
    run_remote "$pandahost" "createdb -U postgres $db || true" "$lf"
    run_remote "$pandahost" "psql -d $db -f $lava/fbi/lava.sql -U postgres" "$lf"
    run_remote "$pandahost" "echo dbwipe complete" "$lf"
    tock
    echo "reset complete $time_diff seconds"
fi

if [ $reset_db -eq 1 ]; then
    lf="$logs/dbwipe.log"
    truncate "$lf"
    progress 1  "Resetting (cleaning) up lava db -- logging to $lf"
    run_remote "$pandahost" "dropdb --if-exists -U postgres $db" "$lf"
    run_remote "$pandahost" "createdb -U postgres $db || true" "$lf"
    run_remote "$pandahost" "psql -d $db -f $lava/fbi/lava.sql -U postgres" "$lf"
    run_remote "$pandahost" "echo dbwipe complete" "$lf"

fi

if [ $add_queries -eq 1 ]; then
    tick
    progress 1  "Add queries step -- btrace lavatool and fixups"
    lf="$logs/add_queries.log"
    truncate "$lf"
    progress 1 "Adding queries to source -- logging to $lf"
    run_remote "$buildhost" "$scripts/add_queries.sh $ATP_TYPE $json" "$lf"
    if [ "$fixupscript" != "null" ]; then
        lf="$logs/fixups.log"
        truncate "$lf"
        progress 1 "Fixups -- logging to $lf"
        run_remote "$buildhost" "( $fixupscript )" "$lf"
    else
        progress 1 "No fixups"
    fi
    tock
    echo "add queries complete $time_diff seconds"
fi


if [ $make -eq 1 ]; then
    tick
    progress 1 "Make step -- making 32-bit version with queries"
    lf="$logs/make.log"
    truncate "$lf"
    run_remote "$buildhost" "cd $sourcedir && $makecmd" "$lf"
    run_remote "$buildhost" "cd $sourcedir && $install" "$lf"
    tock
    echo "make complete $time_diff seconds"
    echo "make complete $time_diff seconds" >> "$lf"
fi


if [ $taint -eq 1 ]; then
    tick
    progress 1 "Taint step -- running panda and fbi"
    for input in $inputs
    do
        i=`echo $input | sed 's/\//-/g'`
        lf="$logs/bug_mining-$i.log"
        truncate "$lf"
        progress 1 "PANDA taint analysis prospective bug mining -- input $input -- logging to $lf"
        run_remote "$pandahost" "$python $scripts/bug_mining.py $json $input" "$lf"
        echo -n "Num Bugs in db: "
        run_remote "$pandahost" "psql -At $db -U postgres -c 'select count(*) from bug'"
        echo
        run_remote "$pandahost" "psql $db -U postgres -c 'select count(*), type from bug group by type order by type'"
    done
    tock
    echo "bug_mining complete $time_diff seconds"
fi


na=1
if [ $inject -eq 1 ]; then
    progress 1 "Injecting step -- $num_trials trials"
    if [ "$exitCode" = "null" ]; then
        exitCode="0";
    fi
    for i in `seq $num_trials`
    do
        lf="$logs/inject-$i.log"
        truncate "$lf"
        progress 1 "Trial $i -- injecting $many bugs logging to $lf"
        run_remote "$testinghost" "$python $scripts/inject.py -d -m $many -e $exitCode $kt $json" "$lf"
    grep yield "$lf"
    done
fi

progress 1 "Everything finished."

