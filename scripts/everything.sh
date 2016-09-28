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
# pandahost:   what remote host to run panda on
# dbhost:      host with postgres on it
# testinghost: what host to test injected bugs on
# fixupscript: script to run after add_query to fix up src before make
#


#set -e # Exit on error

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
while getopts  "arqmtb:i:z:kd" flag
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
    gnome-terminal --geometry=90x40  -x python ./lava_mon.py $1 &
fi

deldir () {
  deldir=$1
  progress 0 "Deleteing $deldir.  Type ok to go ahead."
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
      rm -rf $deldir
  else
      echo "exiting"
      exit
  fi
}

run_remote() {
  remote_machine=$1
  command=$2
  echo "ssh $remote_machine $command"
  ssh $remote_machine $command
  ret_code=$?
  if [ $ret_code != 0 ]; then
    echo "exit code was $ret_code"
    exit $ret_code
  fi
  #return $ret_code
}



progress 1 "JSON file is $json"

lava="$(jq -r .lava $json)"
db="$(jq -r .db $json)"
tarfile="$(jq -r .tarfile $json)"
directory="$(jq -r .directory $json)"
name="$(jq -r .name $json)"
inputs=`jq -r '.inputs' $json  | jq 'join (" ")' | sed 's/\"//g' `
buildhost="$(jq -r .buildhost $json)"
pandahost="$(jq -r .pandahost $json)"
dbhost="$(jq -r .dbhost $json)"
testinghost="$(jq -r .testinghost $json)"
fixupscript="$(jq -r .fixupscript $json)"
makecmd="$(jq -r .make $json)"

scripts="$lava/scripts"
python="/usr/bin/python"
source=$(tar tf "$tarfile" | head -n 1 | cut -d / -f 1)
sourcedir="$directory/$name/$source"
bugsdir="$directory/$name/bugs"
logs="$directory/$name/logs"

/bin/mkdir -p $logs


if [ $reset -eq 1 ]; then
    tick
    dbexists=$(psql -tAc "SELECT 1 from pg_database where datname='$db'" -U postgres -h "$dbhost")
    echo "dbexists $dbexists"
    if [ -z $dbexists ]; then
        progress 0 "No db -- creating $db for first time"
    else
        progress 0 "database $db already exists. removing"
        run_remote "$dbhost" "dropdb -U postgres $db"
    fi
    run_remote "$dbhost" "createdb -U postgres $db"
    deldir "$sourcedir"
    deldir "$logs"
    deldir "$bugsdir"
    deldir "$directory/$name/inputs"
    /bin/mkdir -p $logs
    lf="$logs/dbwipe.log"  
    progress 1  "Setting up lava dab -- logging to $lf"
    run_remote "$dbhost" "/usr/bin/psql -d $db -f $lava/include/lava.sql -U postgres >& $lf"
    run_remote "$dbhost" "echo dbwipe complete >> $lf"
    /bin/mkdir -p $logs
    tock
    echo "reset complete $time_diff seconds"
fi


if [ $add_queries -eq 1 ]; then
    tick
    progress 1  "Add queries step -- btrace lavatool and fixups"
    lf="$logs/add_queries.log"
    progress 1 "Adding queries to source -- logging to $lf"
    run_remote "$buildhost" "$scripts/add_queries.sh $ATP_TYPE $json >& $lf"
    if [ "$fixupscript" != "null" ]; then
        lf="$logs/fixups.log"
        progress 1 "Fixups -- logging to $lf"
        run_remote "$buildhost" "$fixupscript"
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
    run_remote "$buildhost" "cd $sourcedir && $makecmd  >& $lf"
    run_remote "$buildhost" "cd $sourcedir && make install   &>> $lf"
    tock
    echo "make complete $time_diff seconds"
    run_remote "$buildhost" "echo make complete $time_diff seconds &>> $lf"

fi

inputs_dir="$directory/$name/inputs"
$( mkdir -p $inputs_dir )
for input in $inputs
do
    $( cp $input $inputs_dir )
done


if [ $taint -eq 1 ]; then
    tick
    progress 1 "Taint step -- running panda and fbi"
    for input in $inputs
    do
        i=`echo $input | sed 's/\//-/g'`
        lf="$logs/bug_mining-$i.log"
        progress 1 "PANDA taint analysis prospective bug mining -- input $input -- logging to $lf"
        run_remote "$pandahost" "$python $scripts/bug_mining.py $json $input >& $lf"
        echo -n "Num Bugs in db: "
        /usr/bin/psql -h "$dbhost" -d $db -U postgres -c 'select count(*) from bug' | head -3 | tail -1
    done
    tock
    echo "bug_mining complete $time_diff seconds"
fi


na=1
if [ $inject -eq 1 ]; then
    progress 1 "Injecting step -- $num_trials trials"
    for i in `seq $num_trials`
    do
        lf="$logs/inject-$i.log"
        progress 1 "Trial $i -- injecting $many bugs logging to $lf"
        run_remote "$testinghost" "$python $scripts/inject.py -m $many $kt $json >& $lf"
    grep yield $lf
    done
fi

progress 1 "Everything finished."

