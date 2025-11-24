#!/bin/bash
#
# A script to build a competition
# Json file required params
#
# lava:        directory of lava repository

trap '' PIPE
set -e # Exit on error

# Load lava-functions
. `dirname $0`/funcs.sh
lava=$(dirname $(dirname $(readlink -f "$0")))

version="1.0.0"

USAGE() {
  echo "$0 version $version"
  echo "USAGE: $0 -a -k -m [Num bugs] -n [Minimum real bugs] -l [List of bug IDs to use] -e [Expected exit code of original program] ProjectName"
  echo "       . . . or just $0 ProjectName"
  exit 1
}

if [ $# -lt 1 ]; then
    USAGE
fi


# defaults
ok=0
reset=0
num_bugs=0
exit_code=0
min_yield=1
debug=0
diversify=""
skipinject=""
usechaff=""
dataflow=""
bugtypes="ptr_add,rel_write"
echo
progress "competition" 0 "Parsing args"
while getopts  "sbdiackm:l:n:e:t:" flag
do
  if [ "$flag" = "a" ]; then
      reset=1
      num_bugs=4
      progress "competition" 0 "All steps will be executed"
  fi
  if [ "$flag" = "m" ]; then
      num_bugs=$OPTARG
      progress "competition" 0 "num_bugs = $num_bugs"
  fi
  if [ "$flag" = "n" ]; then
      min_yield=$OPTARG
      progress "competition" 0 "min_yield = $min_yield"
  fi
  if [ "$flag" = "l" ]; then
      bug_list="-l $OPTARG"
      progress "competition" 0 "Use bugs with ID: $bug_list"
  fi
  if [ "$flag" = "t" ]; then
      bugtypes=$OPTARG
      progress "competition" 0 "Injecting bugs of type(s): $bugtypes"
  fi
  if [ "$flag" = "e" ]; then
      exit_code=$OPTARG
      progress "competition" 0 "Expect exit: $exit_code"
  fi
  if [ "$flag" = "k" ]; then
      ok=1
      progress "competition" 0 "-k: Okaying through deletes"
  fi
  if [ "$flag" = "b" ]; then
      debug=1
      progress "competition" 0 "-b: running with pdb"
  fi
  if [ "$flag" = "i" ]; then
      diversify="-i"
      progress "competition" 0 "-i: diversifying"
  fi
  if [ "$flag" = "s" ]; then
      skipinject="-s"
      progress "competition" 0 "-s: skipping injection"
  fi
  if [ "$flag" = "c" ]; then
      usechaff="-c"
      progress "competition" 0 "-c: leaving unvalidated bugs"
  fi
done
shift $((OPTIND -1))

project_name="$1"
. `dirname $0`/vars.sh
progress "competition" 1 "Found configuration for project '$project_name'"

if [ "$debug" -eq "1" ]; then
    python=$pdb
fi

mkdir -p $logs
lf="$logs/competition.log"
progress "competition" 1 "Starting -- logging to $lf"
truncate "$lf"
run_remote "$buildhost" "$python $scripts/competition.py -m $num_bugs -n $min_yield $bug_list -e $exit_code $diversify $skipinject --bugtypes=$bugtypes $usechaff $hostjson $project_name" "$lf"
progress "competition" 1 "Everything finished."

tail -n3 $lf
