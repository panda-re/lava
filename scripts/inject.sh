#!/bin/bash
#
# A script to build a inject
# Json file required params
#
# lava:        directory of lava repository


trap '' PIPE
set -e # Exit on error

# Load lava-functions
. `dirname $0`/funcs.sh
version="2.0.0"

USAGE() {
  echo "$0 version $version"
  echo "USAGE: $0 -a -k -m [Num bugs] -n [Minimum real bugs] -l [List of bug IDs to use] -e [Expected exit code of original program] JSONfile"
  echo "       . . . or just $0 JSONfile"
  exit 1
}

if [ -z "$1" ]; then
    USAGE
fi


# defaults
num_bugs=0
buglist=""
exit_code=0
min_yield=1
diversify=""
skipinject=""
dataflow=""
echo
progress "inject" 0 "Parsing args"
while getopts  "sbdikm:l:n:e:" flag
do
  if [ "$flag" = "l" ]; then
      bug_list="-l $OPTARG"
      progress "inject" 0 "Use bugs with ID: $bug_list"
  fi
  if [ "$flag" = "m" ]; then
      num_bugs=$OPTARG
      progress "inject" 0 "num_bugs = $num_bugs"
  fi
  if [ "$flag" = "d" ]; then
      progress "inject" 0 "-d: using data flow"
      dataflow="-d"
  fi
  if [ "$flag" = "e" ]; then
      exit_code=$OPTARG
      progress "inject" 0 "Expect exit: $exit_code"
  fi
#  if [ "$flag" = "n" ]; then
#      min_yield=$OPTARG
#      progress "inject" 0 "min_yield = $min_yield"
#  fi
#  if [ "$flag" = "i" ]; then
#      diversify="-i"
#      progress "inject" 0 "-i: diversifying"
#  fi
#  if [ "$flag" = "s" ]; then
#      skipinject="-s"
#      progress "inject" 0 "-s: skipping injection"
#  fi
done
shift $((OPTIND -1))

json="$(realpath $1)"
. `dirname $0`/vars.sh
progress "inject" 1 "JSON file is $json"

mkdir -p $logs
lf="$logs/inject.log"
progress "inject" 1 "Starting -- logging to $lf"
truncate "$lf"
run_remote "$buildhost" "$python $scripts/inject.py -m $num_bugs $bug_list -e $exit_code $dataflow $json" "$lf"
grep yield "$lf"

progress "inject" 1 "Finished."
