#!/bin/bash

# This script runs an injected executable on a series of inputs comparing
# the location of the crash (using the backtrace output) to the expected
# location of the crash.  Will exit prematurely if the two are different

# USAGE
# Assume that $1 is the path to inject log which will be parsed to find "validated
# bugs."
# Assume that $2 is the path to json file
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )"

USAGE() {
  echo "USAGE: $0 /path/to/json"
  exit 1
}

if [ -z "$1" ]; then
    USAGE
else
    json="$1"
fi
. `dirname $0`/vars.sh

inject_log="$logs/$(ls -t $logs | grep -E "inject-[0-9]+.log" | head -n 1)"

[ "$exitCode" = "null" ] && exitCode="0";

buglist=$(grep "list of real validated bugs" $inject_log | grep -Eo "\[.*\]")
echo "Verifying these bugs found in: $inject_log"
echo "$buglist"
$DIR/run-on-fuzzed-input.py -l "$buglist" -s -e $exitCode $json
