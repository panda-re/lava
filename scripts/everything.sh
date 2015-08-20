
#
# everything.sh runs all of lava.
#
# It takes a json file as its single parameter
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
# 

progress() {
  echo  
  date
  echo -e "\e[32m[everything]\e[0m \e[1m$1\e[0m"
 
}   


deldir () {
  deldir=$1
  progress "Deleteing $deldir.  Type ok to go ahead."
  read ans
  if [ "$ans" = "ok" ] 
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
}

        
set -e # Exit on error                                                                                                                                                                                          
if [ $# -lt 1 ]; then
  echo "Usage: $0 JSONfile"
  exit 1
fi      

json="$(realpath $1)"

lava="$(jq -r .lava $json)"
db="$(jq -r .db $json)"
tarfile="$(jq -r .tarfile $json)"
directory="$(jq -r .directory $json)"
name="$(jq -r .name $json)"
inputs=`jq -r '.inputs' /nas/tleek/lava/s2s/file.json  | jq 'join (" ")' | sed 's/\"//g' ` 
buildhost="$(jq -r .buildhost $json)"
pandahost="$(jq -r .pandahost $json)"
dbhost="$(jq -r .dbhost $json)"
testinghost="$(jq -r .testinghost $json)"

scripts="$lava/scripts"
python="/usr/bin/python"
source=$(tar tf "$tarfile" | head -n 1 | cut -d / -f 1)
sourcedir="$directory/$source/$source"
bugsdir="$directory/$source/bugs"
logs="$directory/$source/logs"

deldir "$sourcedir"
deldir "$logs"
deldir "$bugsdir"
/bin/mkdir -p $logs

lf="$logs/dbwipe.log"  
progress "Wiping db $db -- logging to $lf"
run_remote "$dbhost" "/usr/bin/psql -d $db -f $lava/sql/lava.sql -U postgres >& $lf"

lf="$logs/add_queries.log" 
progress "Adding queries to source -- logging to $lf"
run_remote "$buildhost" "$scripts/add_queries.sh $json >& $lf" 

lf="$logs/make.log"
progress "Making 32-bit version with queries -- logging to $lf"
run_remote "$buildhost" "cd $sourcedir && make -j `nproc` >& $lf"
run_remote "$buildhost" "cd $sourcedir && make install &>> $lf"

for input in $inputs
do
  i=`echo $input | sed 's/\//-/g'`
  lf="$logs/bug_mining-$i.log"
  progress "PANDA taint analysis prospective bug mining -- input $input -- logging to $lf"
  run_remote "$pandahost" "$python $scripts/bug_mining.py $json $input >& $lf"
done

lf="$logs/inject.log"  
progress "Injecting a single bug -- logging to $lf"
run_remote "$testinghost" "$python $scripts/inject.py $json >& $lf"

