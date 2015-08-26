
#
# A script to run all of lava.
#
# everything.sh -s -i 15 jsonfile
#  
# -s skips ahead to injection
# -i 15 injects 15 bugs (default is 1)
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
# 

#set -e # Exit on error                                                                                                                                                                                          


if [ $# -lt 1 ]; then
  echo "Usage: $0 JSONfile "
  exit 1
fi      



progress() {
  echo  
  date
  echo -e "\e[32m[everything]\e[0m \e[1m$1\e[0m"
 
}   

# defaults
num_inject=1
skip_to_inject=0
ok=0
skip_deleting=0

# -s means skip everything up to injection
# -i 15 means inject 15 bugs (default is 1)
echo 
progress "Parsing args"
while getopts  "sni:k" flag
do
#  echo "$flag $OPTARG"
  if [ "$flag" = "s" ]; then
    skip_to_inject=1
    progress "-s: Skipping ahead to inject bugs"
  fi  
  if [ "$flag" = "n" ]; then
    skip_deleting=1
    progress "-s: Skipping deleting of directories and dbs"
  fi    
  if [ "$flag" = "i" ]; then
    num_inject=$OPTARG
    progress "-i: num_inject = $num_inject"
  fi
  if [ "$flag" = "k" ]; then
    ok=1 
    progress "-k: Okaying my way through"
  fi
done
shift $((OPTIND -1))

json="$(realpath $1)"


deldir () {
  deldir=$1
  progress "Deleteing $deldir.  Type ok to go ahead."
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
#    echo "exit code was $ret_code"
  if [ $ret_code != 0 ]; then
    echo "exit code was $ret_code"
  fi
  return $ret_code
}
        


progress "JSON file is $json"

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

scripts="$lava/scripts"
python="/usr/bin/python"
source=$(tar tf "$tarfile" | head -n 1 | cut -d / -f 1)
sourcedir="$directory/$name/$source"
bugsdir="$directory/$name/bugs/$source"
logs="$directory/$name/logs"


if [ $skip_to_inject -eq 0 ]; then

    dbexists=$(psql -tAc "SELECT 1 from pg_database where datname='$db'" -U postgres)
    echo "dbexists $dbexists"

    if [ -z $dbexists ]; then
        progress "No db -- creating $db"
        run_remote "$dbhost" "createdb -U postgres $db"
    else
        if [ $dbexists -eq 1 ]; then
            progress "database $db already exists"
        else 
            progess "wtf"
            exit 1111
        fi
    fi

    if [ $skip_deleting -eq 0 ]; then
        deldir "$sourcedir"
        deldir "$logs"
        deldir "$bugsdir"
        /bin/mkdir -p $logs
        lf="$logs/dbwipe.log"  
        progress "Wiping db $db & setting up anew -- logging to $lf"
        run_remote "$dbhost" "/usr/bin/psql -d $db -f $lava/sql/lava.sql -U postgres >& $lf"
    fi
    /bin/mkdir -p $logs

    lf="$logs/add_queries.log" 
    progress "Adding queries to source -- logging to $lf"
    run_remote "$buildhost" "$scripts/add_queries.sh $json >& $lf" 
    
    lf="$logs/make.log"
    progress "Making 32-bit version with queries -- logging to $lf"
    run_remote "$buildhost" "cd $sourcedir && make -j `nproc`  >& $lf"
    run_remote "$buildhost" "cd $sourcedir && make install   &>> $lf"
    
    for input in $inputs
    do
        i=`echo $input | sed 's/\//-/g'`
        lf="$logs/bug_mining-$i.log"
        progress "PANDA taint analysis prospective bug mining -- input $input -- logging to $lf"
        run_remote "$pandahost" "$python $scripts/bug_mining.py $json $input >& $lf"
        echo -n "Num Bugs in db: "
        run_remote "$dbhost" "/usr/bin/psql -d $db -U postgres -c 'select count(*) from bug' | head -3 | tail -1"
    done
else
    progress "Skipping ahead to injection"
fi

/bin/mkdir -p $logs

progress "Injecting $num_inject bugs"
for i in `seq $num_inject`
do    
    lf="$logs/inject-$i.log"  
    progress "Injecting bug $i -- logging to $lf"
    run_remote "$testinghost" "$python $scripts/inject.py -r $json >& $lf"
    grep SELECTED $lf
    grep retval "$lf"
    a=`psql -d $db -U postgres -c "select count(*) from run where fuzz=true and exitcode != -11" | head -3  | tail -1 `
    b=`psql -d $db -U postgres -c "select count(*) from run where fuzz=true and exitcode = -11" | head -3  | tail -1 `
    y=`bc <<< "scale=3; $b/($a+$b)"`
    t=`bc <<< "$a + $b"`
    echo "Runs: $t  Yield: $y"
done

progress "Everthing finished."

