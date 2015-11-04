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
# 
# everything -q -m -t -i -A -M -I jsonfile
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


if [ $# -lt 1 ]; then
  echo "Usage: $0 JSONfile "
  exit 1
fi      



progress() {
  echo  
  if [ $1 -eq 1 ]; then
      date
  fi
  echo -e "\e[32m[everything]\e[0m \e[1m$2\e[0m" 
}   

# defaults
ok=0
add_queries=0
make=0
taint=0
inject=0
num_inject=0


# -s means skip everything up to injection
# -i 15 means inject 15 bugs (default is 1)
echo 
progress 0 "Parsing args"
while getopts  "aqmti:k" flag
do
  if [ "$flag" = "a" ]; then
      add_queries=1
      make=1
      taint=1
      inject=1
      num_inject=1
      progress 0 "All steps will be executed"
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
      num_inject=$OPTARG
      progress 0 "Inject step will be executed: num_inject = $num_inject"
  fi
  if [ "$flag" = "k" ]; then
      ok=1 
      progress 0 "-k: Okaying through deletes"
  fi
done
shift $((OPTIND -1))

json="$(realpath $1)"


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
bugsdir="$directory/$name/bugs/$source"
logs="$directory/$name/logs"

/bin/mkdir -p $logs


if [ $add_queries -eq 1 ]; then
    progress 1  "Add queries step -- btrace lavatool and fixups"
    dbexists=$(psql -tAc "SELECT 1 from pg_database where datname='$db'" -U postgres)
    echo "dbexists $dbexists"    
    if [ -z $dbexists ]; then
        progress 0 "No db -- creating $db"
        run_remote "$dbhost" "createdb -U postgres $db"
    else
        if [ $dbexists -eq 1 ]; then
            progress 0 "database $db already exists"
        else 
            progess 0 "wtf"
            exit 1111
        fi
    fi
    deldir "$sourcedir"
    deldir "$logs"
    deldir "$bugsdir"
    /bin/mkdir -p $logs
    lf="$logs/dbwipe.log"  
    progress 1  "Wiping db $db & setting up anew -- logging to $lf"
    run_remote "$dbhost" "/usr/bin/psql -d $db -f $lava/sql/lava.sql -U postgres >& $lf"
    /bin/mkdir -p $logs
    lf="$logs/add_queries.log" 
    progress 1 "Adding queries to source -- logging to $lf"
    run_remote "$buildhost" "$scripts/add_queries.sh $json >& $lf" 
    if [ "$fixupscript" != "null" ]; then
        lf="$logs/fixups.log"
        progress 1 "Fixups -- logging to $lf"
        run_remote "$buildhost" "$fixupscript"
    else
        progress 1 "No fixups"
    fi
fi


if [ $make -eq 1 ]; then 
    progress 1 "Make step -- making 32-bit version with queries"
    lf="$logs/make.log"    
    run_remote "$buildhost" "cd $sourcedir && $makecmd  >& $lf"
    run_remote "$buildhost" "cd $sourcedir && make install   &>> $lf"
fi

    
if [ $taint -eq 1 ]; then 
    progress 1 "Taint step -- running panda and fbi"
    for input in $inputs
    do
        i=`echo $input | sed 's/\//-/g'`
        lf="$logs/bug_mining-$i.log"
        progress 1 "PANDA taint analysis prospective bug mining -- input $input -- logging to $lf"
        run_remote "$pandahost" "$python $scripts/bug_mining.py $json $input >& $lf"
        echo -n "Num Bugs in db: "
        run_remote "$dbhost" "/usr/bin/psql -d $db -U postgres -c 'select count(*) from bug' | head -3 | tail -1"
    done
fi


na=1
if [ $inject -eq 1 ]; then 
    progress 1 "Injecting step -- trying $num_inject bugs"
    for i in `seq $num_inject`
    do    
        lf=`/bin/mktemp`
        progress 1 "Injecting bug $i -- logging to $lf"
        run_remote "$testinghost" "$python $scripts/inject.py -r $json >& $lf"
        grep Remaining $lf
        grep SELECTED $lf
        grep retval "$lf"
        bn=`grep SELECTED $lf | awk '{print $3}'`
#        echo bug number $bn
        nlf="$logs/inject-$bn.log"
        echo move $lf $nlf
        /bin/mv $lf $nlf
        a=`psql -d $db -U postgres -c "select count(*) from run where fuzz=true and exitcode != -11 and exitcode != -6" | head -3  | tail -1 `
        b=`psql -d $db -U postgres -c "select count(*) from run where fuzz=true and (exitcode = -11 or exitcode = -6)" | head -3  | tail -1 `
        y=`bc <<< "scale=3; $b/($a+$b)"`
        t=`bc <<< "$a + $b"`
        echo "Runs: $t  a=$a b=$b  Yield: $y"
    done
fi

progress 1 "Everthing finished."

