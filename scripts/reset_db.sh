
# Load lava-functions
. `dirname $0`/funcs.sh
absolute_path=$(readlink -f "$0")
scripts_path=$(dirname "$absolute_path")
lava=$(dirname "$scripts_path")
sql="$lava/tools/lavaODB/generated/lava.sql"

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

# This is just a dummy values
project_name="toy"

. `dirname $0`/vars.sh

sourcedir="$directory/$name/$source"
bugsdir="$directory/$name/bugs"
logs="$directory/$name/logs"

RESET_DB() {
    lf="$logs/dbwipe.log"
    truncate "$lf"
    progress "everything" 1  "Resetting lava db -- logging to $lf"
    run_remote "$buildhost" "dropdb -U $pguser -h $dbhost $db || true" "$lf"
    run_remote "$buildhost" "createdb -U $pguser -h $dbhost $db || true" "$lf"
    run_remote "$buildhost" "psql -d $db -h $dbhost -f \"$sql\" -U $pguser" "$lf"
    run_remote "$buildhost" "echo dbwipe complete" "$lf"
}

RESET_DB
