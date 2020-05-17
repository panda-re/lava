#!/bin/sh
. `dirname $0`/funcs.sh
digit_re='^[0-9]+$'

# Default values for all configuration varaibles
ok=0
reset=0
reset_db=0
add_queries=0
make=0
taint=0
inject=0
num_trials=0
kt=""
validate=0
reset_taint_labels=0
curtail=0
bugtypes="ptr_add,rel_write" # defaults
atptypes="pointer_write" # default - Note this does nothing for now
many=50

function parse_args {
    echo
    progress "everything" 0 "Parsing args"
    if [ "$#" -eq 1 ]; then # With no arguments run everything, else try matching args
        # If the single argument is a  flag, e.g., --help, handle that instead
        if ! [[ $1 == *"-"* ]]; then
            reset=1
            reset_db=1
            validate=1
            add_queries=1
            make=1
            taint=1
            inject=1
            num_trials=3
            progress "everything" 0 "All steps will be executed"
            project_name=$1
            return 0
        fi
    fi
    while :; do
        case $1 in
            -h|-\?|--help)
                USAGE
                exit
                ;;
            -a|--all)
               reset=1
               reset_db=1
               validate=1
               add_queries=1
               make=1
               taint=1
               inject=1
               num_trials=3
               progress "everything" 0 "All steps will be executed"
               ;;
            -k|--force)
               ok=1
               progress "everything" 0 "--force: Forcing through deletes"
               ;;

           -ak) # Backwards compatability with everyone's favorite lava1 option
               reset=1
               reset_db=1
               validate=1
               add_queries=1
               make=1
               taint=1
               inject=1
               num_trials=3
               progress "everything" 0 "All steps will be executed"
               ok=1
               progress "everything" 0 "--force: Forcing through deletes"
               ;;

            # Individual steps
            -r|--reset)
               reset=1
               progress "everything" 0 "Reset step will be executed"
               ;;
            -v|--validate)
               validate=1
               progress "everything" 0 "Validate step will be executed"
               ;;
            -c|--clean)
               reset_db=1
               progress "everything" 0 "Reset (clean) just databse step will be executed"
               ;;
            -q|--add-queries)
               add_queries=1
               progress "everything" 0 "Add queries step will be executed"
               ;;
            -m|--make)
               make=1 # TODO: does this mean make the target with the previously added queries? - Merge into add-queries step?
               progress "everything" 0 "Make step will be executed"
               ;;
            -t|--taint)
               taint=1
               progress "everything" 0 "Taint step will be executed"
               ;;

            # Expert only options- Dev/testing flags that may be broken
            --demo)
               demo=1
               progress "everything" 0 "-d: demo mode"
               ;;
            --test-data-flow) # For testing- inject 0 bugs, but add data_flow
               inject=1
               many=0
               num_trials=1
               progress "everything" 0 "[TESTING] Inject data_flow only, 0 bugs"
               ;;
            --reset-taint) # For testing, reset taint labels in database so we can rerun FBI by hand
               reset_taint_labels=1
               progress "everything" 0 "[TESTING] Resetting taint labels"
               ;;

            # Arguments that take options
            -i|--inject)
                if [ "$2" ]; then
                    inject=1
                    num_trials=$2
                    shift
                    progress "everything" 0 "Inject step will be executed: num_trials = $num_trials"
                else
                    die "ERROR: --inject requires [num_trials], got $@"
                fi
               ;;
            -n|--count)
                if [ "$2" ]; then
                    many="$2"
                    if ! [[ $many =~ $re ]] ; then
                        die 'ERROR: --many requires numeric argument'
                    fi
                    progress "everything" 0 "Number of injected bug at the same time: $many"
                    shift
                else
                    die 'ERROR: --many requires argument'
                fi
               ;;

            --enable-knob-trigger)
                if [ "$2" ]; then
                    knob=$2
                    kt="--knobTrigger $knob"
                    progress "everything" 0 "Inject step will be executed with knob trigger: knob = $knob"
                    shift
                else
                    die "--knobTrigger requires knob argument"
                fi
                ;;
            --curtail)
                if [ "$2" ] && [[ $2 =~ ^[0-9]+$ ]]; then
                    curtail="$2"
                    shift
                else
                    # default curtail=1000
                    curtail=1000
                fi
                progress "everything" 0 "Curtailing FBI after $curtail"
               ;;
            -y|--bug-types)
                if [ "$2" ]; then
                    bugtypes="$2"
                    progress "everything" 0 "Injecting bugs of type(s): $bugtypes"
                    shift
                else
                    die 'ERROR: --bug-types requires comma-seperated list of bug types'
                fi
               ;;
            -b|--atp-types )
                # -b [bugType] : use this to specify attact point type: pointer_read,pointer_write,function_call
                if [ "$2" ]; then
                    atptypes="$2"
                    progress "everything" 0 "Query step will be executed with atp types: = $atptypes"
                    shift
                else
                    die 'ERROR: --atp-types requires comma-seperated list of atp types'
                fi
                ;;

            #TODO: enable --inject=1 instead of just --inject 1 with something like:
            #--file=?*)
            #    file=${1#*=} # Delete everything up to "=" and assign the remainder.
            #    ;;
            --)              # End of all options.
                shift
                break
                ;;
            -?*)
                printf 'ERROR: Unknown option: %s\n' "$1" >&2
                USAGE
                ;;
            *)               # Default case: No more options, so break out of the loop.
                break
        esac

       shift
    done

    project_name=$1
}

