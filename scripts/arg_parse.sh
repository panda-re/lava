#!/bin/sh
. `dirname $0`/funcs.sh
digit_re='^[0-9]+$'

function parse_args {
    echo
    progress "everything" 0 "Parsing args"

    if [ "$#" -lt 2 ]; then # With no arguments run everything
        reset=1
        reset_db=1
        add_queries=1
        make=1
        taint=1
        inject=1
        num_trials=3
        progress "everything" 0 "All steps will be executed"
        project_name=$1
        return 0
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
            -c|--clean)
               reset_db=1
               progress "everything" 0 "Reset (clean) just databse step will be executed"
               ;;
            -q|--add-queries)
               add_queries=1
               progress "everything" 0 "Add queries step will be executed"
               ;;
            -m|--make)
               make=1 # TODO: what does this mean? Make queries?
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
                knob=$OPTARG
                kt="--knobTrigger $knob"
                progress "everything" 0 "Inject step will be executed with knob trigger: knob = $knob"
                ;;

            -y|--bug-types)
                if [ "$2" ]; then
                    bug_types="$2" # TODO: single arguments must be passed as 'arg1,'
                    progress "everything" 0 "Injecting bugs of type(s): $bugtypes"
                    shift
                else
                    die 'ERROR: --bug-types requires comma-seperated list of bug types'
                fi
               ;;
            -b|--atp-type )
                # -b [bugType] : use this to specify attact point type: [mem_write|mem_read|fn_arg]
                # TODO: should allow combinations of atp types
                if [ "$2" ]; then
                    ATP_TYPE="$2"
                else
                    die 'ERROR: --atp-types requires a single atp-type'
                fi

                if [ "$ATP_TYPE" != "mem_read" -a "$ATP_TYPE" != "fn_arg" -a "$ATP_TYPE" != "mem_write" ]; then
                    echo "ATP Type ($ATP_TYPE) is not valid must specify:"
                    echo "    --atp-type [mem_write|mem_read|fn_arg]"
                    echo "Exiting . . ."
                    exit 1
                fi
                progress "everything" 0 "Query step will be executed with bug type: atp = $ATP_TYPE"
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

