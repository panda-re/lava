#!/bin/bash

run_test() {
    # args: project, log_name, everything's flags
    # returns 0 on success
    log="logs/$1/$2.txt"
    ../scripts/everything.sh $3 $1 > "$log" 2>/dev/null
    if ! grep -q "Everything finished" $log; then
        echo "Failure for $1"
        return 1
    fi
    return 0
}

results=./results.txt
echo -e "Each zero denotes a successesful step. After the first failure, no other tests run" > $results
echo -e "Project\t\tRESET\tCLEAN\tADD\tMAKE\tTAINT\tINJECT" >> $results

for project in ../target_configs/*; do
    project=$(basename $project)
    echo "Starting test for $project"
    mkdir -p logs/$project
    rm -f logs/$project/*.txt

    # Default values: failures
    RESET=; CLEAN=; ADD=; MAKE=; TAINT=; INJECT=
    END=;

    # Run each step individually, check for errors
    (run_test $project "01_reset" "--reset -k") &&
    RESET="PASS\t" &&
    (run_test $project "02_clean" "--clean -k") &&
    CLEAN="PASS\t" &&
    run_test $project "03_add_queries" "--add-queries -k" &&
    ADD="PASS\t"  &&
    run_test $project "04_make" "--make -k" &&
    MAKE="PASS\t"  &&
    run_test $project "05_taint" "--taint --curtail 1000 -k" &&
    TAINT="PASS\t"  &&
    run_test $project "06_inject" "--inject 3 -k" &&
    INJECT="PASS\t"  &&
    echo "Passed all tests for $project" ||
    (echo "Failed a test for $project" && END="FAIL")

    # The vars for failing steps will all be blank so we just append
    # FAIL if there's a failure and it ends up in the right spot
    echo -e "$project\t\t$RESET$CLEAN$ADD$MAKE$TAINT$INJECT$END" >> $results
done
