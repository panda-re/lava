#!/bin/bash

pad=$(printf '%0.1s' " "{1..15})
n_padlength=13
padlength=8

run_test() {
    # args: project, log_name, everything's flags
    # returns 0 on success
    log="logs/$1/$2.txt"
    ../scripts/everything.sh $3 $1 > "$log" 2>/dev/null
    if ! grep -q "Everything finished" $log; then
        return 1
    fi
    return 0
}

test_competition() {
    # args: project, log_name, competition's flags
    # returns 0 on success
    log="logs/$1/$2.txt"
    ../scripts/competition.sh $3 $1 > "$log" 2>/dev/null
    if ! grep -q "Everything finished" $log; then
        echo "Competition didn't finish"
        return 1
    fi
    if ! grep -q "Competition infrastructure found" $log; then
        echo "Competition failed early"
        return 1
    fi
    if grep -q "Competition infrastructure found: 0" $log; then
        echo "Competition found no bugs"
        return 1
    fi
    return 0
}

pass() {
    out="PASS"
    printf '%s %*.*s' $out 0 $((padlength - ${#out})) "$pad"
    return 0
}

fail() {
    out="FAIL"
    printf '%s %*.*s' $out 0 $((padlength - ${#out})) "$pad"
    return 0
}

run_tests() {
    # 15 chars for proj, then 8 for each field
    echo "Project       RESET    CLEAN    ADD      MAKE     TAINT    INJECT   COMP"
    # Arg: project name
    project="$1"
    mkdir -p logs/$project
    rm -f logs/$project/*.txt

    # Default values: failures

    printf '%s %*.*s' "$project" 0 $((n_padlength - ${#project})) "$pad"

    # Run each step individually, check for errors
    (run_test $project "01_reset" "--reset -k" &&
    pass &&
    run_test $project "02_clean" "--clean -k" &&
    pass
    run_test $project "03_add_queries" "--add-queries -k" &&
    pass &&
    run_test $project "04_make" "--make -k" &&
    pass &&
    run_test $project "05_taint" "--taint --curtail 1000 -k" &&
    pass &&
    run_test $project "06_inject" "--inject 3 -k" &&
    pass &&
    test_competition $project "07_comp" "-m 100" &&
    pass) ||
    fail

    echo
}
