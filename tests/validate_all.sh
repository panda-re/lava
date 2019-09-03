#!/bin/bash

. test_fns.sh

echo "Project       VALIDATE"
for project in ../target_configs/*; do
    mkdir -p logs/$project
    name=$(basename $project)
    printf '%s %*.*s' "$name" 0 $((n_padlength - ${#name})) "$pad"
    run_test $name "00_validate" "--validate" && pass || fail
    printf '\n'
done
