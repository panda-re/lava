#!/bin/bash

. test_fns.sh

results=./results.txt
for project in ../target_configs/*; do
    run_tests $(basename $project) >> $results
done
