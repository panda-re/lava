#!/bin/bash

. test_fns.sh

results=./results.txt
echo -e "Project\t\tRESET\tCLEAN\tADD \tMAKE\tTAINT\tINJECT" > $results

for project in ../target_configs/*; do
    run_tests $(basename $project) >> $results
done
