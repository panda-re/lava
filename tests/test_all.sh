#!/bin/bash

. test_fns.sh

results=./results.txt
echo "Project       VALIDATE RESET    CLEAN    ADD      MAKE     TAINT    INJECT   COMP" > $results
for project in ../target_configs/*; do
    run_tests $(basename $project) >> $results
done
