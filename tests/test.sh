#!/bin/bash

. test_fns.sh
echo -e "Project\t\tRESET\tCLEAN\tADD \tMAKE\tTAINT\tINJECT"
run_tests $1
