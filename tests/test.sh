#!/bin/bash

. test_fns.sh
echo "Project       RESET    CLEAN    ADD      MAKE     TAINT    INJECT   COMP"
run_tests $1
