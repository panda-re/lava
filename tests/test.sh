#!/bin/bash

. test_fns.sh
echo "Project       VALIDATE RESET    CLEAN    ADD      MAKE     TAINT    INJECT   COMP"
run_tests $1
