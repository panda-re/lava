#!/bin/bash

sed -i -e 's/data_flowvoid/data_flow/g' $1/*/*.c
sed -i -e 's/int \*void/int \*/g' $1/*/*.c
sed -i -e 's/__attribute__ ((__nonnull__ (.*)))//g' $1/*/*.c

sed -i -e 's/__attribute__ ((__format__ (__printf__, 1, 2)))//g' $1/src/grep-pre.c

sed -i -e 's/dfaerror (gettext/dfaerror (data_flow, gettext/g' $1/src/dfa-pre.c
sed -i -e 's/pred->func (data_flow, /pred->func (/g' $1/src/dfa-pre.c

sed -i -e 's/(int \*data_flow, options \&/(options \&/g' $1/src/exclude-pre.c
sed -i -e 's/int (\*matcher) (char/int (\*matcher) (int *, char/g' $1/src/exclude-pre.c
sed -i -e 's/addfnptr) (struct/addfnptr) (int *, struct/g' $1/src/exclude-pre.c
