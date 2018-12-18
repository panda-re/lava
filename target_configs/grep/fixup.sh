#!/bin/bash

sed -i -e 's/data_flowvoid/data_flow/g' $1/*/*.c
sed -i -e 's/int \*void/int \*/g' $1/*/*.c
sed -i -e 's/__attribute__ ((__nonnull__ (.*)))//g' $1/*/*.c

#sed -i -e 's/pred->func (data_flow, /pred->func (/g' $1/lib/dfa-pre.c
#sed -i -e 's/dfaerror (dcgettext/dfaerror (data_flow, dcgettext/g' $1/lib/dfa-pre.c
#
#sed -i -e 's/int (\*matcher) (char/int (\*matcher) (int*, char/g' $1/lib/exclude-pre.c
#sed -i -e 's/int \*data_flow, options/options/g' $1/lib/exclude-pre.c
#sed -i -e 's/void (\*\*addfnptr) (struct exclude/void (\*\*addfnptr) (int*, struct exclude/g' $1/lib/exclude-pre.c
#
#sed -i -e 's/int (\*compare) (void const \*,/int (\*compare) (int *, void const \*,/g' $1/lib/fts-pre.c
#sed -i -e 's/int \*data_flow, (sizeof &dummy/data_flow, (sizeof \&dummy/g' $1/lib/fts-pre.c

sed -i -e 's/suppressible_error ((\*/suppressible_error (data_flow, (\*/g' $1/src/grep-pre.c
sed -i -e 's/open_symlink_nofollow_error ((\*/open_symlink_nofollow_error (data_flow, (\*/g' $1/src/grep-pre.c
sed -i -e 's/__gnu_printf__, 1, 2/__gnu_printf__, 2, 3/g' $1/src/grep-pre.c

sed -i -e 's/dfaerror (gettext/dfaerror (data_flow, gettext/g' $1/src/dfa-pre.c
sed -i -e 's/pred->func (data_flow, /pred->func (/g' $1/src/dfa-pre.c

sed -i -e 's/(int \*data_flow, options \&/(options \&/g' $1/src/exclude-pre.c
sed -i -e 's/int (\*matcher) (char/int (\*matcher) (int *, char/g' $1/src/exclude-pre.c

sed -i -e 's/addfnptr) (struct/addfnptr) (int *, struct/g' $1/src/exclude-pre.c
