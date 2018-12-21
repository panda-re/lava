#!/bin/bash

sed -i -e 's/data_flowvoid/data_flow/g' $1/*/*.c
sed -i -e 's/ __attribute__ (([ _a-zA-Z0-9,]*))//g' $1/src/*.c
sed -i -e 's/ __attribute__ .*__printf__.*/;/g' $1/src/*.c

# Replace the handler typedef with one without dataflow since something
# is going wrong with it
sed -i -e 's/jv_nomem_handler_f)(int \*data_flow, /jv_nomem_handler_f)(/g' $1/src/*.c

# Sometimes we don't inject into put_char?
sed -i -e "s/put_char('/put_char(data_flow, '/g" $1/src/*.c

# We're adding dataflow into foo=\n((void *)0); Don't do that
sed -i -e 's/int \*data_flow, (void \*)0/(void \*)0/g' $1/src/*.c
