#!/bin/bash

cd "$1/src"
sed -i -e 's/duk_push_literal_raw((thr)/duk_push_literal_raw(data_flow, (thr)/g' duktape-pre.c
sed -i -e 's/duk_push_string(ctx/duk_push_string(data_flow, ctx/g' duk_module_duktape-pre.c
