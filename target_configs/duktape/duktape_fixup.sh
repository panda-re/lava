#!/bin/bash

cd "$1/src"
sed -i -e 's/duk_push_string(ctx/duk_push_string(data_flow, ctx/g' duk_module_duktape-pre.c
sed -i -e 's/typedef\(.*\)int \*data_flow, /typedef\1/g' duktape-pre.c

sed -i -e 's/duk_push_literal_raw((thr)/duk_push_literal_raw(data_flow, (thr)/g' duktape-pre.c
#sed -i -e 's/duk_heap_mark_and_sweep(heap/duk_heap_mark_and_sweep(data_flow, heap/g' duktape-pre.c

# Don't inject into these, they're called from uninstrumented fns
#sed -i -e 's/duk_heap_mem_alloc_checked((thr)/duk_heap_mem_alloc_checked(data_flow, (thr)/g' duktape-pre.c
#sed -i -e 's/duk__check_voluntary_gc((heap/duk__check_voluntary_gc(data_flow, (heap/g' duktape-pre.c
#sed -i -e 's/duk_err_error_alloc_failed((thr)/duk_err_error_alloc_failed(data_flow, (thr)/g' duktape-pre.c

sed -i -e 's/duk_err_handle_error((thr)/duk_err_handle_error(data_flow, (thr)/g' duktape-pre.c

sed -i -e 's/duk_generic_error_stash)(ctx/duk_generic_error_stash)(data_flow, ctx /g' duk_cmdline-pre.c

# Too ambitious, we didn't inject into all these
#sed -i -e 's/duk_\([a-z_]*\)((thr)/duk_\1(data_flow, (thr)/g' duktape-pre.c
