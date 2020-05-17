#!/bin/bash

sed -i -e 's/data_flowvoid/data_flow/g' $1/*/*.c
sed -i -e 's/(int \*data_flow, (void \*)0)$/((void \*)0)/g' $1/src/jddctmgr-pre.c

# Specific fix (maybe unnecessary)
#sed -i -e 's/cinfo->dest->term_destination) (c/cinfo->dest->term_destination) (data_flow, c/g' $1/src/*-pre.c

# *cinfo->foo->zoo) (cinfo)
sed -i -e 's/(\*cinfo->\([a-zA-Z>_-]*\)) (c/(\*cinfo->\1) (data_flow, c/g' $1/src/*-pre.c
# *cinfo->foo->zoo) ((j_common_ptr) (cinfo))
sed -i -e 's/(\*cinfo->\([a-zA-Z>_-]*\)) ((j/(\*cinfo->\1) (data_flow, (j/g'  $1/src/*-pre.c
# *(cinfo)->err->exit_err) ((j_common_ptr) (cinfo)) TODO
sed -i -e 's/(\*(cinfo)->\([a-zA-Z>_-]*\)) ((j/(\*(cinfo)->\1) (data_flow, (j/g'  $1/src/*-pre.c

# jinit_marker_writer, jpeg_destory and jinit_memory_mgr missing get data_flow
#sed -i -e 's/jinit_marker_writer(cinfo/jinit_marker_writer(data_flow, cinfo/g' $1/src/*-pre.c
#sed -i -e 's/jpeg_destroy((j/jpeg_destroy(data_flow, (j/g' $1/src/*-pre.c
#sed -i -e 's/jinit_memory_mgr((j/jinit_memory_mgr(data_flow, (j/g' $1/src/*-pre.c

#sed -i -e 's/jpeg_suppress_tables(c/jpeg_suppress_tables(data_flow, c/g' $1/src/*-pre.c
#sed -i -e 's/jinit_compress_master(c/jinit_compress_master(data_flow, c/g' $1/src/*-pre.c

#sed -i -e 's/arith_encode(c/arith_encode(data_flow, c/g' $1/src/*-pre.c
#sed -i -e 's/jpeg_abort((j_/jpeg_abort(data_flow, (j_/g' $1/src/*-pre.c
