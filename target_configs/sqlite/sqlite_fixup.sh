#!/bin/bash
FILE=sqlite3-pre.c

cd "$1/src"

# Remove all instances where data_flow was added to second part of the fn
sed -i -e 's/))(int \*data_flow, /))/g' $FILE

# Manually add as first where necessary
sed -i -e 's/DlSym(sqlite3_vfs/DlSym(int \*data_flow data_flow,sqlite3_vfs/g' $FILE
sed -i -e 's/(\*sqlite3OsDlSym(sqlite3_vfs \*, void \*, const char \*))/(\*sqlite3OsDlSym(int \*data_flow, sqlite3_vfs \*, void \*, const char \*))/g' $FILE


# Fix void args
sed -i -e 's/data_flowvoid/data_flow/g' $FILE
sed -i -e 's/data_flow, void)/data_flow)/g' $FILE

