#!/bin/bash

cd "$1/src"


sed -i -e 's/file_printf(ms/file_printf(data_flow,ms/g' compress-pre.c
sed -i -e 's/zm = (((int (\*)(/zm = (((int (\*)(int \*,/g' compress-pre.c

sed -i -e 's/defprint(int \*data_flow,/defprint(/g' file-pre.c
sed -i -e 's/defprint(data_flow,/defprint(/g' file-pre.c



sed -i -e 's/file_magwarn(ms/file_magwarn(data_flow, ms/g' apprentice-pre.c

sed -i -e 's/\(\([a-z]\)(\)/\1int * data_flow, /g' magic.h.in
sed -i -e 's/data_flow, void/data_flow/g' magic.h.in

sed -i -e 's/\(\(F\)(\)/\1data_flow, /g' softmagic-pre.c
sed -i -e 's/file_fmtcheck((/file_fmtcheck((data_flow), (/g' softmagic-pre.c
sed -i -e 's/__format_arg__(3)//g' softmagic-pre.c

sed -i -e '/data_flow/! s/\(\(getu..\)(\)/\1data_flow, /g' readelf-pre.c
sed -i -e 's/getu32(swap/getu32(data_flow, swap/g' readelf-pre.c

sed -i -e 's/\(\(elf_getu16\|toomany\|dophn_exec\|dophn_core\|doshn\)(\)/\1data_flow, /g' elfclass.h


sed -i -e '/data_flow/! s/\(\(cdf_read_catalog\|cdf_read_encrypted_package\|cdf_read_user_stream\)(\)/\1data_flow, /g' readcdf-pre.c

sed -i -e '/data_flow/! s/\(\(get_next_format_from_precision\|get_next_format_from_width\)(\)/\1data_flow, /g' fmtcheck-pre.c

sed -i -e 's/data_flowvoid/data_flow/g' file-pre.c
sed -i -e 's/docprint(.*data_flow, /docprint(/g' file-pre.c

sed -i -e 's/data_flowvoid/data_flow/g' apprentice-pre.c

sed -i -e 's/data_flowvoid/data_flow/g' magic-pre.c
