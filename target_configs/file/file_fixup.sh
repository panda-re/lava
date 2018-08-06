#!/bin/bash

cd "$1/src"

sed -i -e 's/\(\([a-z]\)(\)/\1int * data_flow, /g' magic.h.in
sed -i -e 's/data_flow, void/data_flow/g' magic.h.in

sed -i -e 's/\(\(F\)(\)/\1data_flow, /g' softmagic.c
sed -i -e 's/file_fmtcheck((/file_fmtcheck((data_flow), (/g' softmagic.c
sed -i -e 's/__format_arg__(3)//g' softmagic.c

sed -i -e '/data_flow/! s/\(\(getu..\)(\)/\1data_flow, /g' readelf.c
sed -i -e 's/getu32(swap/getu32(data_flow, swap/g' readelf.c

sed -i -e 's/\(\(elf_getu16\|toomany\|dophn_exec\|dophn_core\|doshn\)(\)/\1data_flow, /g' elfclass.h

sed -i -e 's/\(cdf_tole.\|cdf_getuint..\)(int \*data_flow, /\1(/g' cdf.c

sed -i -e '/data_flow/! s/\(\(cdf_read_catalog\|cdf_read_encrypted_package\|cdf_read_user_stream\)(\)/\1data_flow, /g' cdf.h
sed -i -e '/data_flow/! s/\(\(cdf_read_catalog\|cdf_read_encrypted_package\|cdf_read_user_stream\)(\)/\1data_flow, /g' readcdf.c
sed -i -e 's/cdf_tole2(data_flow, /cdf_tole2(/g' readcdf.c
sed -i -e 's/\(cdf_tole.\)(.*data_flow, /\1(/g' cdf.h

sed -i -e '/data_flow/! s/\(\(get_next_format_from_precision\|get_next_format_from_width\)(\)/\1data_flow, /g' fmtcheck.c

sed -i -e 's/data_flowvoid/data_flow/g' file.c
sed -i -e 's/docprint(.*data_flow, /docprint(/g' file.c

sed -i -e 's/\*fun)(/\*fun)(int* data_flow, /g' apprentice.c
sed -i -e 's/data_flowvoid/data_flow/g' apprentice.c

sed -i -e 's/data_flowvoid/data_flow/g' magic.c

cp ~/lava/file/magic.mgc ../magic
touch -d 0 ../magic/magic.mgc
