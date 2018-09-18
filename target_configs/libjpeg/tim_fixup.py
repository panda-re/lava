#!/usr/bin/python
"""
tleek@dd0421b8e69e:~/lava$ grep inverse_DCT_method_ptr libjpeg_tleek/bugs/0/libjpeg-9c-pre-m32/src/jddctmgr-pre.c 
typedef void (*inverse_DCT_method_ptr) (int *data_flow, j_decompress_ptr cinfo, jpeg_component_info * compptr, JCOEFPTR coef_block, JSAMPARRAY output_buf, JDIMENSION output_col)
  inverse_DCT_method_ptr inverse_DCT[10];
  inverse_DCT_method_ptr method_ptr = (int *data_flow, (void *)0);

"""

fn = "src/jddctmgr-pre.c"
a = open(fn).read()
open(fn+".sav", "w").write(a)

old_version = "inverse_DCT_method_ptr method_ptr = (int *data_flow, (void *)0)"
new_version = "inverse_DCT_method_ptr method_ptr = ((void *)0)"
b = a.replace(old_version, new_version)
a = b

old_version = "int *data_flowvoid"
new_version = "void"
b = a.replace(old_version, new_version)
a = b

old_version = "((*((**(pdtbl)).pub)).huffval)"
new_version = "(pdtbl && *pdtbl)"
b = a.replace(old_version, new_version)
a = b

open(fn, "w").write(a)
