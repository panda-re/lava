#!/usr/bin/env python3
#
# LAVA-owned fork of panda-re's pandare/extras/dwarfdump.py (upstream
# https://github.com/panda-re/panda/blob/dev/panda/python/core/pandare/extras/dwarfdump.py,
# as of pandare 1.8.85). Forked instead of patched upstream because LAVA is
# -- as far as we can tell -- the only real consumer of this file today, and
# panda-re is in maintenance mode, so waiting on an upstream review cycle for
# fixes LAVA is already blocked on doesn't make sense. See
# docs/dwarfdump.log at the LAVA repo root for the full bug writeups this
# fork's fixes are based on (bugs numbered 1-8 there); each fix below is
# tagged with which bug it addresses. If you're diffing this against
# upstream to send a PR there eventually, docs/dwarfdump.log is the
# changelog.

import sys
import json
import re
import os
import bisect
import functools
from typing import Optional

# Bug 1 (docs/dwarfdump.log): DIE tags that can legitimately be the resolved
# target of a pointer/sugar-type "overlay" (a DW_TAG_pointer_type or
# const/volatile/restrict/typedef DIE with no inline DW_AT_type, whose target
# is only known once the *next* sibling DIE is seen). Used to stop the parser
# from wiring a pointer's ref to whatever non-type DIE (e.g. a DW_TAG_variable
# -- in LAVA's case, its own injected LAVA_ATTACK_POINT global) happens to
# follow it at the same nesting level.
TYPE_DIE_TAGS = {
    "DW_TAG_base_type", "DW_TAG_pointer_type", "DW_TAG_structure_type",
    "DW_TAG_union_type", "DW_TAG_enumeration_type", "DW_TAG_array_type",
    "DW_TAG_subroutine_type", "DW_TAG_const_type", "DW_TAG_volatile_type",
    "DW_TAG_restrict_type", "DW_TAG_typedef",
}

# Bug 1 fix, continued: reserved per-CU type-table offset for a synthetic
# "void" placeholder (see the DW_TAG_compile_unit handler, which inserts one
# at this offset for every CU). Read panda-re's actual JSON consumer
# (panda/plugins/dwarf2/dwarf2.cpp) end to end and found that a `ref: null`
# (a genuinely untyped pointer/sugar type -- e.g. any `const void*`
# parameter, extremely common in real C) is NOT safe everywhere downstream:
# __dwarf_type_iter()'s SugarType case (dwarf2.cpp) does
# `ty = type_map[...][((RefTypeInfo*)ty)->ref]; tag = ty->type;` with NO
# null check -- a missing/null ref null-derefs and crashes PANDA at replay
# time. (Its sibling PointerType case in the same function DOES have a
# null check and degrades gracefully; SugarType's doesn't -- inconsistent,
# but not LAVA's code to fix.) Rather than leaving `ref: None`/JSON `null`
# and hoping every current and future consumer guards against it, every
# genuinely-untyped pointer/sugar-type ref is pointed at this real,
# harmless placeholder BaseType entry instead -- type_map[...][ref] then
# always resolves to a valid, non-null entry, sidestepping every unguarded
# consumer site at once without needing to patch panda's C++ side. Safe to
# hardcode as a per-CU offset: a compile unit's header always precedes its
# first real DIE by several bytes in DWARF, so local offset 0 is never a
# real DIE's offset in practice (confirmed empirically -- never observed
# across toy/lcms2/libpng/sqlite/freetype2/libxml2/openssl).
VOID_PLACEHOLDER_OFFSET = 0


# Bug 2 (docs/dwarfdump.log): resolve_real_path() is a pure function called
# once per .debug_line entry (tens to hundreds of thousands of times on a
# real binary) with heavily repeated filenames. Caching cut lcms2's transicc
# parse from ~5min to 2m44s, verified live.
@functools.lru_cache(maxsize=None)
def resolve_real_path(dwarf_path: str, project_root: Optional[str]) -> str:
    """
    Heuristically resolves corrupted DWARF file paths caused by recursive build systems.

    Build systems using commands like `make -C src` often duplicate directory names 
    in the resulting DWARF DW_AT_comp_dir and DW_AT_name fields (e.g., creating 
    phantom paths like `.../src/src/file.c`). This function detects these stutters 
    and attempts to map them back to the physical file on disk.

    Args:
        dwarf_path (str): The absolute path extracted from the DWARF data.
        project_root (str): The absolute, safe path to the root of the extracted 
                            project folder. This portion of the path is strictly 
                            protected from heuristic modifications.

    Returns:
        str: The corrected absolute file path if found on disk, otherwise 
             returns the original unmodified dwarf_path.
             
    Raises:
        TypeError: If either dwarf_path or project_root is not a string.
    """
    if not isinstance(dwarf_path, str):
        raise TypeError(f"Expected dwarf_path to be a str, got {type(dwarf_path)}")

    if project_root is None or project_root == "":
        return dwarf_path

    if not isinstance(project_root, str):
        raise TypeError(f"Expected project_root to be a str or None, got {type(project_root)}")

    # 1. If it already exists on disk, it's perfect. Return it immediately.
    if os.path.isfile(dwarf_path):
        return dwarf_path
        
    # Normalize paths to handle trailing slashes consistently
    norm_root = os.path.normpath(project_root)
    norm_dwarf = os.path.normpath(dwarf_path)
    
    # 2. THE REGEX FIX (Root-Protected)
    try:
        in_root = os.path.commonpath([norm_root, norm_dwarf]) == norm_root
    except ValueError:
        in_root = False

    if in_root:
        # Extract the unsafe downstream portion of the path
        unsafe_suffix = norm_dwarf[len(norm_root):]

        # Apply the stutter fix ONLY to the downstream portion
        # Turns "/src/src/magic.c" into "/src/magic.c"
        fixed_suffix = re.sub(r'(/[^/]+)\1/', r'\1/', unsafe_suffix)

        # Recombine the strictly safe root with the healed suffix
        # Using lstrip to prevent os.path.join from treating fixed_suffix as an absolute path
        fixed_path = os.path.join(norm_root, fixed_suffix.lstrip('/\\'))
    else:
        # Fallback: if the dwarf_path somehow doesn't start with our project root,
        # try to heal the whole string as a last resort.
        fixed_path = re.sub(r'(/[^/]+)\1/', r'\1/', norm_dwarf)
    
    # 3. Check if our regex fix actually points to a real file!
    if os.path.isfile(fixed_path):
        return fixed_path
        
    # If even the fixed path doesn't exist, return the original and hope for the best
    return dwarf_path


def parse_die(ent: str) -> dict:
    """
    Parses a single DWARF Debugging Information Entry (DIE) line from dwarfdump output.

    The line is expected to start after the DIE tag (e.g., '<1><0x45> DW_TAG_... >').
    It extracts DWARF attributes (DW_AT_*) and their values.

    Args:
        ent (str): A string containing the DWARF attributes and values for a DIE.

    Returns:
        dict: A dictionary where keys are DWARF attribute names (str) and
              values are the attribute data (str).
    """
    result = {}
    for e in ent.split('> ')[1:]:
        while e.endswith('>'):
            e = e[:-1]
        if not e.startswith('DW_AT_'):
            continue
        dat = e.split('<')
        attr = dat[0].strip()
        for v in dat[1:]:
            v = v.strip()
            if v:
                result[attr] = v
    return result

def parse_section(input_data: str) -> dict:
    """
    Parses the raw dwarfdump output into sections, separating .debug_info
    and .debug_line entries.

    Args:
        input_data (str): The raw content of the dwarfdump output.

    Returns:
        dict: A dictionary with keys '.debug_line' and '.debug_info'.
              Each value is a list of relevant string lines from that section.
              A 'None' marker is added to .debug_line to signal the end of a CU's
              line table.
    """
    result = {'.debug_line': [], '.debug_info': []}
    data = input_data.strip().split('\n')
    for l in data:
        l = l.strip()
        if l.startswith("0x"):
            result['.debug_line'].append(l)
            # Signal End of Text
            if 'ET' in l.split():
                result['.debug_line'].append(None)
        elif l.startswith("<") and not l.startswith("<pc>"):
            result['.debug_info'].append(l)
    return result

def reprocess_ops(ops):
    """
    Converts DWARF location/frame base operation values from strings to integers,
    handling hexadecimal addresses.

    Args:
        ops (list): A list of strings representing DWARF operations and operands.

    Returns:
        list: A list with operands converted to integer types where applicable.
    """
    out = []
    for op in ops:
        if op.startswith('DW_'):
            out.append(op)
        elif type(op) == str:
            if op.lstrip('-+').startswith("0x"):
                out.append(int(op, 16))
            else:
                out.append(int(op))
        else:
            out.append(op)
    return out

class TypeInfo(object):
    """Base class for all DWARF type information."""
    def __init__(self, name: str):
        """
        Initializes TypeInfo.

        Args:
            name (str): Type name.
        """
        self.name = name

    def jsondump(self):
        """
        Prepares the base type info for JSON serialization.

        Returns:
            dict: A dictionary containing the type name.
        """
        return {'name': self.name}

class TypeDB(object):
    """
    A database to store and manage DWARF type information (TypeInfo objects)
    indexed by Compilation Unit (CU) offset and type offset within the CU.
    """
    def __init__(self):
        """Initializes an empty dictionary to store type data."""
        self.data = {}

    def insert(self, cu: int, off: int, ty: TypeInfo):
        """
        Inserts a TypeInfo object into the database.

        Args:
            cu (int): The offset of the Compilation Unit (CU).
            off (int): The offset of the type within the CU.
            ty (TypeInfo): The TypeInfo object to store.
        """
        if cu not in self.data:
            self.data[cu] = {}
        if off not in self.data[cu]:
            self.data[cu][off] = ty

    def jsondump(self):
        """
        Prepares the database content for JSON serialization.

        Returns:
            dict: A nested dictionary structure ready for JSON output.
        """
        jout = {}
        for cu in self.data:
            jout[cu] = {}
            for off in self.data[cu]:
                jout[cu][off] = self.data[cu][off].jsondump()
        return jout

class LineDB(object):
    """
    A database to store and manage source code line number and address mapping (LineRange objects).
    """
    def __init__(self):
        """Initializes an empty dictionary to store line data."""
        self.data = {}

    def _find_best_fit(self, srcfn: str, lno: int, addr: int):
        """
        (Internal) Finds the best-fitting LineRange entry for a previous line number
        that should be extended to cover the current address range.

        Args:
            srcfn (str): Source file name.
            lno (int): Line number to search for.
            addr (int): Current address.

        Returns:
            int: The index of the best-fit LineRange, or -1 if none is found.
        """
        # Bugs 3/4 fix (docs/dwarfdump.log): this used to be a full O(n) scan
        # over *every* entry for srcfn regardless of .lno, called ~5x per
        # insert() on a real binary -- the single biggest cost in the whole
        # parser (236s of 426s profiled on lcms2's transicc; sqlite's
        # single-CU amalgamation made it far worse -- 35+ min and still not
        # done before this fix). self.data[srcfn] is kept sorted by .lno (see
        # insert()), so narrow to the contiguous slice with .lno == lno via
        # binary search first, then only scan within that slice for the
        # highpc-eligible match -- same result, O(log n + k) instead of O(n).
        entries = self.data[srcfn]
        lo = bisect.bisect_left(entries, lno, key=lambda x: x.lno)
        hi = bisect.bisect_right(entries, lno, key=lambda x: x.lno)
        r = [-1, -1]
        for i in range(lo, hi):
            if r[1] < entries[i].highpc and addr > entries[i].highpc:
                r = [i, entries[i].highpc]
        return r[0]

    def insert(self, srcfn: str, lno: int, col: int, addr: int, func: int = 0):
        """
        Inserts or updates a code address to line number mapping.

        Args:
            srcfn (str): Source file name.
            lno (int): Line number.
            col (int): Column number.
            addr (int): Start address of the line range.
            func (int, optional): Address of the enclosing function. Defaults to None.
        """
        assert srcfn, "Source filename not found in line info"
        if srcfn not in self.data:
            self.data[srcfn] = []

        if self.data[srcfn] and lno < self.data[srcfn][-1].lno:
            i = -1
        else:
            i = self._find_best_fit(srcfn, lno, addr)
        if i == -1:
            # Bug 4 fix: previously appended then re-sorted the *entire*
            # list from scratch on every new entry (90,820 calls / ~430M
            # comparator invocations profiled on lcms2's transicc).
            # bisect.insort keeps the list sorted incrementally instead --
            # same end state, O(n) insertion (list shift) instead of a full
            # O(n log n) re-sort every time.
            bisect.insort(self.data[srcfn], LineRange(lno, col, addr, addr, func), key=lambda x: x.lno)

        prevlno = lno-1
        i = self._find_best_fit(srcfn, prevlno, addr)
        while prevlno > 0 and i == -1:
            prevlno -= 1
            i = self._find_best_fit(srcfn, prevlno, addr)
        if i != -1:
            self.data[srcfn][i].highpc = addr

    # Bug 5 fix (docs/dwarfdump.log): update_function() used to live here --
    # an O(functions * total_lines) nested scan (for every function, over
    # every line entry in every source file) that both (a) found the line
    # whose lowpc exactly matched the function's entry address, to populate
    # FuncInfo.fn/.lno, and (b) stamped LineRange.func on every line
    # contained in the function's PC range. Removed entirely after checking
    # the actual downstream consumer (panda-re's dwarf2.cpp): it never reads
    # FuncInfo.fn/.lno, and it unconditionally re-derives and overwrites
    # every LineRange's "func" field itself right after loading this JSON
    # (load_func_info()'s own std::for_each sweep, with an even more
    # permissive containment check) -- so this method's entire output was
    # dead work. FuncInfo.fn/.lno are now populated for O(1) instead, direct
    # from the subprogram DIE's own DW_AT_decl_file/DW_AT_decl_line (see the
    # DW_TAG_subprogram handler in parse_dwarfdump()); LineRange.func is
    # simply left at its default (0) since nothing downstream reads the
    # value LAVA would have written there anyway.

    def jsondump(self):
        """
        Prepares the database content for JSON serialization.

        Returns:
            dict: A dictionary mapping source file names to lists of line range data.
        """
        jout = {}
        for srcfn in self.data:
            jout[srcfn] = []
            for lr in self.data[srcfn]:
                jout[srcfn].append(lr.jsondump())
        return jout

class GlobVarDB(object):
    """
    A database to store and manage global variable information (VarInfo objects)
    indexed by Compilation Unit (CU) offset.
    """
    def __init__(self):
        """Initializes an empty dictionary to store global variable data."""
        self.data = {}

    def insert(self, cu, var):
        """
        Inserts a global variable into the database.

        Args:
            cu (int): The offset of the Compilation Unit (CU).
            var (VarInfo): The VarInfo object to store.
        """
        if cu not in self.data:
            self.data[cu] = set()
        self.data[cu].add(var)

    def jsondump(self):
        """
        Prepares the database content for JSON serialization.

        Returns:
            dict: A dictionary mapping CU offsets to lists of global variable data.
        """
        jout = {}
        for cu in self.data:
            jout[cu] = [f.jsondump() for f in self.data[cu]]
        return jout

class FunctionDB(object):
    """
    A database to store and manage function information (FuncInfo objects)
    indexed by Compilation Unit (CU) offset.
    """
    def __init__(self):
        """Initializes an empty dictionary to store function data."""
        self.data = {}

    def insert(self, cu, f):
        """
        Inserts a function into the database.

        Args:
            cu (int): The offset of the Compilation Unit (CU).
            f (FuncInfo): The FuncInfo object to store.
        """
        if cu not in self.data:
            self.data[cu] = set()
        self.data[cu].add(f)

    def jsondump(self):
        """
        Prepares the database content for JSON serialization.

        Returns:
            dict: A dictionary mapping CU offsets to lists of function data.
        """
        jout = {}
        for cu in self.data:
            jout[cu] = [f.jsondump() for f in self.data[cu]]
        return jout


class VarInfo(object):
    """
    Stores DWARF information for a variable (local, global, or parameter).
    You will see this populate the _funcinfo.json
    """
    def __init__(self, name, cu_off):
        """
        Initializes VarInfo.

        Args:
            name (str): Variable name.
            cu_off (int): Compilation Unit offset.
        """
        self.name = name
        self.cu_offset = cu_off
        self.scope = None
        self.decl_lno = None
        self.decl_fn = None
        self.loc_op = []
        self.type = None

    def jsondump(self):
        """
        Prepares the variable info for JSON serialization.

        Returns:
            dict: A dictionary containing all variable attributes.
        """
        return {'name': self.name,
                'cu_offset': self.cu_offset,
                'scope': self.scope.jsondump(),
                'decl_lno': self.decl_lno,
                'decl_fn': self.decl_fn,
                'loc_op': self.loc_op,
                'type': self.type}

class FuncInfo(object):
    """
    Stores DWARF information for a function (subprogram).
    """
    def __init__(self, cu_off, name, scope, fb_op):
        """
        Initializes FuncInfo.

        Args:
            cu_off (int): Compilation Unit offset.
            name (str): Function name.
            scope (Scope): The memory range (low/high PC) of the function.
            fb_op (list): DWARF operation list for the frame base.
        """
        self.cu_offset = cu_off
        self.name = name
        self.scope = scope
        self.framebase = fb_op
        self.fn = None
        self.lno = None
        self.varlist = []

    def jsondump(self):
        """
        Prepares the function info for JSON serialization.

        Returns:
            dict: A dictionary containing all function attributes.
        """
        return {'name': self.name,
                'cu_offset': self.cu_offset,
                'scope': self.scope.jsondump(),
                'framebase': self.framebase,
                'fn': self.fn,
                'lno': self.lno,
                'varlist': [v.jsondump() for v in self.varlist]}

class StructType(TypeInfo):
    """Stores DWARF information for a structure or class."""
    def __init__(self, name, cu_off, size):
        """
        Initializes StructType.

        Args:
            name (str): Struct name.
            cu_off (int): Compilation Unit offset.
            size (int): Size of the struct in bytes.
        """
        TypeInfo.__init__(self, name)
        self.size = size
        self.cu_off = cu_off
        self.children = {}  # <member_offset: (name, type_offset)>

    def jsondump(self):
        """
        Prepares the struct info for JSON serialization.

        Returns:
            dict: A dictionary containing struct-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'StructType',
                'size': self.size,
                'cu_off': self.cu_off,
                'children': self.children,
                })
        return d

class BaseType(TypeInfo):
    """Stores DWARF information for a fundamental type (e.g., int, float)."""
    def __init__(self, name, size):
        """
        Initializes BaseType.

        Args:
            name (str): Base type name.
            size (int): Size of the base type in bytes.
        """
        TypeInfo.__init__(self, name)
        self.size = size

    def jsondump(self):
        """
        Prepares the base type info for JSON serialization.

        Returns:
            dict: A dictionary containing base type-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'BaseType',
                'size': self.size,
                })
        return d

class SugarType(TypeInfo):
    """Base class for types that are aliases or modifiers (e.g., typedef, const)."""
    def __init__(self, name: str, cu_off: int):
        """
        Initializes SugarType.

        Args:
            name (str): Type name/alias.
            cu_off (int): Compilation Unit offset.
        """
        TypeInfo.__init__(self, name)
        self.cu_off = cu_off
        self.ref = None

    def jsondump(self):
        """
        Prepares the sugar type info for JSON serialization.

        Returns:
            dict: A dictionary containing sugar type-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'SugarType',
                'cu_off': self.cu_off,
                'ref': self.ref,
                })
        return d

class PointerType(SugarType):
    """Stores DWARF information for a pointer type."""
    def __init__(self, name: str, cu_off: int, target: int):
        """
        Initializes PointerType.

        Args:
            name (str): Type name.
            cu_off (int): Compilation Unit offset.
            target (int): DWARF offset of the type being pointed to.
        """
        SugarType.__init__(self, name, cu_off)
        self.ref = target

    def jsondump(self):
        """
        Prepares the pointer type info for JSON serialization.

        Returns:
            dict: A dictionary containing pointer type-specific and base attributes.
        """
        d = SugarType.jsondump(self)
        d.update({
                'tag': 'PointerType',
                })
        return d

class ArrayType(SugarType):
    """Stores DWARF information for an array type."""
    def __init__(self, name: str, cu_off: int, elemty: int):
        """
        Initializes ArrayType.

        Args:
            name (str): Type name.
            cu_off (int): Compilation Unit offset.
            elemty (int): DWARF offset of the array element type.
        """
        SugarType.__init__(self, name, cu_off)
        self.ref = elemty
        self.range = []

    def jsondump(self):
        """
        Prepares the array type info for JSON serialization.

        Returns:
            dict: A dictionary containing array type-specific and base attributes.
        """
        d = SugarType.jsondump(self)
        d.update({
                'tag': 'ArrayType',
                'range': self.range,
                })
        return d

class ArrayRangeType(SugarType):
    """Stores DWARF information for the size or bounds of an array dimension."""
    def __init__(self, name: str, cu_off: int, rtype: int, cnt: int):
        """
        Initializes ArrayRangeType.

        Args:
            name (str): Type name.
            cu_off (int): Compilation Unit offset.
            rtype (int): DWARF offset of the array index type.
            cnt (int): Array size/count.
        """
        SugarType.__init__(self, name, cu_off)
        self.ref = rtype
        self.size = cnt

    def jsondump(self):
        """
        Prepares the array range type info for JSON serialization.

        Returns:
            dict: A dictionary containing array range type-specific and base attributes.
        """
        d = SugarType.jsondump(self)
        d.update({
                'tag': 'ArrayRangeType',
                'size': self.size,
                })
        return d

class EnumType(TypeInfo):
    """Stores DWARF information for an enumeration type."""
    def __init__(self, name, size):
        """
        Initializes EnumType.

        Args:
            name (str): Enum name.
            size (int): Size of the enum in bytes.
        """
        TypeInfo.__init__(self, name)
        self.size = size

    def jsondump(self):
        """
        Prepares the enum type info for JSON serialization.

        Returns:
            dict: A dictionary containing enum type-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'EnumType',
                'size': self.size,
                })
        return d

class SubroutineType(TypeInfo):
    """Stores DWARF information for a function type (signature)."""
    def __init__(self, name: str):
        """
        Initializes SubroutineType.

        Args:
            name (str): Subroutine type name.
        """
        TypeInfo.__init__(self, name)

    def jsondump(self):
        """
        Prepares the subroutine type info for JSON serialization.

        Returns:
            dict: A dictionary containing subroutine type-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'SubroutineType',
                })
        return d

class UnionType(TypeInfo):
    """Stores DWARF information for a union type."""
    def __init__(self, name: str, cu_off: int, size: int):
        """
        Initializes UnionType.

        Args:
            name (str): Union name.
            cu_off (int): Compilation Unit offset.
            size (int): Size of the union in bytes.
        """
        TypeInfo.__init__(self, name)
        self.size = size
        self.cu_off = cu_off
        self.children = {}  # <member_offset: (name, type_offset)>

    def jsondump(self):
        """
        Prepares the union type info for JSON serialization.

        Returns:
            dict: A dictionary containing union type-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'UnionType',
                'size': self.size,
                'cu_off': self.cu_off,
                'children': self.children,
                })
        return d

class Scope(object):
    """Represents a code range (e.g., function body, lexical block)."""
    def __init__(self, lopc: int, hipc: int):
        """
        Initializes Scope.

        Args:
            lopc (int): Low PC (start address).
            hipc (int): High PC (end address).
        """
        self.lowpc = lopc
        self.highpc = hipc

    def jsondump(self):
        """
        Prepares the scope info for JSON serialization.

        Returns:
            dict: A dictionary containing lowpc and highpc.
        """
        return {'lowpc': self.lowpc, 'highpc': self.highpc}

class LineRange(object):
    """Represents a contiguous range of addresses corresponding to a source line."""
    def __init__(self, lno: int, col: int, lopc: int, hipc: int, func: int):
        """
        Initializes LineRange.

        Args:
            lno (int): Line number.
            col (int): Column number.
            lopc (int): Low PC (start address).
            hipc (int): High PC (end address).
            func (int): Start address of the enclosing function.
        """
        self.lno = lno
        self.col = col
        self.lowpc = lopc
        self.highpc = hipc
        self.func = func

    def jsondump(self):
        """
        Prepares the line range info for JSON serialization.

        Returns:
            dict: A dictionary containing all line range attributes.
        """
        return {
                'lno': self.lno,
                'col': self.col,
                'lowpc': self.lowpc,
                'highpc': self.highpc,
                'func': self.func,
                }


def parse_dwarfdump(input_data: str, prefix: str="", project_root: Optional[str] = None, debug: bool = False):
    """
    The main parsing routine. Reads dwarfdump output, processes both line info
    and debug info sections, and populates the databases of variables, functions,
    and types. Finally, it dumps the databases to JSON files.

    Args:
        :param input_data: The content of the dwarfdump output.
        :param prefix: Prefix for the output JSON filenames. Defaults to "".
        :param project_root: The absolute path to the root of the extracted project folder, used for path resolution. Defaults to None.
        :param debug: A boolean flag to enable debug output, printing each line of the .debug_line section as it is processed. Defaults to False.
    """
    reloc_base = 0
    line_info = LineDB()
    globvar_info = GlobVarDB()
    func_info = FunctionDB()
    type_info = TypeDB()

    data = parse_section(input_data)
    tag = ".debug_line"
    if tag in data:
        for line in data[tag]:
            if line is None:
                continue
            
            line = line.strip()
            if debug:
                print(line)
            if line.startswith("0x"):
                addrstr, rest = line.split('[')
                lnostr, info = rest.split(']')
                addr = int(addrstr.strip(), 16) + reloc_base
                lno = int(lnostr.strip().split(',')[0])
                col = int(lnostr.strip().split(',')[1])
                if "uri:" in info:
                    srcfn = info.split("uri:")[-1].strip()
                    while srcfn and srcfn[0] in ['"', "'"]:
                        srcfn = srcfn[1:]
                    while srcfn and srcfn[-1] in ['"', "'"]:
                        srcfn = srcfn[:-1]
                    srcfn = resolve_real_path(srcfn, project_root=project_root)
                # I genuninely have no idea why if line info goes inside the 'if' this scripts breaks...
                # but don't touch it if it doesn't break any tests!
                line_info.insert(srcfn, lno, col, addr)

    type_overlay = None
    cu_off = None
    lvl_stack = []
    scope_stack = []
    func_stack = []
    type_stack = []
    # Names of abstract-instance subprograms skipped by the Bug 7 fix,
    # keyed by (cu_off, die_offset) since offsets are only unique within a
    # CU. A "concrete" (materialized) instance of an inlined function omits
    # DW_AT_name and points back at its abstract instance via
    # DW_AT_abstract_origin instead -- see the DW_TAG_subprogram handler.
    abstract_names = {}
    tag = ".debug_info"
    if tag in data:
        for line in data[tag]:
            line = line.strip()
            if not line:
                continue
            if not line.startswith('<'):
                continue

            die = line.split(' ')[0].strip()
            # Check for VALID DIE format
            if not (die.startswith('<') and die.endswith('>')):
                continue
            lvl, idx, tname = die[1:-1].split('><')
            lvl = int(lvl)

            res = parse_die(line)

            # If it's just a declaration, skip it. We want the actual code definition.
            #
            # Newly found while validating the Bug 1 fix above (not yet in
            # docs/dwarfdump.log's numbered list, but the same class of
            # problem): DW_TAG_structure_type/DW_TAG_union_type are exempted
            # from this skip. A forward-declared opaque struct (e.g. glibc's
            # `struct _IO_marker;`, pointed to by FILE's `_markers` member)
            # is exactly what DW_TAG_structure_type's own handler below
            # already has forward-declaration handling for (byte_size
            # missing -> insert a size-0 stub) -- but that handler never got
            # a chance to run, because this universal early skip removed the
            # DIE before it got there, leaving any pointer that legitimately
            # targets it dangling. Struct/union declarations don't have
            # member children to worry about, so letting them fall through
            # here is safe.
            if 'DW_AT_declaration' in res and tname not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                if res['DW_AT_declaration'] == 'yes(1)':
                    continue

            if "DW_TAG_compile_unit" in line:
                if type_overlay is not None:
                    # Bug 1 fix, continued (found live on openssl): an
                    # unclosed overlay (a pointer/sugar-type DIE with no
                    # inline DW_AT_type) that was the very last DIE of the
                    # previous CU never got a "next sibling" DIE to resolve
                    # against. Flush it as a genuine untyped pointer/sugar
                    # type instead of silently dropping it from the type
                    # table, which left anything pointing at it dangling.
                    # ref points at the VOID_PLACEHOLDER_OFFSET entry rather
                    # than staying None/null -- see that constant's comment.
                    type_overlay[2].ref = VOID_PLACEHOLDER_OFFSET
                    type_info.insert(type_overlay[0], type_overlay[1], type_overlay[2])
                    type_overlay = None
                if 'DW_AT_low_pc' in res and 'DW_AT_high_pc' in res:
                    base_addr = int(res['DW_AT_low_pc'], 16) + reloc_base
                    end_addr = int(res['DW_AT_high_pc'], 16) + reloc_base
                else:
                    # A compile unit with no code at all -- e.g. openssl's
                    # generated apps/progs.c, which is purely a dispatch
                    # data table with no function bodies -- has no PC range
                    # to report; DWARF permits this. Placeholder scope
                    # instead of crashing; only affects a variable declared
                    # directly at file scope with no enclosing function,
                    # which isn't meaningfully "scoped" anyway.
                    base_addr = 0
                    end_addr = 0
                scope_stack = [Scope(base_addr, end_addr)]
                lvl_stack = [(lvl, 'DW_TAG_compile_unit')]
                func_stack = []
                type_stack = []
                cu_off = int(idx.split('+')[0], 16)
                # Bug 1 fix, continued: synthetic "void" placeholder every
                # genuinely-untyped pointer/sugar-type ref in this CU points
                # at -- see VOID_PLACEHOLDER_OFFSET's comment above.
                type_info.insert(cu_off, VOID_PLACEHOLDER_OFFSET, BaseType("void", 0))
                continue

            idx = int(idx, 16)

            #print(lvl, idx, tname)

            while lvl < lvl_stack[-1][0]:
                lvl_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_lexical_block':
                    scope_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_subprogram':
                    # TODO: Verify if scope pop is needed here
                    # scope_stack.pop() # Added scope pop, AI recommendation...
                    func_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_structure_type':
                    type_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_union_type':
                    type_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_array_type':
                    type_stack.pop()

            if lvl != lvl_stack[-1][0] and lvl != (lvl_stack[-1][0]+1):
                continue

            if lvl_stack[-1][1] in ['SugarType', 'DW_TAG_pointer_type']:
                assert lvl == lvl_stack[-1][0], "Invalid level for type overlay"
                lvl_stack.pop()
                assert type_overlay, "Type overlay missing"
                # Bug 1 fix: only wire the overlay's ref to the next DIE if
                # that DIE actually describes a type. Previously this ran
                # unconditionally, so a pointer/sugar type with no inline
                # DW_AT_type (a genuine void*) would get its ref pointed at
                # whatever non-type DIE (e.g. a DW_TAG_variable) happened to
                # be next in raw DWARF offset order -- a dangling reference
                # that crashes the C++ dwarf2 plugin at PANDA replay time.
                if tname in TYPE_DIE_TAGS:
                    type_overlay[2].ref = idx
                else:
                    # This genuinely is an untyped pointer/sugar type (e.g.
                    # void*, or const void* -> const's own ref) -- point at
                    # the synthetic placeholder instead of wiring it to an
                    # unrelated DIE, or leaving it None/null (unsafe -- see
                    # VOID_PLACEHOLDER_OFFSET's comment).
                    type_overlay[2].ref = VOID_PLACEHOLDER_OFFSET
                type_info.insert(type_overlay[0], type_overlay[1], type_overlay[2])
                type_overlay = None

            if tname == "DW_TAG_lexical_block":
                # Same family as Bug 7: a lexical block with no PC range of
                # its own shows up as part of an abstract/never-materialized
                # structure (seen live on libxml2 and openssl, nested inside
                # what's structurally an abstract-instance region). Skip it
                # the same way -- `continue` relies on the level gate above
                # to also skip its children, since nothing gets pushed for
                # it onto lvl_stack/scope_stack.
                if 'DW_AT_low_pc' not in res or 'DW_AT_high_pc' not in res:
                    continue
                base_addr = int(res['DW_AT_low_pc'], 16) + reloc_base
                end_addr = int(res['DW_AT_high_pc'], 16) + reloc_base
                scope_stack.append(Scope(base_addr, end_addr))
                lvl_stack.append((lvl, 'DW_TAG_lexical_block'))

            elif tname == "DW_TAG_variable":
                # Anonymous compiler-generated temporaries (seen live on
                # libxml2: a DW_TAG_variable with only DW_AT_location,
                # pointing into .debug_loc, and nothing else -- no name, no
                # decl_file/line) are valid DWARF. DW_TAG_formal_parameter
                # already tolerates this same case below; mirror it here
                # instead of hard-asserting a name that doesn't exist.
                if 'DW_AT_name' not in res:
                    continue
                name = res['DW_AT_name']
                v = VarInfo(name, cu_off)

                v.scope = scope_stack[-1]
                assert 'DW_AT_decl_line' in res, "DW_AT_decl_line missing in variable"
                v.decl_lno = int(res['DW_AT_decl_line'], 16)
                assert 'DW_AT_decl_file' in res, "DW_AT_decl_file missing in variable"
                v.decl_fn = res['DW_AT_decl_file']
                v.decl_fn = v.decl_fn[v.decl_fn.find(' ') + 1:]
                v.decl_fn = resolve_real_path(v.decl_fn, project_root=project_root)
                if 'DW_AT_location' not in res:
                    continue
                for x in res['DW_AT_location'].split(':')[-1].strip().split('DW_OP_'):
                    x = x.strip()
                    if not x:
                        continue
                    v.loc_op.extend('DW_OP_{}'.format(x).split())
                v.loc_op = reprocess_ops(v.loc_op)
                assert 'DW_AT_type' in res, "DW_AT_type missing in variable"
                v.type = int(res['DW_AT_type'], 16)

                if len(func_stack) == 0:
                    globvar_info.insert(cu_off, v)
                else:
                    func_stack[-1].varlist.append(v)

            elif tname == "DW_TAG_formal_parameter":
                if 'DW_AT_name' not in res:
                    continue
                name = res['DW_AT_name']
                v = VarInfo(name, cu_off)

                v.scope = scope_stack[-1]
                assert 'DW_AT_decl_line' in res, "DW_AT_decl_line missing in formal parameter"
                v.decl_lno = int(res['DW_AT_decl_line'], 16)
                assert 'DW_AT_decl_file' in res, "DW_AT_decl_file missing in formal parameter"
                v.decl_fn = res['DW_AT_decl_file']
                v.decl_fn = v.decl_fn[v.decl_fn.find(' ') + 1:]
                v.decl_fn = resolve_real_path(v.decl_fn, project_root=project_root)
                if 'DW_AT_location' not in res:
                    continue
                for x in res['DW_AT_location'].split(':')[-1].strip().split('DW_OP_'):
                    x = x.strip()
                    if not x:
                        continue
                    v.loc_op.extend('DW_OP_{}'.format(x).split())
                v.loc_op = reprocess_ops(v.loc_op)
                assert 'DW_AT_type' in res, "DW_AT_type missing in formal parameter"
                v.type = int(res['DW_AT_type'], 16)

                assert len(func_stack) > 0, "Formal parameter outside function"
                func_stack[-1].varlist.append(v)

            elif tname == "DW_TAG_subprogram":
                if 'DW_AT_name' in res:
                    name = res['DW_AT_name']
                elif 'DW_AT_abstract_origin' in res:
                    # Found while widening the Bug 7 fix to more targets
                    # (libxml2): a "concrete" (materialized) instance of an
                    # inlined function -- has its own real low_pc/high_pc
                    # (e.g. because it's also called indirectly via a
                    # function pointer, forcing a real out-of-line copy to
                    # exist) but DWARF omits the redundant name here since
                    # it's already on the abstract-instance DIE this points
                    # back to. Recover it from abstract_names, populated
                    # below when the abstract instance itself was skipped.
                    origin_off = int(res['DW_AT_abstract_origin'], 16)
                    name = abstract_names.get((cu_off, origin_off), "<unknown_inlined_subprogram>")
                else:
                    assert False, "DW_AT_name missing in subprogram (and no DW_AT_abstract_origin to recover it from)"

                # Bug 7 fix: a DW_TAG_subprogram DIE with no DW_AT_low_pc is
                # an "abstract instance" -- e.g. a function fully inlined at
                # every call site (DW_AT_inline=DW_INL_inlined), which
                # legitimately contributes no PC range of its own. Treat it
                # like the DW_AT_declaration case already skipped above: a
                # bare `continue` here relies on the level-gate check earlier
                # in the loop to also skip this DIE's children (formal
                # parameters etc. of the abstract instance), since nothing
                # gets pushed onto lvl_stack/func_stack for it. Previously
                # this hard-asserted DW_AT_low_pc/high_pc were present and
                # crashed the whole parse on any binary with a fully-inlined
                # `inline`/`static inline` function -- i.e. most real C code.
                # Record the name first so a later concrete instance (the
                # case just above) can recover it via DW_AT_abstract_origin.
                if 'DW_AT_low_pc' not in res or 'DW_AT_high_pc' not in res:
                    abstract_names[(cu_off, idx)] = name
                    continue

                base_addr = int(res['DW_AT_low_pc'], 16) + reloc_base
                end_addr = int(res['DW_AT_high_pc'], 16) + reloc_base
                scope = Scope(base_addr, end_addr)
                scope_stack.append(scope)
                lvl_stack.append((lvl, 'DW_TAG_subprogram'))

                # (DW_AT_decl_file was asserted-present here upstream, but
                # its value was never actually read anywhere below -- the
                # assert only served to crash on concrete inlined-function
                # instances, which legitimately omit it -- see above. Dropped
                # the assert; see the Bug 5 fix below for what replaced the
                # old way FuncInfo.fn/.lno got populated.)
                if 'DW_AT_frame_base' in res:
                    fb_op = [res['DW_AT_frame_base'].split(':')[-1].strip()]
                else:
                    fb_op = []
                fb_op = reprocess_ops(fb_op)

                f = FuncInfo(cu_off, name, scope, fb_op)

                # Bug 5 fix (docs/dwarfdump.log): FuncInfo.fn/.lno (the
                # function's own declaration file/line) used to come from
                # LineDB.update_function() -- an O(functions * total_lines)
                # nested scan over *every* line-table entry in *every*
                # source file, called once per function (53.8s / 1,253 calls
                # profiled on lcms2's transicc; the dominant remaining cost
                # after Bugs 2/3/4 were fixed). Checked against the actual
                # consumer (panda-re's dwarf2.cpp, load_func_info() /
                # populate_line_range_list()): it never reads
                # FuncInfo.fn/.lno at all, and it unconditionally
                # re-derives+overwrites every LineRange's own "func" field
                # itself right after loading (its own std::for_each sweep in
                # load_func_info(), with an even more permissive containment
                # check than update_function()'s). So update_function()'s
                # entire output was dead work downstream. Replaced with an
                # O(1) read of DW_AT_decl_file/DW_AT_decl_line straight off
                # this DIE -- the same fields DW_TAG_variable/
                # DW_TAG_formal_parameter already use for the same purpose,
                # and arguably more accurate anyway (a function's prologue
                # can start at a different .debug_line row than its literal
                # declaration line). Left None (FuncInfo's default) when
                # absent, e.g. on concrete inlined-function instances, which
                # omit this the same way they omit DW_AT_name.
                if 'DW_AT_decl_file' in res and 'DW_AT_decl_line' in res:
                    decl_fn = res['DW_AT_decl_file']
                    decl_fn = decl_fn[decl_fn.find(' ') + 1:]
                    f.fn = resolve_real_path(decl_fn, project_root=project_root)
                    f.lno = int(res['DW_AT_decl_line'], 16)

                func_stack.append(f)
                func_info.insert(cu_off, f)

            elif tname == "DW_TAG_structure_type":
                if 'DW_AT_byte_size' in res:
                    sz = int(res['DW_AT_byte_size'], 16)
                else:
                    # It's a forward declaration. Set size to 0.
                    # 'None' is generally better as it indicates 'unknown size yet'.
                    sz = 0
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                t = StructType(name, cu_off, sz)

                type_info.insert(cu_off, idx, t)

                type_stack.append(t)
                lvl_stack.append((lvl, 'DW_TAG_structure_type'))

            elif tname == "DW_TAG_member":
                assert lvl_stack[-1][1] in ['DW_TAG_structure_type', 'DW_TAG_union_type'], "DW_TAG_member outside struct/union"

                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"

                # Skip bit fields
                if 'DW_AT_bit_size' in res or 'DW_AT_bit_offset' in res:
                    continue

                assert 'DW_AT_type' in res, "DW_AT_type missing in member"
                toff = int(res['DW_AT_type'], 16)

                # Found while widening the Bug 1/6/7/8 fixes to more targets
                # (not yet in docs/dwarfdump.log's numbered list): union
                # members have no DW_AT_data_member_location at all -- every
                # member of a union is implicitly at offset 0, so clang
                # doesn't bother emitting the (redundant) location
                # expression. Previously hard-required, crashing the parse
                # on any binary with a union type (freetype2's
                # FT_StreamDesc_, for one).
                if 'DW_AT_data_member_location' not in res:
                    off = 0
                else:
                    loc_op = ['DW_OP_{}'.format(x.strip()) for x in \
                            res['DW_AT_data_member_location'].split(':')[-1].strip().split('DW_OP_')[1:]]
                    # Signal attribute form DW_FORM_data1/2/4/8
                    assert len(loc_op) == 1, "Complex location expressions in member not supported"
                    assert loc_op[0].split()[0] == 'DW_OP_plus_uconst', "Only DW_OP_plus_uconst supported in member location"
                    off = int(loc_op[0].split()[1])

                type_stack[-1].children[off] = (name, toff)

            elif tname == "DW_TAG_array_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                assert 'DW_AT_type' in res, "DW_AT_type missing in array type"
                elemoff = int(res['DW_AT_type'], 16)

                t = ArrayType(name, cu_off, elemoff)

                type_info.insert(cu_off, idx, t)

                lvl_stack.append((lvl, 'DW_TAG_array_type'))
                type_stack.append(t)

            elif tname == "DW_TAG_subrange_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                assert 'DW_AT_type' in res, "DW_AT_type missing in subrange type"
                toff = int(res['DW_AT_type'], 16)
                # Bug 6 fix: DWARF allows an array dimension to be described
                # by either DW_AT_count (element count) or DW_AT_upper_bound
                # (highest valid index, count - 1) -- never both. clang
                # routinely emits the latter (e.g. glibc's FILE struct's
                # `char _shortbuf[1]` member). Previously DW_AT_count was
                # hard-required (with the upper_bound fallback written but
                # commented out), crashing the parse on any binary whose
                # DWARF references such a type -- i.e. almost anything
                # including <stdio.h>.
                if 'DW_AT_count' in res:
                    cnt = int(res['DW_AT_count'], 16)
                elif 'DW_AT_upper_bound' in res:
                    cnt = int(res['DW_AT_upper_bound'], 16) + 1
                else:
                    # Genuinely unbounded, e.g. a flexible array member
                    # (`char x[]`) -- DWARF permits a subrange_type DIE with
                    # neither attribute.
                    cnt = 0

                t = ArrayRangeType(name, cu_off, toff, cnt)

                type_info.insert(cu_off, idx, t)

                assert lvl_stack[-1][1] == 'DW_TAG_array_type', "DW_TAG_subrange_type outside array_type"
                assert (lvl_stack[-1][0]+1) == lvl, "Invalid level for subrange type"

                type_stack[-1].range.append(idx)

            elif tname == "DW_TAG_subroutine_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                t = SubroutineType(name)

                type_info.insert(cu_off, idx, t)

            elif tname == "DW_TAG_base_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                assert 'DW_AT_byte_size' in res, "DW_AT_byte_size missing in base type"
                sz = int(res['DW_AT_byte_size'], 16)
                t = BaseType(name, sz)

                type_info.insert(cu_off, idx, t)

            elif tname == "DW_TAG_pointer_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"

                if 'DW_AT_type' not in res:
                    lvl_stack.append((lvl, 'DW_TAG_pointer_type'))
                    type_overlay = (cu_off, idx, PointerType(name, cu_off, None))
                    continue
                target = int(res['DW_AT_type'], 16)

                t = PointerType(name, cu_off, target)

                type_info.insert(cu_off, idx, t)

            elif tname == "DW_TAG_enumeration_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"

                assert 'DW_AT_byte_size' in res, "DW_AT_byte_size missing in enumeration type"
                sz = int(res['DW_AT_byte_size'], 16)

                t = EnumType(name, sz)

                type_info.insert(cu_off, idx, t)

            elif tname in [
                    "DW_TAG_restrict_type",
                    "DW_TAG_const_type",
                    "DW_TAG_volatile_type",
                    "DW_TAG_typedef"
                    ]:
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                t = SugarType(name, cu_off)

                if 'DW_AT_type' not in res:
                    lvl_stack.append((lvl, 'SugarType'))
                    type_overlay = (cu_off, idx, t)
                    continue
                t.ref = int(res['DW_AT_type'], 16)

                type_info.insert(cu_off, idx, t)

            elif tname == "DW_TAG_union_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                if 'DW_AT_byte_size' in res:
                    sz = int(res['DW_AT_byte_size'], 16)
                else:
                    # Forward declaration (now reachable here since the
                    # declaration skip above exempts struct/union) -- same
                    # size=0 stub convention DW_TAG_structure_type already
                    # uses for this case.
                    sz = 0
                t = UnionType(name, cu_off, sz)

                type_info.insert(cu_off, idx, t)

                type_stack.append(t)
                lvl_stack.append((lvl, 'DW_TAG_union_type'))

            elif tname == "DW_TAG_ptr_to_member_type":
                # (C++-only construct, essentially never appears in LAVA's
                # pure-C targets, but fixed for consistency with the rest of
                # the Bug 1 fix -- see VOID_PLACEHOLDER_OFFSET's comment.)
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                t = PointerType(name, cu_off, VOID_PLACEHOLDER_OFFSET)
                type_info.insert(cu_off, idx, t)

            elif tname == "DW_TAG_imported_declaration":
                pass
            elif tname == "DW_TAG_unspecified_parameters":
                pass
            elif tname == "DW_TAG_constant":
                pass

        # Bug 1 fix, continued: same flush as above, for the very last CU in
        # the file (its trailing unclosed overlay never triggers the
        # DW_TAG_compile_unit-boundary flush since there's no next CU).
        if type_overlay is not None:
            type_overlay[2].ref = VOID_PLACEHOLDER_OFFSET
            type_info.insert(type_overlay[0], type_overlay[1], type_overlay[2])
            type_overlay = None

    with open(prefix+'_lineinfo.json', 'w') as file:
        dump_json(file, line_info)
    with open(prefix+'_globvar.json', 'w') as file:
        dump_json(file, globvar_info)
    with open(prefix+'_funcinfo.json', 'w') as file:
        dump_json(file, func_info)
    with open(prefix+'_typeinfo.json', 'w') as file:
        dump_json(file, type_info)

def dump_json(j, info):
    """
    Utility function to serialize a DWARF database object to a JSON file.

    It uses a custom encoder to call the 'jsondump' method on DWARF objects.

    Args:
        j (file object): The file stream to write JSON to.
        info (TypeDB, LineDB, etc.): The database object to serialize.
    """
    class DwarfJsonEncoder(json.JSONEncoder):
        def default(self, obj):
            if hasattr(obj, "jsondump"):
                return obj.jsondump()
            else:
                return json.JSONEncoder.default(self, obj)
    json.dump(info.jsondump(), j, cls=DwarfJsonEncoder, indent=4)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <dwarfdump_output_file | output_prefix> [output_prefix_if_file_used] [project_root]")
        sys.exit(1)

    dwarf_content = None
    project_root = os.environ.get("PROJECT_ROOT", None) # Can pass via env var

    if os.path.isfile(sys.argv[1]):
        with open(sys.argv[1], 'r', encoding='utf-8') as fd:
            print(f"[*] Reading dwarfdump output from file: {sys.argv[1]}")
            dwarf_content = fd.read()
        prefix = sys.argv[2] if len(sys.argv) > 2 else "output"
        # Grab project root if passed as 3rd CLI argument
        if len(sys.argv) > 3:
            project_root = sys.argv[3]
    else:
        prefix = sys.argv[1]
        print(f"[*] Reading dwarfdump data from stdin (pipe mode)...")
        dwarf_content = sys.stdin.buffer.read().decode()
        # Grab project root if passed as 2nd CLI argument in pipe mode
        if len(sys.argv) > 2:
            project_root = sys.argv[2]

    if not dwarf_content:
        print("[-] Error: No DWARF data found.")
        sys.exit(1)

    try:
        print(f"[*] Processing DWARF for prefix: {prefix}...")
        print(f"[*] Using Project Root: {project_root if project_root else None}")
        
        parse_dwarfdump(dwarf_content, prefix, project_root=project_root, debug=True)
        print(f"[+] Success! JSON files generated with prefix '{prefix}'")
    except AssertionError as e:
        print("[-] Error: DWARF parsing failed (AssertionError).")
        print("    Try recompiling your guest binary with -O0 -g -gdwarf-2")
        print(f"   Full stack trace: {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()