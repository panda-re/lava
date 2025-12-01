import sys

# --- 1. GLOBAL C++ HEADER (Templates & Includes) ---
CPP_HEADER = """#ifndef __LAVA_HXX__
#define __LAVA_HXX__

#include <cstddef>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <memory>
#include <tuple>
#include <sstream>
#include <algorithm>
#include <iterator>

template<typename T, class InputIt>
inline void merge_into(InputIt first, InputIt last, size_t size, std::vector<T> &dest) {
    static std::vector<T> prev_dest;
    prev_dest.clear();
    prev_dest.swap(dest);
    dest.reserve(prev_dest.size() + size);
    std::set_union(prev_dest.begin(), prev_dest.end(), first, last, std::back_inserter(dest));
}

template<typename T, class InputIt>
inline void merge_into(InputIt first, InputIt last, std::vector<T> &dest) {
    merge_into(first, last, last - first, dest);
}

#pragma db map type("INTEGER\\\\[\\\\]") as("TEXT") to("(?)::INTEGER[]") from("(?)::TEXT")
typedef std::vector<uint32_t> uint32_t_vec;
#pragma db value(uint32_t_vec) type("INTEGER[]")

#pragma db map type("BIGINT\\\\[\\\\]") as("TEXT") to("(?)::BIGINT[]") from("(?)::TEXT")
typedef std::vector<uint64_t> uint64_t_vec;
#pragma db value(uint64_t_vec) type("BIGINT[]")

namespace clang { class FullSourceLoc; }
"""

# --- 2. ENUMS ---
ENUMS = {
    "AtpKind": {
        "values": ["FUNCTION_ARG", "POINTER_READ", "POINTER_WRITE", "QUERY_POINT", "PRINTF_LEAK", "MALLOC_OFF_BY_ONE"],
        "cpp_name": "Type"  # In C++ struct, it's just 'Type'
    },
    "BugKind": {
        "values": ["PTR_ADD", "RET_BUFFER", "REL_WRITE", "PRINTF_LEAK", "MALLOC_OFF_BY_ONE"],
        "cpp_name": "Type"
    }
}

# --- 3. COMPOSITES ---
COMPOSITES = [
    {
        "name": "Loc",
        "fields": [("line", "uint32"), ("column", "uint32")],
        "extra_cpp": """
    Loc() {}
    Loc(uint32_t line, uint32_t column) : line(line), column(column) {}
    // Loc(const clang::FullSourceLoc &full_loc); // Uncomment if linking against clang

    friend std::ostream &operator<<(std::ostream &os, const Loc &loc) {
        os << loc.line << ":" << loc.column;
        return os;
    }
    Loc adjust_line(uint32_t line_offset) const { return Loc(line + line_offset, column); }
    bool operator==(const Loc &other) const { return line == other.line && column == other.column; }
    bool operator<(const Loc &other) const { return std::tie(line, column) < std::tie(other.line, other.column); }
"""
    },
    {
        "name": "LavaASTLoc",
        "fields": [("filename", "string"), ("begin", "Loc"), ("end", "Loc")],
        "extra_cpp": """
    LavaASTLoc() {}
    LavaASTLoc(std::string filename, Loc begin, Loc end) : filename(filename), begin(begin), end(end) {}
    explicit LavaASTLoc(std::string serialized) {
        std::vector<std::string> components;
        std::istringstream iss(serialized);
        for (std::string item; std::getline(iss, item, ':');) { components.push_back(item); }
        if (components.size() >= 5) {
            filename = components[0];
            begin = Loc(std::stol(components[1]), std::stol(components[2]));
            end = Loc(std::stol(components[3]), std::stol(components[4]));
        }
    }
    operator std::string() const { std::stringstream os; os << *this; return os.str(); }
    friend std::ostream &operator<<(std::ostream &os, const LavaASTLoc &loc) {
        os << loc.filename << ":" << loc.begin << ":" << loc.end;
        return os;
    }
    bool operator==(const LavaASTLoc &other) const { return std::tie(begin, end, filename) == std::tie(other.begin, other.end, other.filename); }
    bool operator<(const LavaASTLoc &other) const { return std::tie(begin, end, filename) < std::tie(other.begin, other.end, other.filename); }
"""
    },
    {
        "name": "Range",
        "fields": [("low", "uint32"), ("high", "uint32")],
        "extra_cpp": """
    operator std::string() const { std::stringstream os; os << *this; return os.str(); }
    friend std::ostream &operator<<(std::ostream &os, const Range &r) { os << "[" << r.low << ", " << r.high << "]"; return os; }
    bool operator==(const Range &other) const { return std::tie(low, high) == std::tie(other.low, other.high); }
    bool operator<(const Range &other) const { return std::tie(low, high) < std::tie(other.low, other.high); }
    inline uint32_t size() const { return high - low; }
    inline bool empty() const { return high <= low; }
"""
    }
]

# --- 4. DATABASE MODELS ---
MODELS = [
    {
        "name": "SourceLval",
        "fields": [("loc", "LavaASTLoc"), ("ast_name", "string"), ("len_bytes", "uint32")],
        "unique": ["loc", "ast_name"],
        "extra_cpp": """
    bool operator<(const SourceLval &other) const { return std::tie(loc, ast_name) < std::tie(other.loc, other.ast_name); }
    friend std::ostream &operator<<(std::ostream &os, const SourceLval &m) {
        os << "Lval [" << m.loc.filename << " " << m.loc.begin << " " << "\\"" << m.ast_name << "\\"]";
        return os;
    }
"""
    },
    {
        "name": "LabelSet",
        "fields": [("ptr", "uint64"), ("inputfile", "string"), ("labels", "[uint32]")],
        "unique": ["ptr", "inputfile"],
        "extra_cpp": """
    bool operator<(const LabelSet &other) const { return std::tie(ptr, inputfile, labels) < std::tie(other.ptr, other.inputfile, other.labels); }
"""
    },
    {
        "name": "Dua",
        "fields": [
            ("lval", "Ref:SourceLval"), ("viable_bytes", "RefList:LabelSet"), ("byte_tcn", "[uint32]"),
            ("all_labels", "[uint32]"), ("inputfile", "string"), ("max_tcn", "uint32"),
            ("max_cardinality", "uint32"), ("instr", "uint64"), ("fake_dua", "bool")
        ],
        "unique": ["lval", "inputfile", "instr", "fake_dua"],
        "extra_cpp": """
    Dua() {}
    inline Dua(const SourceLval *lval, std::vector<const LabelSet*> &&viable_bytes,
            std::vector<uint32_t> &&byte_tcn, std::vector<uint32_t> &&all_labels,
            std::string inputfile, uint32_t max_tcn, uint32_t max_cardinality,
            uint64_t instr, bool fake_dua)
        : id(0), lval(lval), viable_bytes(std::move(viable_bytes)),
            byte_tcn(std::move(byte_tcn)), all_labels(std::move(all_labels)),
            inputfile(inputfile), max_tcn(max_tcn),
            max_cardinality(max_cardinality), instr(instr), fake_dua(fake_dua) {}

    bool operator<(const Dua &other) const {
         return std::tie(lval->id, inputfile, instr, fake_dua) < std::tie(other.lval->id, other.inputfile, other.instr, other.fake_dua);
    }
    operator std::string() const { std::stringstream os; os << *this; return os.str(); }
    friend std::ostream &operator<<(std::ostream &os, const Dua &dua) {
        os << "DUA [" << dua.inputfile << "][" << *dua.lval << ",[{";
        auto it = std::ostream_iterator<uint64_t>(os, "}, {");
        for (const LabelSet *ls : dua.viable_bytes) { *it++ = ls ? ls->ptr : 0; }
        os << "}]," << dua.max_tcn << "," << dua.max_cardinality << "," << dua.instr << "," << (dua.fake_dua ? "fake" : "real") << "]";
        return os;
    }
"""
    },
    {
        "name": "DuaBytes",
        "fields": [("dua", "Ref:Dua"), ("selected", "Range"), ("all_labels", "[uint32]")],
        "unique": ["dua", "selected"],
        "extra_cpp": """
    DuaBytes() {}
    DuaBytes(const Dua *dua, Range selected) : dua(dua), selected(selected) {
        assert(selected.low <= selected.high);
        if (selected.high <= dua->viable_bytes.size()) {
            auto it = dua->viable_bytes.cbegin() + selected.low;
            auto end = dua->viable_bytes.cbegin() + selected.high;
            for (; it != end; it++) {
                if(const LabelSet *ls = *it) merge_into(ls->labels.begin(), ls->labels.end(), all_labels);
            }
        }
    }
    bool operator<(const DuaBytes &other) const { return std::tie(dua->id, selected) < std::tie(other.dua->id, other.selected); }
    friend std::ostream &operator<<(std::ostream &os, const DuaBytes &db) { os << "DUABytes " << db.selected << " of " << *db.dua; return os; }
"""
    },
    {
        "name": "AttackPoint",
        "fields": [("loc", "LavaASTLoc"), ("type", "Enum:AtpKind")],
        "unique": ["loc", "type"],
        "extra_cpp": """
    bool operator<(const AttackPoint &other) const { return std::tie(type, loc) < std::tie(other.type, other.loc); }
    operator std::string() const { std::stringstream os; os << *this; return os.str(); }
    friend std::ostream &operator<<(std::ostream &os, const AttackPoint &m) {
        constexpr const char *names[] = {"ATP_FUNCTION_ARG", "ATP_POINTER_READ", "ATP_POINTER_WRITE", "ATP_QUERY_POINT", "ATP_PRINTF_LEAK", "ATP_MALLOC_OFF_BY_ONE"};
        os << "ATP [" << m.loc.filename << " " << m.loc.begin << "] {" << names[m.type] << "}";
        return os;
    }
"""
    },
    {
        "name": "Bug",
        "fields": [
            ("type", "Enum:BugKind"), ("trigger", "Ref:DuaBytes"), ("trigger_lval", "Ref:SourceLval"),
            ("atp", "Ref:AttackPoint"), ("max_liveness", "uint64"), ("extra_duas", "[uint64]"), ("magic", "uint32")
        ],
        "unique": ["type", "atp", "trigger_lval"],
        "extra_cpp": """
    static constexpr uint32_t const num_extra_duas[] = { [PTR_ADD] = 0, [RET_BUFFER] = 1, [REL_WRITE] = 2, [PRINTF_LEAK] = 0, [MALLOC_OFF_BY_ONE] = 0 };

    Bug() {}
    Bug(Type type, const DuaBytes *trigger, uint64_t max_liveness, const AttackPoint *atp, std::vector<uint64_t> extra_duas)
        : id(0), type(type), trigger(trigger), trigger_lval(trigger->dua->lval), atp(atp), max_liveness(max_liveness), extra_duas(extra_duas), magic(0) {
        for (int i = 0; i < 4; i++) {
            magic <<= 8; magic |= rand() % 26 + 0x60; magic ^= rand() & 0x20;
        }
    }
    // Ctor for raw ptrs used in legacy code
    Bug(Type type, const DuaBytes *trigger, uint64_t max_liveness, const AttackPoint *atp, std::vector<const DuaBytes *> extra_duas_)
        : Bug(type, trigger, max_liveness, atp, std::initializer_list<uint64_t>({})) {
        for (const DuaBytes *dua_bytes : extra_duas_) { extra_duas.push_back(dua_bytes->id); }
    }
    friend std::ostream &operator<<(std::ostream &os, const Bug &bug) { os << "Bug:\\n        " << *bug.trigger << "\\n        " << *bug.atp; return os; }
    inline uint16_t magic_kt() const { return (uint16_t)magic; }
"""
    },
    {
        "name": "Build",
        "fields": [("bugs", "RefList:Bug"), ("output", "string"), ("compile", "bool")],
        "extra_cpp": """
    bool operator<(const Build &other) const { return std::tie(bugs, output, compile) < std::tie(other.bugs, other.output, other.compile); }
"""
    },
    {
        "name": "Run",
        "fields": [("build", "Ref:Build"), ("fuzzed", "Ref:Bug"), ("exitcode", "int"), ("output", "string"),
                   ("success", "bool"), ("validated", "bool")],
        "extra_cpp": """
    bool operator<(const Run &other) const { return std::tie(build->id, fuzzed->id, exitcode, output, success) < std::tie(other.build->id, other.fuzzed->id, other.exitcode, other.output, other.success); }
"""
    }
]

# --- 5. GENERATION LOGIC ---
TYPE_MAP_CPP = {"uint32": "uint32_t", "uint64": "uint64_t", "int": "int", "string": "std::string", "bool": "bool",
                "float": "float"}
TYPE_MAP_PY = {"uint32": "int", "uint64": "int", "int": "int", "string": "str", "bool": "bool", "float": "float"}
SQL_MAP = {"uint32": "Integer", "uint64": "BigInteger", "int": "Integer", "string": "Text", "bool": "Boolean",
           "float": "Float"}


def generate_cpp():
    out = [CPP_HEADER]

    # Composites
    for comp in COMPOSITES:
        out.append(f"\n#pragma db value\nstruct {comp['name']} {{")
        for fn, ft in comp['fields']:
            cpp_t = TYPE_MAP_CPP.get(ft, ft)
            out.append(f"    {cpp_t} {fn};")
        if "extra_cpp" in comp: out.append(comp["extra_cpp"])
        out.append("};")

    # Models
    for model in MODELS:
        out.append(f"\n#pragma db object\nstruct {model['name']} {{")
        out.append("    #pragma db id auto\n    uint64_t id;")
        for fn, ft in model['fields']:
            if ft.startswith("Ref:"):
                out.append(f"    #pragma db not_null\n    const {ft.split(':')[1]}* {fn};")
            elif ft.startswith("RefList:"):
                out.append(f"    std::vector<const {ft.split(':')[1]}*> {fn};")
            elif ft.startswith("["):
                out.append(f"    std::vector<{TYPE_MAP_CPP.get(ft[1:-1], ft[1:-1])}> {fn};")
            elif ft.startswith("Enum:"):
                ename = ft.split(":")[1]
                out.append("    enum Type {")
                out.append(", ".join([f"        {v}" for v in ENUMS[ename]["values"]]))
                out.append(f"        , TYPE_END\n    }} {fn};")
            else:
                out.append(f"    {TYPE_MAP_CPP.get(ft, ft)} {fn};")

        if "unique" in model:
            out.append(f'    #pragma db index("{model["name"]}Uniq") unique members({", ".join(model["unique"])})')

        if "extra_cpp" in model: out.append(model["extra_cpp"])
        out.append("};")

    out.append("\n#endif")
    return "\n".join(out)


def generate_python():
    out = [
        "from typing import List, Optional\nfrom enum import IntEnum",
        "from sqlalchemy import BigInteger, Integer, Text, Boolean, Float, ForeignKey, UniqueConstraint",
        "from sqlalchemy.orm import Mapped, mapped_column, relationship, composite, DeclarativeBase",
        "from sqlalchemy.dialects import postgresql\nfrom dataclasses import dataclass\n",
        "class Base(DeclarativeBase):\n    pass"
    ]

    for ename, data in ENUMS.items():
        out.append(f"\nclass {ename}(IntEnum):")
        for i, v in enumerate(data["values"]): out.append(f"    {data.get('prefix', '')}{v} = {i}")

    for comp in COMPOSITES:
        out.append(f"\n@dataclass\nclass {comp['name']}:")
        for fn, ft in comp['fields']: out.append(f"    {fn}: {TYPE_MAP_PY.get(ft, ft)}")
        out.append(
            "    def __composite_values__(self): return " + ", ".join([f"self.{fn}" for fn, ft in comp['fields']]))

    for model in MODELS:
        out.append(f"\nclass {model['name']}(Base):\n    __tablename__ = '{model['name'].lower()}'")
        out.append("    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)")
        for fn, ft in model['fields']:
            if ft.startswith("Ref:"):
                target = ft.split(":")[1]
                out.append(
                    f"    {fn}_id: Mapped[int] = mapped_column('{fn}', BigInteger, ForeignKey('{target.lower()}.id'))")
                out.append(f"    {fn}: Mapped['{target}'] = relationship('{target}')")
            elif ft.startswith("RefList:"):
                target = ft.split(":")[1]
                out.append(
                    f"    {fn}: Mapped[List['{target}']] = relationship('{target}', secondary='{model['name'].lower()}_{fn}')")
            elif ft.startswith("["):
                st = SQL_MAP.get(ft[1:-1], "Integer")
                out.append(f"    {fn}: Mapped[List[int]] = mapped_column(postgresql.ARRAY({st}))")
            elif ft.startswith("Enum:"):
                out.append(
                    f"    {fn}: Mapped[{ft.split(':')[1]}] = mapped_column('{fn if fn != 'type' else 'type_'}', Integer)")
            elif any(c['name'] == ft for c in COMPOSITES):
                c = next(x for x in COMPOSITES if x['name'] == ft)
                col_defs = []
                for subn, subt in c['fields']:
                    col_name = f"{fn}_{subn}"
                    out.append(
                        f"    _{col_name}: Mapped[{TYPE_MAP_PY.get(subt, 'int')}] = mapped_column('{col_name}', {SQL_MAP.get(subt, 'Integer')})")
                    col_defs.append(f"_{col_name}")
                out.append(f"    {fn}: Mapped[{ft}] = composite(lambda *a: {ft}(*a), {', '.join(col_defs)})")
            else:
                out.append(
                    f"    {fn}: Mapped[{TYPE_MAP_PY.get(ft, 'int')}] = mapped_column({SQL_MAP.get(ft, 'Integer')})")

        if "unique" in model:
            # Simple unique constraint mapper
            # Note: For Enum 'type', C++ struct field is 'type', but DB col is 'type' or 'type_'.
            # This simplistic generator assumes column name matches field name unless overridden.
            cols = [f"'{c}'" for c in model["unique"]]
            out.append(f"    __table_args__ = (UniqueConstraint({', '.join(cols)}, name='{model['name']}Uniq'),)")

    return "\n".join(out)


if __name__ == "__main__":
    with open("lava.hxx", "w") as f: f.write(generate_cpp())
    with open("database_types.py", "w") as f: f.write(generate_python())
    print("Regenerated lava.hxx and database_types.py")