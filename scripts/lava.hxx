#ifndef __LAVA_HXX__
#define __LAVA_HXX__
#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <tuple>
#include <algorithm>
#include <iterator>
#include <memory>

// ODB Array Mappings
#pragma db map type("INTEGER\\[\\]") as("TEXT") to("(?)::INTEGER[]") from("(?)::TEXT")
typedef std::vector<uint32_t> uint32_t_vec;
#pragma db value(uint32_t_vec) type("INTEGER[]")
#pragma db map type("BIGINT\\[\\]") as("TEXT") to("(?)::BIGINT[]") from("(?)::TEXT")
typedef std::vector<uint64_t> uint64_t_vec;
#pragma db value(uint64_t_vec) type("BIGINT[]")

#pragma db value
struct Loc {
    uint32_t line;
    uint32_t column;
    Loc() {}
    Loc(uint32_t line, uint32_t column) : line(line), column(column) {}
    bool operator==(const Loc &other) const {
        return line == other.line && column == other.column;
    }
};

#pragma db value
struct LavaASTLoc {
    std::string filename;
    Loc begin;
    Loc end;
    LavaASTLoc() {}
    LavaASTLoc(std::string filename, Loc begin, Loc end) : filename(filename), begin(begin), end(end) {}
    bool operator==(const LavaASTLoc &other) const {
        return filename == other.filename && begin == other.begin && end == other.end;
    }

    // Custom C++ parsing logic for LavaASTLoc
    explicit LavaASTLoc(std::string serialized) {
        std::vector<std::string> components;
        std::istringstream iss(serialized);
        for (std::string item; std::getline(iss, item, ':');) { components.push_back(item); }
        if(components.size() >= 5) {
            filename = components[0];
            begin = Loc(std::stol(components[1]), std::stol(components[2]));
            end = Loc(std::stol(components[3]), std::stol(components[4]));
        }
    }
        
};

#pragma db value
struct Range {
    uint32_t low;
    uint32_t high;
    Range() {}
    Range(uint32_t low, uint32_t high) : low(low), high(high) {}
    bool operator==(const Range &other) const {
        return low == other.low && high == other.high;
    }
};

#pragma db object
struct SourceLval {
    #pragma db id auto
    uint64_t id;
    LavaASTLoc loc;
    std::string ast_name;
    uint32_t len_bytes;
    #pragma db index("SourceLvalUniq") unique members(loc, ast_name)
    SourceLval() {}
};

#pragma db object
struct LabelSet {
    #pragma db id auto
    uint64_t id;
    uint64_t ptr;
    std::string inputfile;
    std::vector<uint32_t> labels;
    #pragma db index("LabelSetUniq") unique members(ptr, inputfile)
    LabelSet() {}
};

#pragma db object
struct Dua {
    #pragma db id auto
    uint64_t id;
    #pragma db not_null
    const SourceLval* lval;
    std::vector<const LabelSet*> viable_bytes;
    std::vector<uint32_t> byte_tcn;
    std::vector<uint32_t> all_labels;
    std::string inputfile;
    uint32_t max_tcn;
    uint32_t max_cardinality;
    uint64_t instr;
    bool fake_dua;
    #pragma db index("DuaUniq") unique members(lval, inputfile, instr, fake_dua)
    Dua() {}
};

#pragma db object
struct DuaBytes {
    #pragma db id auto
    uint64_t id;
    #pragma db not_null
    const Dua* dua;
    Range selected;
    std::vector<uint32_t> all_labels;
    #pragma db index("DuaBytesUniq") unique members(dua, selected)
    DuaBytes() {}
};

#pragma db object
struct AttackPoint {
    #pragma db id auto
    uint64_t id;
    LavaASTLoc loc;
    enum Type {
        FUNCTION_ARG,
        POINTER_READ,
        POINTER_WRITE,
        QUERY_POINT,
        PRINTF_LEAK,
        MALLOC_OFF_BY_ONE,
        TYPE_END
    } type;
    #pragma db index("AttackPointUniq") unique members(loc, type)
    AttackPoint() {}
};

#pragma db object
struct Bug {
    #pragma db id auto
    uint64_t id;
    enum Type {
        PTR_ADD,
        RET_BUFFER,
        REL_WRITE,
        PRINTF_LEAK,
        MALLOC_OFF_BY_ONE,
        TYPE_END
    } type;
    #pragma db not_null
    const DuaBytes* trigger;
    #pragma db not_null
    const SourceLval* trigger_lval;
    #pragma db not_null
    const AttackPoint* atp;
    uint64_t max_liveness;
    std::vector<uint64_t> extra_duas;
    uint32_t magic;
    #pragma db index("BugUniq") unique members(type, atp, trigger_lval)
    Bug() {}
};

#pragma db object
struct Build {
    #pragma db id auto
    uint64_t id;
    std::vector<const Bug*> bugs;
    std::string output;
    bool compile;
    Build() {}
};

#pragma db object
struct Run {
    #pragma db id auto
    uint64_t id;
    #pragma db not_null
    const Build* build;
    #pragma db not_null
    const Bug* fuzzed;
    int exitcode;
    std::string output;
    bool success;
    bool validated;
    Run() {}
};

#pragma db object
struct SourceFunction {
    #pragma db id auto
    uint64_t id;
    LavaASTLoc loc;
    std::string name;
    #pragma db index("SourceFunctionUniq") unique members(loc, name)
    SourceFunction() {}
};

#pragma db object
struct Call {
    #pragma db id auto
    uint64_t id;
    uint64_t call_instr;
    uint64_t ret_instr;
    #pragma db not_null
    const SourceFunction* called_function;
    std::string callsite_file;
    uint32_t callsite_line;
    #pragma db index("CallUniq") unique members(call_instr, ret_instr, called_function, callsite_file, callsite_line)
    Call() {}
};

#endif