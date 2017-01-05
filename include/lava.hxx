#ifndef __LAVA_HXX__
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

// This garbage makes the ORM map integer-vectors to INTEGER[] type in Postgres
// instead of making separate tables. Important for uniqueness constraints to
// work!
#pragma db map type("INTEGER\\[\\]") as("TEXT") to("(?)::INTEGER[]") from("(?)::TEXT")
typedef std::vector<uint32_t> uint32_t_vec;
#pragma db value(uint32_t_vec) type("INTEGER[]")

namespace clang { class FullSourceLoc; }
#pragma db value
struct Loc {
    unsigned line;
    unsigned column;

    Loc() {}
    Loc(unsigned line, unsigned column) : line(line), column(column) {}
    Loc(const clang::FullSourceLoc &full_loc);

    friend std::ostream &operator<<(std::ostream &os, const Loc &loc) {
        os << loc.line << ":" << loc.column;
        return os;
    }

    Loc adjust_line(unsigned line_offset) const {
        return Loc(line + line_offset, column);
    }

    bool operator==(const Loc &other) const {
        return line == other.line && column == other.column;
    }

    bool operator<(const Loc &other) const {
        return std::tie(line, column) < std::tie(other.line, other.column);
    }
};

#pragma db value
struct LavaASTLoc {
    std::string filename;
    Loc begin;
    Loc end;

    LavaASTLoc() {}
    LavaASTLoc(std::string filename, Loc begin, Loc end) :
        filename(filename), begin(begin), end(end) {}

    explicit LavaASTLoc(std::string serialized) {
        std::vector<std::string> components;
        std::istringstream iss(serialized);
        for (std::string item; std::getline(iss, item, ':');) {
            components.push_back(item);
        }
        filename = components[0];
        begin = Loc(std::stol(components[1]), std::stol(components[2]));
        end = Loc(std::stol(components[3]), std::stol(components[4]));
    }
    operator std::string() const {
        std::stringstream os;
        os << *this;
        return os.str();
    }

    friend std::ostream &operator<<(std::ostream &os, const LavaASTLoc &loc) {
        os << loc.filename << ":" << loc.begin << ":" << loc.end;
        return os;
    }

    LavaASTLoc adjust_line(unsigned line_offset) const {
        return LavaASTLoc(filename,
                begin.adjust_line(line_offset),
                end.adjust_line(line_offset));
    }

    bool operator==(const LavaASTLoc &other) const {
        return std::tie(filename, begin, end)
            == std::tie(other.filename, other.begin, other.end);
    }

    bool operator<(const LavaASTLoc &other) const {
        return std::tie(filename, begin, end)
            < std::tie(other.filename, other.begin, other.end);
    }
};

#pragma db object
struct SourceLval { // was DuaKey
#pragma db id auto
    unsigned long id;

    LavaASTLoc loc;

    std::string ast_name;

    // When did we see taint?
    enum Timing {
        NULL_TIMING = 0,
        BEFORE_OCCURRENCE = 1,
        AFTER_OCCURRENCE = 2
    } timing;

    uint32_t len_bytes;

#pragma db index("SourceLvalUniq") unique members(loc, ast_name, timing)

    bool operator<(const SourceLval &other) const {
        return std::tie(loc, ast_name, timing) <
            std::tie(other.loc, other.ast_name, other.timing);
    }

    friend std::ostream &operator<<(std::ostream &os, const SourceLval &m) {
        os << "Lval [" << m.loc.filename << " " << m.loc.begin << " ";
        os << "\"" << m.ast_name << "\"]";
        return os;
    }
};

#pragma db object
struct LabelSet {
#pragma db id auto
    unsigned long id;

    uint64_t ptr;           // Pointer to labelset during taint run
    std::string inputfile;  // Inputfile used for this run.

    std::vector<uint32_t> labels;

#pragma db index("LabelSetUniq") unique members(ptr, inputfile, labels)

    bool operator<(const LabelSet &other) const {
        return std::tie(ptr, inputfile, labels) <
            std::tie(other.ptr, other.inputfile, other.labels);
    }
};

#pragma db object
struct Dua {
#pragma db id auto
    unsigned long id;

#pragma db not_null
    const SourceLval* lval;

    // Labelset for each byte, in sequence, at shoveling point.
    std::vector<const LabelSet*> viable_bytes;
    std::vector<uint32_t> byte_tcn;

    std::vector<uint32_t> all_labels;

    // Inputfile used when this dua appeared.
    std::string inputfile;

    // max tcn of any byte of this lval
    uint32_t max_tcn;
    // max cardinality of taint set for lval
    uint32_t max_cardinality;

    uint64_t instr;     // instr count
    bool fake_dua;      // true iff this dua is fake (corresponds to untainted bytes)

#pragma db index("DuaUniq") unique members(lval, inputfile, instr)

    bool operator<(const Dua &other) const {
         return std::tie(lval->id, viable_bytes, inputfile, max_tcn,
                         max_cardinality, instr, fake_dua) <
             std::tie(other.lval->id, other.viable_bytes, other.inputfile,
                     other.max_tcn, other.max_cardinality, other.instr,
                     other.fake_dua);
    }

    operator std::string() const {
        std::stringstream os;
        os << *this;
        return os.str();
    }

    friend std::ostream &operator<<(std::ostream &os, const Dua &dua) {
        os << "DUA [" << dua.inputfile << "][" << *dua.lval << ",";
        os << "[{";
        auto it = std::ostream_iterator<uint64_t>(os, "}, {");
        for (const LabelSet *ls : dua.viable_bytes) {
            *it++ = ls ? ls->ptr : 0;
        }
        os << "}]," << "{";
        std::copy(dua.all_labels.begin(), dua.all_labels.end(),
                std::ostream_iterator<uint32_t>(os, ","));
        os << "}," << dua.max_tcn;
        os << "," << dua.max_cardinality << "," << dua.instr;
        os << "," << (dua.fake_dua ? "fake" : "real");
        os << "]";
        return os;
    }

};

#pragma db object
struct AttackPoint {
#pragma db id auto
    unsigned long id;

    LavaASTLoc loc;

    std::string ast_name;

    enum Type {
        FUNCTION_ARG,
        POINTER_RW,
        QUERY_POINT,
        TYPE_END
    } type;

#pragma db index("AttackPointUniq") unique members(loc, type)

    bool operator<(const AttackPoint &other) const {
        return std::tie(loc, type) <
            std::tie(other.loc, other.type);
    }

    operator std::string() const {
        std::stringstream os;
        os << *this;
        return os.str();
    }

    friend std::ostream &operator<<(std::ostream &os, const AttackPoint &m) {
        constexpr const char *names[TYPE_END] = {
            "ATP_FUNCTION_ARG",
            "ATP_POINTER_RW",
            "ATP_QUERY_POINT",
        };
        os << "ATP [" << m.loc.filename << " " << m.loc.begin << "] {";
        os << names[m.type] << "}";
        return os;
    }

    static inline AttackPoint OldStyle(LavaASTLoc loc, std::string ast_name, Type type) {
        return AttackPoint{0, loc, ast_name, type};
    }
    static AttackPoint FunctionArg(LavaASTLoc loc, std::string ast_name) {
        return OldStyle(loc, ast_name, FUNCTION_ARG);
    }
    static AttackPoint PointerRW(LavaASTLoc loc, std::string ast_name) {
        return OldStyle(loc, ast_name, POINTER_RW);
    }
    static AttackPoint QueryPoint(LavaASTLoc loc, std::string ast_name) {
        return AttackPoint{0, loc, ast_name, QUERY_POINT};
    }
};

#pragma db object bulk(5000)
struct Bug {
#pragma db id auto
    unsigned long id;

    enum Type {
        PTR_ADD,
        RET_BUFFER,
        REL_WRITE,
        TYPE_END
    } type;

#pragma db not_null
    const Dua* trigger;
#pragma db not_null
    const SourceLval* trigger_lval; // == trigger->lval
    std::vector<uint32_t> selected_bytes;
    uint64_t selected_bytes_hash;

#pragma db not_null
    const AttackPoint* atp;

    uint64_t max_liveness;

    // Possible exploit pad for ret-eax bugs.
    // Distance for relative-write style bugs.
    // NULL otherwise.
    const Dua *extra_dua;
    uint32_t exploit_pad_offset;

#pragma db index("BugUniq") unique members(type, atp, trigger_lval, \
        selected_bytes, extra_dua)
#pragma db index("BugLvalsQuery") members(atp, type, extra_dua)

    Bug() {}
    Bug(Type type, const Dua *trigger, std::vector<uint32_t> selected_bytes,
            uint64_t max_liveness, const AttackPoint *atp,
            const Dua *extra_dua, uint32_t exploit_pad_offset)
        : id(0), type(type), trigger(trigger), trigger_lval(trigger->lval),
            selected_bytes(selected_bytes), atp(atp), max_liveness(max_liveness),
            extra_dua(extra_dua), exploit_pad_offset(exploit_pad_offset),
            selected_bytes_hash(0) {
        for (size_t i = 0; i < selected_bytes.size(); i++) {
            selected_bytes_hash ^= (selected_bytes[i] + 1) << (16 * (i % 4));
        }
    }

    bool operator<(const Bug &other) const {
        return std::tie(type, atp->id, trigger->id, selected_bytes_hash,
                extra_dua->id) < std::tie(other.type, other.atp->id,
                    other.trigger->id, other.selected_bytes_hash,
                    other.extra_dua->id);
    }

    inline uint32_t magic() const {
        return 0x6c617661 - id;
    }

    // this logic is complicated.  TODO: understand/fix this
    // magic for kt has to be 2 bytes and we could
    // can either be (LAVA - id) & 0xffff
    // or (LAVA & 0xffff) - id
    // the second way seems like a better solution for id's greater than
    // LAVA & 0xffff because we get wrap arounds that still create unique
    // magic values
    inline uint16_t magic_kt() const {
        return ((uint16_t) (0x6c617661 & 0xffff)) - id;
    }

    static Bug PtrAdd(const Dua *trigger, std::vector<uint32_t> selected_bytes,
            uint64_t max_liveness, const AttackPoint *atp) {
        return Bug(PTR_ADD, trigger, selected_bytes, max_liveness, atp,
            nullptr, 0);
    }
    static Bug RetBuffer(const Dua *trigger, std::vector<uint32_t> selected_bytes,
            uint64_t max_liveness, const AttackPoint *atp,
            const Dua *exploit_pad, uint32_t exploit_pad_offset) {
        return Bug(RET_BUFFER, trigger, selected_bytes, max_liveness, atp,
            exploit_pad, exploit_pad_offset);
    }
    static Bug RelWrite(const Dua *trigger, std::vector<uint32_t> selected_bytes,
            uint64_t max_liveness, const AttackPoint *atp,
            const Dua *rel_write_distance) {
        return Bug(REL_WRITE, trigger, selected_bytes, max_liveness, atp,
            rel_write_distance, 0);
    }
};

#pragma db view object(Bug) \
    query((?) + "ORDER BY" + Bug::trigger_lval, distinct)
struct BugLval {
    unsigned long trigger_lval;
};

#pragma db object
struct Build {
#pragma db id auto
    unsigned long id;

#pragma db value_not_null
    // Bugs that were inserted into this build
    std::vector<const Bug*> bugs;

    std::string output;    // path to executable
    bool compile;           // did the build compile?

    bool operator<(const Build &other) const {
        return std::tie(bugs, output, compile) <
            std::tie(other.bugs, other.output, other.compile);
    }
};

#pragma db object
struct Run {
#pragma db id auto
    unsigned long id;

#pragma db not_null
    const Build* build;
    const Bug* fuzzed;      // was this run on fuzzed or orig input?
    int exitcode;           // exit code of program
    std::string output;     // output of program
    bool success;           // true unless python script failed somehow.

    bool operator<(const Run &other) const {
        return std::tie(build->id, fuzzed->id, exitcode, output, success) <
            std::tie(other.build->id, other.fuzzed->id, other.exitcode,
                    other.output, other.success);
    }
};

#pragma db object
struct SourceFunction {
#pragma db id auto
    unsigned long id;

    LavaASTLoc loc;
    std::string name;       // Function name

#pragma db index("SourceFunctionUniq") unique members(loc, name)

    bool operator<(const SourceFunction &other) const {
        return std::tie(loc, name) <
            std::tie(other.loc, other.name);
    }
};

#pragma db object
struct Call {
#pragma db id auto
    unsigned long id;

    uint64_t call_instr;    // Instruction count at call
    uint64_t ret_instr;     // Instruction count at ret

#pragma db not_null
    const SourceFunction* called_function;
    std::string callsite_file;
    uint32_t callsite_line;

#pragma db index("CallUniq") unique members(call_instr, ret_instr, called_function, callsite_file, callsite_line)

    bool operator<(const Call &other) const {
        return std::tie(call_instr, ret_instr, called_function->id,
                callsite_file, callsite_line) <
            std::tie(other.call_instr, other.ret_instr,
                    other.called_function->id, other.callsite_file,
                    other.callsite_line);
    }
};
#endif
