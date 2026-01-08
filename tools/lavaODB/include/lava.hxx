#ifndef __LAVA_HXX__
#define __LAVA_HXX__

#include "lava.pb.h"
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
#include <typeinfo>

/**
 * enforce_name_match: The "Contract Lock"
 * This function ensures that the C++ Struct, the Protobuf Message,
 * and the expected Name string are all identical.
 */
template <typename T_STRUCT, typename T_PROTO>
void enforce_name_match(const std::string& expected_name) {
    // We use std::string here instead of string_view for safety
    std::string proto_name = T_PROTO::descriptor()->name();

    if (proto_name != expected_name) {
        std::cerr << "[!] SCHEMA NAME MISMATCH: " << expected_name << std::endl;
        assert(false && "Case-sensitive name mismatch");
    }
}

template<typename T, class InputIt>
inline void merge_into(InputIt first, InputIt last, size_t size, std::vector<T> &dest) {
    // Make empty array and swap with all_labels.
    // Obviously not thread-safe.
    static std::vector<T> prev_dest;
    prev_dest.clear();
    prev_dest.swap(dest);

    dest.reserve(prev_dest.size() + size);
    std::set_union(
            prev_dest.begin(), prev_dest.end(),
            first, last, std::back_inserter(dest));
}

template<typename T, class InputIt>
inline void merge_into(InputIt first, InputIt last, std::vector<T> &dest) {
    merge_into(first, last, last - first, dest);
}

// This garbage makes the ORM map integer-vectors to INTEGER[] type in Postgres
// instead of making separate tables. Important for uniqueness constraints to
// work!
#pragma db map type("INTEGER\\[\\]") as("TEXT") to("(?)::INTEGER[]") from("(?)::TEXT")
typedef std::vector<uint32_t> uint32_t_vec;
#pragma db value(uint32_t_vec) type("INTEGER[]")

#pragma db map type("BIGINT\\[\\]") as("TEXT") to("(?)::BIGINT[]") from("(?)::TEXT")
typedef std::vector<uint64_t> uint64_t_vec;
#pragma db value(uint64_t_vec) type("BIGINT[]")

namespace clang { class FullSourceLoc; }
#pragma db value
struct Loc {
    uint32_t line;
    uint32_t column;

    Loc() {}
    Loc(uint32_t line, uint32_t column) : line(line), column(column) {}
    Loc(const clang::FullSourceLoc &full_loc);

    friend std::ostream &operator<<(std::ostream &os, const Loc &loc) {
        os << loc.line << ":" << loc.column;
        return os;
    }

    Loc adjust_line(uint32_t line_offset) const {
        return Loc(line + line_offset, column);
    }

    bool operator==(const Loc &other) const {
        return line == other.line && column == other.column;
    }

    bool operator<(const Loc &other) const {
        return std::tie(line, column) < std::tie(other.line, other.column);
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<Loc, lava::Loc>("Loc");
        lava::Loc p;
        p.set_line(this->line);
        p.set_column(this->column);
    }
};

#pragma db value
struct ASTLoc {
    std::string filename;
    Loc begin;
    Loc end;

    ASTLoc() {}
    ASTLoc(std::string filename, Loc begin, Loc end) :
        filename(filename), begin(begin), end(end) {}

    explicit ASTLoc(std::string serialized) {
        std::vector<std::string> components;
        std::istringstream iss(serialized);
        for (std::string item; std::getline(iss, item, ':');) {
            components.push_back(item);
        }
        begin = Loc(std::stol(components[0]), std::stol(components[1]));
        end = Loc(std::stol(components[2]), std::stol(components[3]));
        filename = components[4];
    }
    operator std::string() const {
        std::stringstream os;
        os << *this;
        return os.str();
    }

    friend std::ostream &operator<<(std::ostream &os, const ASTLoc &loc) {
        os << loc.begin << ":" << loc.end << ":" << loc.filename;
        return os;
    }

    ASTLoc adjust_line(uint32_t line_offset) const {
        return ASTLoc(filename,
                begin.adjust_line(line_offset),
                end.adjust_line(line_offset));
    }

    bool operator==(const ASTLoc &other) const {
        return std::tie(begin, end, filename)
            == std::tie(other.begin, other.end, other.filename);
    }

    bool operator<(const ASTLoc &other) const {
        return std::tie(begin, end, filename)
            < std::tie(other.begin, other.end, other.filename);
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<ASTLoc, lava::ASTLoc>("ASTLoc");
        lava::ASTLoc p;
        p.set_filename(this->filename);
        this->begin.__enforce_proto();
        this->end.__enforce_proto();
    }
};

// Standard left-closed, right-open range.
#pragma db value
struct Range {
    uint32_t low;
    uint32_t high;

    operator std::string() const {
        std::stringstream os;
        os << *this;
        return os.str();
    }

    friend std::ostream &operator<<(std::ostream &os, const Range &r) {
        os << "[" << r.low << ", " << r.high << "]";
        return os;
    }

    bool operator==(const Range &other) const {
        return std::tie(low, high) == std::tie(other.low, other.high);
    }

    bool operator<(const Range &other) const {
        return std::tie(low, high) < std::tie(other.low, other.high);
    }

    inline uint32_t size() const { return high - low; }
    inline bool empty() const { return high <= low; }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<Range, lava::Range>("Range");
        lava::Range p;
        p.set_low(this->low);
        p.set_high(this->high);
    }
};


#pragma db object
struct SourceLval {
#pragma db id auto
    uint64_t id;

    ASTLoc loc;

    std::string ast_name;

    uint32_t len_bytes;

#pragma db index("SourceLvalUniq") unique members(loc, ast_name)

    bool operator<(const SourceLval &other) const {
        return std::tie(loc, ast_name) <
            std::tie(other.loc, other.ast_name);
    }

    friend std::ostream &operator<<(std::ostream &os, const SourceLval &m) {
        os << "Lval [" << m.loc.filename << " " << m.loc.begin << " ";
        os << "\"" << m.ast_name << "\"]";
        return os;
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<SourceLval, lava::SourceLval>("SourceLval");
        lava::SourceLval p;
        p.set_id(this->id);
        p.set_ast_name(this->ast_name);
        p.set_len_bytes(this->len_bytes);
        this->loc.__enforce_proto();
    }
};

#pragma db object
struct LabelSet {
#pragma db id auto
    uint64_t id;

    uint64_t ptr;           // Pointer to labelset during taint run
    std::string inputfile;  // Inputfile used for this run.

    std::vector<uint32_t> labels;

#pragma db index("LabelSetUniq") unique members(ptr, inputfile)

    bool operator<(const LabelSet &other) const {
        return std::tie(ptr, inputfile, labels) <
            std::tie(other.ptr, other.inputfile, other.labels);
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<LabelSet, lava::LabelSet>("LabelSet");
        lava::LabelSet p;
        p.set_id(this->id);
        p.set_ptr(this->ptr);
        p.set_inputfile(this->inputfile);
        p.add_labels(0);
    }
};

#pragma db object
struct Dua {
#pragma db id auto
    uint64_t id;

#pragma db not_null
    const SourceLval* lval;

    // Labelset for each byte, in sequence, at shoveling point.
    std::vector<const LabelSet*> viable_bytes;
    std::vector<uint32_t> byte_tcn;

    // Union of labelsets in viable_bytes.
    std::vector<uint32_t> all_labels;

    // Inputfile used when this dua appeared.
    std::string inputfile;

    // max tcn of any byte of this lval
    uint32_t max_tcn;
    // max cardinality of taint set for lval
    uint32_t max_cardinality;

    uint64_t instr;     // instr count
    bool fake_dua;      // true iff this dua is fake (corresponds to untainted bytes)

#pragma db index("DuaUniq") unique members(lval, inputfile, instr, fake_dua)

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
         return std::tie(lval->id, inputfile, instr, fake_dua) <
             std::tie(other.lval->id, other.inputfile, other.instr,
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
        os << "}]," << dua.max_tcn;
        os << "," << dua.max_cardinality << "," << dua.instr;
        os << "," << (dua.fake_dua ? "fake" : "real");
        os << "]";
        return os;
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<Dua, lava::Dua>("Dua");
        lava::Dua p;
        p.set_id(this->id);
        if (this->lval) {
            this->lval->__enforce_proto();
        }
        for (auto ls : this->viable_bytes) {
            if (ls) {
                ls->__enforce_proto();
            }
        }
        p.add_byte_tcn(0);
        p.add_all_labels(0);
        p.set_inputfile(this->inputfile);
        p.set_max_tcn(this->max_tcn);
        p.set_max_cardinality(this->max_cardinality);
        p.set_instr(this->instr);
        p.set_fake_dua(this->fake_dua);
    }
};

#pragma db object
struct DuaBytes {
#pragma db id auto
    uint64_t id;

#pragma db not_null
    const Dua *dua;

    // Selected bytes.
    Range selected;

#pragma db not_null
    std::vector<uint32_t> all_labels;

#pragma db index("DuaBytesUniq") unique members(dua, selected)

    DuaBytes() {}
    DuaBytes(const Dua *dua, Range selected) : dua(dua), selected(selected) {
        assert(selected.low <= selected.high);
        assert(selected.high <= dua->viable_bytes.size());
        const auto &viable_bytes = dua->viable_bytes;
        auto it = viable_bytes.cbegin() + selected.low;
        auto end = viable_bytes.cbegin() + selected.high;
        for (; it != end; it++) {
            const LabelSet *ls = *it;
            merge_into(ls->labels.begin(), ls->labels.end(), all_labels);
        }
    }

    bool operator<(const DuaBytes &other) const {
        return std::tie(dua->id, selected) <
            std::tie(other.dua->id, other.selected);
    }

    friend std::ostream &operator<<(std::ostream &os, const DuaBytes &dua_bytes) {
        os << "DUABytes " << dua_bytes.selected << " of " << *dua_bytes.dua;
        return os;
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<DuaBytes, lava::DuaBytes>("DuaBytes");
        lava::DuaBytes p;
        p.set_id(this->id);
        if (this->dua) {
            this->dua->__enforce_proto();
        }
        this->selected.__enforce_proto();
        p.add_all_labels(0);
    }
};

#pragma db object
struct AttackPoint {
#pragma db id auto
    uint64_t id;

    ASTLoc loc;

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

    bool operator<(const AttackPoint &other) const {
        return std::tie(type, loc) <
            std::tie(other.type, other.loc);
    }

    operator std::string() const {
        std::stringstream os;
        os << *this;
        return os.str();
    }

    friend std::ostream &operator<<(std::ostream &os, const AttackPoint &m) {
        constexpr const char *names[TYPE_END] = {
            "ATP_FUNCTION_ARG",
            "ATP_POINTER_READ",
            "ATP_POINTER_WRITE",
            "ATP_QUERY_POINT",
            "ATP_PRINTF_LEAK",
            "ATP_MALLOC_OFF_BY_ONE"
        };
        os << "ATP [" << m.loc.filename << " " << m.loc.begin << "] {";
        os << names[m.type] << "}";
        return os;
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<AttackPoint, lava::AttackPoint>("AttackPoint");
        lava::AttackPoint p;
        p.set_id(this->id);
        this->loc.__enforce_proto();
        p.set_type(static_cast<lava::AttackPoint::AtpKind>(this->type));
    }
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

    static constexpr uint32_t const num_extra_duas[] = {
        [PTR_ADD] = 0,
        [RET_BUFFER] = 1,
        [REL_WRITE] = 2,
	[PRINTF_LEAK] = 0,
        [MALLOC_OFF_BY_ONE] = 0,
    };

#pragma db not_null
    const DuaBytes* trigger;
#pragma db not_null
    const SourceLval* trigger_lval; // == trigger->dua->lval

#pragma db not_null
    const AttackPoint* atp;

    uint64_t max_liveness;

    // Possible exploit pad for ret-eax bugs.
    // Distance and value change for relative-write style bugs.
    // empty otherwise.
    // Actually id's of DuaBytes.
    std::vector<uint64_t> extra_duas;

    uint32_t magic;

#pragma db index("BugUniq") unique members(type, atp, trigger_lval)
#pragma db index("BugLvalsQuery") members(atp, type)

    Bug() {}
    Bug(Type type, const DuaBytes *trigger, uint64_t max_liveness,
            const AttackPoint *atp, std::vector<uint64_t> extra_duas)
        : id(0), type(type), trigger(trigger), trigger_lval(trigger->dua->lval),
            atp(atp), max_liveness(max_liveness), extra_duas(extra_duas),
            magic(0) {
        for (int i = 0; i < 4; i++) {
            magic <<= 8;
            magic |= rand() % 26 + 0x60;
            magic ^= rand() & 0x20; // maybe flip case
        }
    }

    Bug(Type type, const DuaBytes *trigger, uint64_t max_liveness,
            const AttackPoint *atp, std::vector<const DuaBytes *> extra_duas_)
        : Bug(type, trigger, max_liveness, atp, std::initializer_list<uint64_t>({})) {
        for (const DuaBytes *dua_bytes : extra_duas_) {
            extra_duas.push_back(dua_bytes->id);
        }
    }

    friend std::ostream &operator<<(std::ostream &os, const Bug &bug) {
        os << "Bug:\n        " << *bug.trigger << "\n        " << *bug.atp;
        return os;
    }

    // this logic is complicated.  TODO: understand/fix this
    // magic for kt has to be 2 bytes and we could
    // can either be (LAVA - id) & 0xffff
    // or (LAVA & 0xffff) - id
    // the second way seems like a better solution for id's greater than
    // LAVA & 0xffff because we get wrap around that still create unique
    // magic values
    inline uint16_t magic_kt() const {
        return (uint16_t) magic;
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<Bug, lava::Bug>("Bug");
        lava::Bug p;
        p.set_id(this->id);
        p.set_type(static_cast<lava::Bug::BugKind>(this->type));
        if (this->trigger) {
            this->trigger->__enforce_proto();
        }
        if (this->trigger_lval) {
            this->trigger_lval->__enforce_proto();
        }
        if (this->atp) {
            this->atp->__enforce_proto();
        }
        p.set_max_liveness(this->max_liveness);
        p.add_extra_duas(0);
        p.set_magic(this->magic);
    }
};

#pragma db view object(Bug) \
    query((?) + "ORDER BY" + Bug::trigger_lval, distinct)
struct BugLval {
    uint64_t trigger_lval;
};

#pragma db object
struct Build {
#pragma db id auto
    uint64_t id;

#pragma db value_not_null
    // Bugs that were inserted into this build
    std::vector<const Bug*> bugs;

    std::string output;    // path to executable
    bool compile;           // did the build compile?

    bool operator<(const Build &other) const {
        return std::tie(bugs, output, compile) <
            std::tie(other.bugs, other.output, other.compile);
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<Build, lava::Build>("Build");
        lava::Build p;
        p.set_id(this->id);
        for (const Bug *bug : this->bugs) {
            bug->__enforce_proto();
        }
        p.set_output(this->output);
        p.set_compile(this->compile);
    }
};

#pragma db object
struct Run {
#pragma db id auto
    uint64_t id;

#pragma db not_null
    const Build* build;
    const Bug* fuzzed;      // was this run on fuzzed or orig input?
    int exitcode;           // exit code of program
    std::string output;     // output of program
    bool success;           // true unless python script failed somehow.
    bool validated;         // true if bug successfully triggered by inject.py

    bool operator<(const Run &other) const {
        return std::tie(build->id, fuzzed->id, exitcode, output, success) <
            std::tie(other.build->id, other.fuzzed->id, other.exitcode,
                    other.output, other.success);
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<Run, lava::Run>("Run");
        lava::Run p;
        p.set_id(this->id);
        this->build->__enforce_proto();
        this->fuzzed->__enforce_proto();
        p.set_exitcode(this->exitcode);
        p.set_output(this->output);
        p.set_success(this->success);
        p.set_validated(this->validated);
    }
};

#pragma db object
struct SourceFunction {
#pragma db id auto
    uint64_t id;

    ASTLoc loc;
    std::string name;       // Function name

#pragma db index("SourceFunctionUniq") unique members(loc, name)

    bool operator<(const SourceFunction &other) const {
        return std::tie(loc, name) <
            std::tie(other.loc, other.name);
    }

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        lava::SourceFunction p;
        p.set_id(this->id);
        this->loc.__enforce_proto();
        p.set_name(this->name);
    }
};

#pragma db object
struct Call {
#pragma db id auto
    uint64_t id;

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

    // SCHEMA ENFORCEMENT:
    // This function will cause a COMPILE ERROR, letting you know the schemas are out of sync.
    void __enforce_proto() const {
        enforce_name_match<Call, lava::Call>("Call");
        lava::Call p;
        p.set_id(this->id);
        p.set_call_instr(this->call_instr);
        p.set_ret_instr(this->ret_instr);
        this->called_function->__enforce_proto();
        p.set_callsite_file(this->callsite_file);
        p.set_callsite_line(this->callsite_line);
    }
};
#endif
