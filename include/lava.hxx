#ifndef __LAVA_HXX__
#define __LAVA_HXX__
#include <string>
#include <set>
#include <vector>
#include <cstdint>
#include <memory>
#include <tuple>

#include <odb/core.hxx>

#pragma db object
struct SourceLval { // was DuaKey
#pragma db id auto
    unsigned long id;

    std::string file;
    uint32_t line;
    std::string ast_name;   // AST node definition.

    // When did we see taint?
    enum Timing {
        BEFORE_OCCURRENCE,
        AFTER_OCCURRENCE
    } timing;

    std::set<uint32_t> selected_bytes;

    bool operator<(const SourceLval &other) const {
        return std::tie(file, line, ast_name, timing, selected_bytes) <
            std::tie(other.file, other.line, other.ast_name, other.timing,
                    other.selected_bytes);
    }

    friend class odb::access;
};

#pragma db object
struct LabelSet {
#pragma db id auto
    unsigned long id;

    uint64_t ptr;           // Pointer to labelset during taint run
    std::string inputfile;  // Inputfile used for this run.

    std::set<uint32_t> labels;

    bool operator<(const LabelSet &other) const {
        return std::tie(ptr, inputfile, labels) <
            std::tie(other.ptr, other.inputfile, other.labels);
    }

    friend class odb::access;
};

#pragma db object
struct Dua {
#pragma db id auto
    unsigned long id;

#pragma db not_null
    SourceLval* lval;

#pragma db value_not_null
    // Labelset for each byte, in sequence.
    std::vector<LabelSet*> labelsets;

    // Labels that taint dua (union of all labelsets)
    std::set<uint32_t> labels;

    // Inputfile used when this dua appeared.
    std::string inputfile;

    // max tcn of any byte of this lval
    uint32_t max_tcn;
    // max cardinality of taint set for lval
    uint32_t max_cardinality;
    // max liveness of any label in any taint set for dua
    // NB: this is at observation time.
    float max_liveness;

    uint64_t instr;     // instr count

private:
    auto to_tuple() const {
         return std::tie(lval, labelsets, labels, inputfile, max_tcn,
                 max_cardinality, max_liveness, instr);
    }
public:
    bool operator<(const Dua &other) const {
        return to_tuple() < other.to_tuple();
    }

    friend class odb::access;
};

#pragma db object
struct AttackPoint {
#pragma db id auto
    unsigned long id;

    std::string file;
    uint32_t line;

    enum Type {
        ATP_FUNCTION_CALL
    } type;

    bool operator<(const AttackPoint &other) const {
        return std::tie(file, line, type) <
            std::tie(other.file, other.line, other.type);
    }

    friend class odb::access;
};

#pragma db object
struct Bug {
#pragma db id auto
    unsigned long id;

#pragma db not_null
    AttackPoint* atp;
#pragma db not_null
    Dua* dua;

    bool operator<(const Bug &other) const {
         return std::tie(atp, dua) < std::tie(other.atp, other.dua);
    }

    friend class odb::access;
};

// Corresponds to one (Lval, )
#pragma db object
struct SourceModification {
#pragma db id auto
    unsigned long id;

#pragma db not_null
    AttackPoint* atp;
#pragma db not_null
    SourceLval* lval;

    bool operator<(const SourceModification &other) const {
         return std::tie(atp, lval) < std::tie(other.atp, other.lval);
    }

    friend class odb::access;
};

#pragma db object
struct Build {
private:
    auto to_tuple() const {
        return std::tie(bugs, binpath, compile);
    }

public:
#pragma db id auto
    unsigned long id;

#pragma db value_not_null
    // Bugs that were inserted into this build
    std::vector<Bug*> bugs;

    std::string binpath;    // path to executable
    bool compile;           // did the build compile?

    bool operator<(const Build &other) const {
         return to_tuple() < other.to_tuple();
    }

    friend class odb::access;
};

#pragma db object
struct Run {
#pragma db id auto
    unsigned long id;

#pragma db not_null
    Build* build;
    bool fuzzed;            // was this run on fuzzed or orig input?
    int exitcode;           // exit code of program
    std::string output;     // output of program
    bool success;           // true unless python script failed somehow.

private:
    auto to_tuple() const {
        return std::tie(build, fuzzed, exitcode, output, success);
    }
public:
    bool operator<(const Run &other) const {
        return to_tuple() < other.to_tuple();
    }

    friend class odb::access;
};

#pragma db object
struct SourceFunction {
#pragma db id auto
    unsigned long id;

    std::string file;       // Definition filename
    uint32_t line;          // Definition line
    std::string name;       // Function name

    bool operator<(const SourceFunction &other) const {
        return std::tie(file, line, name) <
            std::tie(other.file, other.line, other.name);
    }

    friend class odb::access;
};

#pragma db object
struct Call {
#pragma db id auto
    unsigned long id;

    uint64_t call_instr;    // Instruction count at call
    uint64_t ret_instr;     // Instruction count at ret

#pragma db not_null
    SourceFunction* called_function;
    std::string callsite_file;
    uint32_t callsite_line;

private:
    auto to_tuple() const {
        return std::tie(call_instr, ret_instr, called_function,
                callsite_file, callsite_line);
    }

public:
    bool operator<(const Call &other) const {
        return to_tuple() < other.to_tuple();
    }

    friend class odb::access;
};
#endif
