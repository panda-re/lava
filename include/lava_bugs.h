
#ifndef __LAVA_BUGS_H__
#define __LAVA_BUGS_H__

extern "C" {
    #include <stdlib.h>
    #include <stdint.h>
    #include "/usr/include/postgresql/libpq-fe.h"
    #include "panda_hypercall_struct.h"
}


#include <string>
#include <sstream>
#include <map>
#include <set>
#include <vector>
#include <tuple>

// instruction count
typedef uint64_t Instr;
// Taint Compute Number
typedef uint32_t Tcn;
// ptr used to ref a label set
typedef uint64_t Ptr;

std::string iset_str(std::set<uint32_t> &iset);
std::string pvec_str(std::vector<Ptr> &pvec);

// represents the src mod for a dua
// note that two duas can map to the same src mod
struct DuaKey {

    uint32_t filename;
    uint32_t linenum;
    uint32_t astnodename;
    uint32_t insertionpoint;
    std::set<uint32_t> lval_offsets_tainted;

    auto inline to_tuple() const {
        return std::tie(filename, linenum, astnodename, insertionpoint,
                lval_offsets_tainted);
    }

public:
    bool operator<(const DuaKey &other) const {
        return to_tuple() < other.to_tuple();
    }

    bool operator==(const DuaKey &other) const {
        return to_tuple() == other.to_tuple();
    }

};

struct Dua {

    std::string filename;                 // name of src file this dua is in
    uint32_t line;                        // line in that src file
    std::string lvalname;                 // name of the lval, i.e. x or y->f or x[i].m or ...
    uint32_t insertionpoint;              // was query before or after call?
    std::set<uint32_t> file_offsets;      // byte offsets w/in input that taint dua
    std::vector<Ptr> lval_taint;          // vector of taint set pointers, one per byte in the lval
    std::string input_file;               // name of input file used to discover this dua
    uint32_t max_tcn;                     // max tcn of any byte of this lval
    uint32_t max_card;                    // max cardinality of taint set for lval
    float max_liveness;                   // max liveness of any label in any taint set for dua
    uint32_t icount;                      // num times this dua has been used to inject a bug
    uint32_t scount;                      // num times this dua has been used to inject a bug that turned out to realy be a bug
    uint64_t instr;                       // instr count

    auto inline to_tuple() const {
        return std::tie(filename, line, lvalname, insertionpoint, input_file,
                max_liveness, max_tcn, max_card, icount, scount, instr,
                file_offsets, lval_taint);
    }

public:
    std::string str() {
        std::stringstream ss;
        ss << "DUA ["
           << filename << ","
           << line << ","
           << insertionpoint << ","
           << lvalname << ",";
        // offsets within the input file that taint dua
        ss << "{" << iset_str(file_offsets) << "},";
        // offsets within the lval that are duas
        ss << "{" << pvec_str(lval_taint) << "}";
        ss << "," << max_liveness << "," << max_tcn << "," << max_card ;
        ss << "," << instr;
        ss << "]";
        return ss.str();
    }

    bool operator<(const Dua &other) const {
        return to_tuple() < other.to_tuple();
    }

    bool operator==(const Dua &other) const {
        return to_tuple() == other.to_tuple();
    }

};

struct AttackPointKey {
    uint32_t filename;
    uint32_t line;
    uint32_t typ;

    auto inline to_tuple() const { return std::tie(filename, line, typ); }

public:
    bool operator<(const AttackPointKey &other) const {
        return to_tuple() < other.to_tuple();
    }

    bool operator==(const AttackPointKey &other) const {
        return to_tuple() == other.to_tuple();
    }

};

struct AttackPoint {

    std::string filename;   // src filename this attack point is in
    uint32_t line;          // line number in that file
    std::string typ;        // name of type of attack point, i.e. "memcpy", or "malloc"
    std::string input_file;
    uint32_t icount;
    uint32_t scount;

    auto inline to_tuple() const {
        return std::tie(filename, line, typ, input_file, icount, scount);
    }

public:
    bool operator<(const AttackPoint &other) const {
        return to_tuple() < other.to_tuple();
    }

    bool operator==(const AttackPoint &other) const {
        return to_tuple() == other.to_tuple();
    }

    std::string str() {
        std::stringstream ss;
        ss << "ATP [";
        ss << filename << "," << line << "," << typ << "," << input_file << "," << icount << "," << scount;
        ss << "]";
        return ss.str();
    }

};

struct BugKey {
    DuaKey dk;
    AttackPointKey atpk;

    bool operator<(const BugKey &other) const {
        return std::tie(dk, atpk) < std::tie(other.dk, other.atpk);
    }

    bool operator==(const BugKey &other) const {
        return std::tie(dk, atpk) == std::tie(other.dk, other.atpk);
    }

};

struct Bug {
    uint32_t id;
    Dua dua;                 // specifies where the dead data is in the program src
    AttackPoint atp;         // specifes where that dead data might be used to create a bug
    std::string global_name;  // name of global that will provide data flow between dua and atp.
    uint32_t size;            // size of global in bytes

    auto inline to_tuple() const { return std::tie(dua, atp, global_name, size); }

public:
    std::string str() {
        std::stringstream ss;
        ss << "BUG [";
        ss << dua.str() << atp.str() << "," << global_name << "," << size;
        ss << "]";
        return ss.str();
    }

    bool operator<(const Bug &other) const {
        return to_tuple() < other.to_tuple();
    }

    bool operator==(const Bug &other) const {
        return to_tuple() == other.to_tuple();
    }

};


PGconn *pg_connect(std::string dbhost, std::string dbname);

void exit_nicely(PGconn *conn);

// execute query on db via postgresql connection conn
PGresult *pg_exec(PGconn *conn, std::string query);

// samle but uses the more convenient stringstream
PGresult *pg_exec_ss(PGconn *conn, std::stringstream &query);

/*
 assumes table named tablename is in the postgresql db.
 that table has two columns.  first is integer ids.
 second is strings corresponding to thos ids.
 this fn reads that info into a int->string map and returns it
*/
std::map < uint32_t, std::string > pq_get_string_map(PGconn *conn, std::string tablename);

std::set<uint32_t> parse_ints(std::string offs_str);

std::map<Ptr, std::set<uint32_t>> loadTaintSets(PGconn *conn);

// load this set of bugs out of the db given their ids
std::set<Bug> loadBugs(std::set<uint32_t> &bug_ids, PGconn *conn);


#endif
