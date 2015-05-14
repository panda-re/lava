
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


// instruction count
typedef uint64_t Instr;
// Taint Compute Number
typedef uint32_t Tcn;
// ptr used to ref a label set
typedef uint64_t Ptr;



std::string iset_str(std::set<uint32_t> &iset);



struct Dua {    

    std::string filename;               // name of src file this dua is in
    uint32_t line;                          // line in that src file
    std::string lvalname;               // name of the lval, i.e. x or y->f or x[i].m or ...
    std::set<uint32_t> file_offsets;  // byte offsets within input file that taint the dua parts of this lval
    std::set<uint32_t> lval_offsets;  // offsets within this lval that are dua
    std::string input_file;             // name of input file used to discover this dua
    float max_liveness;                 // max liveness of any label in any taint set for dua
    uint32_t max_tcn;                   // max tcn of any byte of this lval
    uint32_t max_card;                  // max cardinality of any taint set for any byte of this lval
    uint32_t icount;                    // num times this dua has been used to inject a bug
    uint32_t scount;                    // num times this dua has been used to inject a bug that turned out to realy be a bug

    std::string str() {
        std::stringstream ss;
        ss << "DUA [" 
           << filename << ","
           << line << ","  
           << lvalname << ",";
        // offsets within the input file that taint dua
        ss << "{" << iset_str(file_offsets) << "},"; 
        // offsets within the lval that are duas
        ss << "{" << iset_str(lval_offsets) << "}";
        ss << "," << max_liveness << "," << max_tcn << "," << max_card ;
        ss << "]";
        return ss.str();
    }    

    bool operator<(const Dua &other) const {
        if (filename < other.filename) return true;
        if (filename > other.filename) return false;
        if (line < other.line) return true;
        if (line > other.line) return false;
        if (lvalname < other.lvalname) return true;
        if (lvalname > other.lvalname) return false;
        if (input_file < other.input_file) return true;
        if (input_file > other.input_file) return false;        
        if (max_liveness < other.max_liveness) return true;
        if (max_liveness > other.max_liveness) return false;
        if (max_tcn < other.max_tcn) return true;
        if (max_tcn > other.max_tcn) return false;
        if (max_card < other.max_card) return true;
        if (max_card > other.max_card) return false;
        if (icount < other.icount) return true;
        if (icount > other.icount) return false;
        if (scount < other.scount) return true;
        if (scount > other.scount) return false;
        if (file_offsets < other.file_offsets) return true;
        if (file_offsets > other.file_offsets) return false;
        return lval_offsets < other.lval_offsets;
    }

    bool operator==(const Dua &other) const {
        return ((filename == other.filename) 
                && (line == other.line) 
                && (lvalname == other.lvalname) 
                && (input_file == other.input_file) 
                && (max_liveness == other.max_liveness) 
                && (max_tcn == other.max_tcn) 
                && (max_card == other.max_card) 
                && (icount == other.icount) 
                && (scount == other.scount) 
                && (file_offsets == other.file_offsets) 
                && (lval_offsets == other.lval_offsets));
    }

};



struct AttackPoint {

    std::string filename;   // src filename this attack point is in
    uint32_t linenum;              // line number in that file
    std::string typ;        // name of type of attack point, i.e. "memcpy", or "malloc"
    std::string input_file; 
    uint32_t icount;
    uint32_t scount;

    std::string str() {
        std::stringstream ss;
        ss << "ATP [";
        ss << filename << "," << linenum << "," << typ << "," << input_file << "," << icount << "," << scount;
        ss << "]";
        return ss.str();
    }

    bool operator<(const AttackPoint &other) const {
        if (linenum < other.linenum) return true;
        if (linenum > other.linenum) return false;
        if (filename < other.filename) return true;
        if (filename > other.filename) return false;
        if (typ < other.typ) return true;
        if (typ > other.typ) return false;
        if (input_file < other.input_file) return true;
        if (input_file > other.input_file) return false;
        if (icount < other.icount) return true;
        if (icount > other.icount) return false;
        return (scount < other.scount);
    }

    bool operator==(const AttackPoint &other) const {
        return ((linenum == other.linenum) 
                && (filename == other.filename) 
                && (typ == other.typ)
                && (input_file == other.input_file)
                && (icount == other.icount)
                && (scount == other.scount));
    }
    
};


struct Bug {
    uint32_t id;
    Dua dua;                 // specifies where the dead data is in the program src
    AttackPoint atp;         // specifes where that dead data might be used to create a bug
    std::string global_name;  // name of global that will provide data flow between dua and atp.
    uint32_t size;            // size of global in bytes

    std::string str() {
        std::stringstream ss;
        ss << "BUG [";
        ss << dua.str() << atp.str() << "," << global_name << "," << size;
        ss << "]";
        return ss.str();
    }
    
    bool operator<(const Bug &other) const {
        // NB: got no > for dua & atp. make do with < & ==
        if (dua < other.dua) return true;
        if (!(dua == other.dua)) return false; // must be >
        if (atp < other.atp) return true;
        if (!(atp == other.atp)) return false;
        if (global_name < other.global_name) return true;
        if (global_name > other.global_name) return false;
        return (size < other.size);
    }

    bool operator==(const Bug &other) const {
        if ((dua == other.dua) 
            && (atp == other.atp) 
            && (global_name == other.global_name)  
            && (size == other.size));
    }
    
};


PGconn *pg_connect(void);

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


// load this set of bugs out of the db given their ids
std::set<Bug> loadBugs(std::set<uint32_t> &bug_ids);


#endif
