
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
    
    bool operator<(const DuaKey &other) const {
        if (filename < other.filename) return true;
        if (filename > other.filename) return false;
        if (linenum < other.linenum) return true;
        if (linenum > other.linenum) return false;
        if (astnodename < other.astnodename) return true;
        if (astnodename > other.astnodename) return false;
        if (insertionpoint < other.insertionpoint) return true;
        if (insertionpoint > other.insertionpoint) return false;
        return (lval_offsets_tainted < other.lval_offsets_tainted);
    }
    
    bool operator==(const DuaKey &other) const {
        return ((filename == other.filename)
                && (linenum == other.linenum)
                && (astnodename == other.astnodename)
                && (insertionpoint == other.insertionpoint)
                && (lval_offsets_tainted == other.lval_offsets_tainted));
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
        if (filename < other.filename) return true;
        if (filename > other.filename) return false;
        if (line < other.line) return true;
        if (line > other.line) return false;
        if (lvalname < other.lvalname) return true;
        if (lvalname > other.lvalname) return false;
        if (insertionpoint < other.insertionpoint) return true;
        if (insertionpoint > other.insertionpoint) return false;
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
        if (instr < other.instr) return true;
        if (instr > other.instr) return false;
        if (file_offsets < other.file_offsets) return true;
        if (file_offsets > other.file_offsets) return false;
        return lval_taint < other.lval_taint;
    }

    bool operator==(const Dua &other) const {
        return ((filename == other.filename) 
                && (line == other.line) 
                && (lvalname == other.lvalname) 
                && (insertionpoint == other.insertionpoint)
                && (input_file == other.input_file) 
                && (max_liveness == other.max_liveness) 
                && (max_tcn == other.max_tcn) 
                && (max_card == other.max_card) 
                && (icount == other.icount) 
                && (scount == other.scount) 
                && (instr == other.instr)
                && (file_offsets == other.file_offsets) 
                && (lval_taint == other.lval_taint));
    }

};


struct AttackPointKey {
    uint32_t filename;
    uint32_t line;
    uint32_t typ;

    bool operator<(const AttackPointKey &other) const {
        if (filename < other.filename) return true;
        if (filename > other.filename) return false;
        if (line < other.line) return true;
        if (line > other.line) return false;
        return (typ < other.typ);
    }
    
    bool operator==(const AttackPointKey &other) const {
        return ((filename == other.filename)
                && (line == other.line)
                && (typ == other.typ));
    }
        
};


struct AttackPoint {

    std::string filename;   // src filename this attack point is in
    uint32_t line;          // line number in that file
    std::string typ;        // name of type of attack point, i.e. "memcpy", or "malloc"
    std::string input_file; 
    uint32_t icount;
    uint32_t scount;

    std::string str() {
        std::stringstream ss;
        ss << "ATP [";
        ss << filename << "," << line << "," << typ << "," << input_file << "," << icount << "," << scount;
        ss << "]";
        return ss.str();
    }

    bool operator<(const AttackPoint &other) const {
        if (line < other.line) return true;
        if (line > other.line) return false;
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
        return ((line == other.line) 
                && (filename == other.filename) 
                && (typ == other.typ)
                && (input_file == other.input_file)
                && (icount == other.icount)
                && (scount == other.scount));
    }
    
};



struct BugKey {
    DuaKey dk;
    AttackPointKey atpk;

    bool operator<(const BugKey &other) const {
        if (dk < other.dk) return true;
        if (!(dk == other.dk)) return false;
        return (atpk < other.atpk);
    }

    bool operator==(const BugKey &other) const {
        return ((dk == other.dk)
                && (atpk == other.atpk));
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
        return ((dua == other.dua) 
                && (atp == other.atp) 
                && (global_name == other.global_name)  
                && (size == other.size));        
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
