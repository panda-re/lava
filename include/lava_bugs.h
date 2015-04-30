
#ifndef __LAVA_BUGS_H__
#define __LAVA_BUGS_H__

#include <stdint.h>

#include <set>

// byte offset within lval extent queried for taint
typedef uint32_t Offset;
// instruction count
typedef uint64_t Instr;
// taint label (input byte #)
typedef uint32_t Label;
// line number
typedef uint32_t Line;
// Taint Compute Number
typedef uint32_t Tcn;
// ptr used to ref a label set
typedef uint64_t Ptr;



static std::string iset_str(std::set<uint32_t> &iset) {
    std::stringstream ss;
    uint32_t n = iset.size();
    uint32_t i=0;
    for (auto el : iset) {
        i++;
        ss << el;
        if (i != n) ss << ",";
    }
    return ss.str();
}



Class Dua {

    Dua () {};

    std::string filename;        // name of src file this dua is in
    Line line;                   // line in that src file
    std::string lvalname;        // name of the lval, i.e. x or y->f or x[i].m or ...
    std::set<Label>labels;       // byte offsets within input file that taint the dua parts of this lval
    std::set<Offset>bytes;       // offsets within this lval that are dua
    std::string input_file;      // name of input file used to discover this dua
    float max_liveness;          // max liveness of any label in any taint set associated with a dua byte of this lval
    uint32_t max_tcn;            // max tcn of any byte of this lval
    uint32_t max_card;           // max cardinality of any taint set for any byte of this lval
    uint32_t icount;             // num times this dua has been used to inject a bug
    uint32_t scount;             // num times this dua has been used to inject a bug that turned out to realy be a bug

    std::string str() const {
        std::stringstream crap1;
        crap1 << filename << ","
              << line << ","  
              << lvalname << ",";
        // offsets within the input file that taint dua
        crap1 << "{" << iset_str(labels) << "},"; 
        // offsets within the lval that are duas
        crap1 << "{" << iset_str(bytes) << "},";
        crap1 << "," << max_liveness << "," << max_tcn << "," << max_card ;
        return crap1.str();
    }    
    bool operator<(const struct dua_struct &other) const {
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
        if (labels < other.labels) return true;
        if (labels > other.labels) return false;
        return bytes < other.bytes;
    }
};



class AttackPoint {
    
    AttackPoint () {};

    std::string filename;   // src filename this attack point is in
    Line line;              // line number in that file
    std::string typ;        // name of type of attack point, i.e. "memcpy", or "malloc"

    std::string str() const {
        std::stringstream crap1;
        crap1 << filename << "," << line << "," << typ;
        return crap1.str();
    }
    bool operator<(const struct attack_point_struct &other) const {
        if (line < other.line) return true;
        if (line > other.line) return false;
        if (filename < other.filename) return true;
        if (filename > other.filename) return false;
        return (typ < other.type);
    }

};


class Bug {

    Bug () {};

    Dua dua;                 // specifies where the dead data is in the program src
    AttackPoint atp;         // specifes where that dead data might be used to create a bug
    std::string global_name;  // name of global that will provide data flow between dua and atp.
    uint32_t size;            // size of global in bytes

    std::string str() const {
        std::stringstream crap1;
        crap1 << "Dua{" << dua.str() << "}-{"<< atp.str() << "}," << global_name << "," << size;
        return crap1.str();
    }

};



#endif
