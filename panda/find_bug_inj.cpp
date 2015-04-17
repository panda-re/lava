/*
  NB: env variable PANDA points to git/panda
  
  g++ -g -o fbi          \
  lava_find_bug_inj.cpp                   \
  ../../panda/qemu/panda/pandalog.c       \
  ../../panda/qemu/panda/pandalog.pb-c.c  \
  -L/usr/local/lib -lprotobuf-c                  \
  -I ../../panda/qemu -I ../../panda/qemu/panda  \
  -lz -D PANDALOG_READER  -std=c++11  -O2
  
  0.5 means max liveness of any byte on extent is 0.5
  10 means max taint compute number of any byte on extent is 10
  4 means max card of a taint labelset on any byte on extent is 4
  1 1000 means extents must be between 1 and 1000 bytes long
  
  ./fbi /nas/tleek/lava/results/dd-pcap-5000.pandalog ufilenames ulvals uattackpoints 0.5 10 4 1 1000 

*/

#define __STDC_FORMAT_MACROS

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <sstream>

#include "pandalog.h"

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


std::map<uint32_t,std::string> ind2fn;
std::map<uint32_t,std::string> ind2lvaln;
std::map<uint32_t,std::string> ind2apn;


typedef struct dua_struct {
    uint32_t filename;
    Line line;
    uint32_t lvalname;
    std::set < Label > labels;   
    std::string str() const {
        std::stringstream crap1;
        crap1 << ind2fn[filename] << "," << line << "," << ind2lvaln[lvalname] << ",[";
        for ( auto l : labels ) {
            crap1 << l << ",";
        }
        crap1 << "]";
        return crap1.str();
    }    
    bool operator<(const struct dua_struct &other) const {
        if (filename < other.filename) return true;
        else {
            if (filename > other.filename) return false;
            else {
                // filenames equal
                if (line < other.line) return true;
                else {
                    if (line > other.line) return false;
                    else {
                        // filename & line equal
                        if (lvalname < other.lvalname) return true;
                        else {
                            if (lvalname > other.lvalname) return false;
                            else {
                                // filename, line, and lvalname equal
                                return (labels < other.labels);
                            }
                        }
                    }
                }
            }
        }
        return true;
    }
} Dua;

typedef struct attack_point_struct {
    uint32_t filename;
    Line line;
    uint32_t info;
    std::string str() const {
        std::stringstream crap1;
        crap1 << ind2fn[filename] << "," << line << "," << ind2apn[info];
        return crap1.str();
    }
    bool operator<(const struct attack_point_struct &other) const {
        if (filename < other.filename) return true;
        else {
            if (filename > other.filename) return false;
            else {
                // filenames equal
                if (line < other.line) return true;
                else {
                    if (line > other.line) return false;
                    else {
                        // filename & line equal
                        return (info < other.info);
                    }
                }
            }
        }
        return true;
    }
} AttackPoint;


typedef std::pair < Dua, AttackPoint > Bug;


Instr last_instr_count;

void get_last_instr(char *pandalog_filename) {
    printf ("Computing dua and ap stats\n");
    pandalog_open(pandalog_filename, "r");
    while (1) {
        Panda__LogEntry *ple = pandalog_read_entry();
        if (ple == NULL) break;
        if (ple->instr != -1) {
            last_instr_count = ple->instr;
        }
    }
    printf ("%" PRIu64 "is last instr\n", last_instr_count);
    pandalog_close();
}
    




std::map <uint32_t, float> read_dead_data(char *pandalog_filename) {
    printf ("Reading Dead data\n");
    pandalog_open(pandalog_filename, "r");
    std::map <uint32_t, float> dd;
    while (1) {
        Panda__LogEntry *ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        if (ple->n_dead_data > 0) {
            printf ("\n");
            for (Label i=0; i<ple->n_dead_data; i++) {
                dd[i] = ple->dead_data[i];
            }
        }
        panda__log_entry__free_unpacked(ple, NULL);
    }
    pandalog_close();
    return dd;
}



std::pair<float, float> update_range(float val, std::pair<float, float> range) {
    if (val < range.first) {
        range.first = val;
    }
    if (val > range.second) {
        range.second = val;
    }
    return range;
}

std::pair<uint32_t, uint32_t> update_range(uint32_t val, std::pair<uint32_t, uint32_t> range) {
    if (val < range.first) {
        range.first = val;
    }
    if (val > range.second) {
        range.second = val;
    }
    return range;
}



std::map<uint32_t,std::string> InvertDB(std::map<std::string,uint32_t> n2ind) {
    std::map<uint32_t,std::string> ind2n;
    for ( auto kvp : n2ind ) {
        ind2n[kvp.second] = kvp.first;
    }
    return ind2n;
}




int main (int argc, char **argv) {

    // panda log file
    char *plf = argv[1];

    // maps from ind -> (filename, lvalname, attackpointname)
    fn2ind = InvertDB(LoadDB(argv[2]));
    lvaln2ind = InvertDB(LoadDB(argv[3]));
    apn2ind = InvertDB(LoadDB(argv[4]));

    get_last_instr(plf);

    float max_liveness = atof(argv[5]);
    printf ("maximum liveness score of %.2f\n", max_liveness);

    uint32_t max_card = atoi(argv[6]);
    printf ("max card of taint set returned by query = %d\n", max_card);

    uint32_t max_tcn = atoi(argv[7]);
    printf ("max tcn for addr = %d\n", max_tcn);

    uint32_t extent_len_min = atoi(argv[8]);
    uint32_t extent_len_max = atoi(argv[9]);
    printf ("extent len %d..%d\n", extent_len_min, extent_len_max);

    // read in dead data (dd[label_num])
    std::map <Label, float> dd = read_dead_data(plf);
    printf ("done reading in dead data\n");

    // read taint query results and figure out which 
    // label is both available and least dead

    pandalog_open(plf, "r");
    Panda__LogEntry *ple;
    std::map <Ptr, std::set<Label> > ptr_to_set;
    uint64_t ii=0;
    Panda__SrcInfo current_si;
    Panda__TaintQueryHypercall current_tqh;
    bool in_hc = false;
    Instr hc_instr_count;
    bool in_ap = false;
    Instr ap_instr_count;
    bool current_ext_ok = false;
    bool current_si_ok = false; 
    uint32_t num_ext_ok = 0;
    std::set<Label> labels;
    //    uint32_t data[32];
    std::pair<float, float> liveness_range;
    std::pair<Tcn, Tcn> tcn_range, card_range;
    bool seen_first_tq = false;
    std::set < Dua > u_dua;
    std::set < AttackPoint > u_ap;
    std::set < std::pair < Dua, AttackPoint > > injectable_bugs;
    std::map < AttackPoint, uint32_t > last_num_dua;

    std::vector <Instr> dua_instr;
    std::vector <Instr> ap_instr;
    
    while (1) {
        ii ++;
        if ((ii % 100000) == 0) {
            printf ("processed %lu of taint queries log.  %u dua.  %u ap.  %u injectable bugs\n", 
                    ii, (uint32_t) u_dua.size(), (uint32_t) u_ap.size(), (uint32_t) injectable_bugs.size());
        }

        ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        if (ple->taint_query_unique_label_set) {
            // this just maintains mapping from ptr (uint64_t) to actual set of taint labels 
            uint32_t i;
            Ptr p = ple->taint_query_unique_label_set->ptr;
            for (i=0; i<ple->taint_query_unique_label_set->n_label; i++) {
                Label l = ple->taint_query_unique_label_set->label[i];
                ptr_to_set[p].insert(l);
            }
        }        
        if (ple->src_info) {
            // save this for later.
            current_si = *(ple->src_info);
        }
        if (in_hc && ple->instr != hc_instr_count) {
            // done with current hypercall.  
            if (current_ext_ok) {
                seen_first_tq = true;
                // great -- extent we just looked at was deemed acceptable
                num_ext_ok ++;
                Dua dua = { current_si.filename, current_si.linenum, current_si.astnodename, labels };
                // keeping track of dead, uncomplicated data extents we have
                // encountered so far in the trace
                u_dua.insert(dua);
                dua_instr.push_back(hc_instr_count);
            }
            in_hc = false;
        }
        if (! in_hc) {
            if (ple->taint_query_hypercall) {
                // start of a new hypercall -- save buf / len / num tainted 
                in_hc = true;
                current_tqh = *(ple->taint_query_hypercall);
                hc_instr_count = ple->instr;
                liveness_range = std::make_pair(0.0,0.0);
                tcn_range = std::make_pair(0,0);
                card_range = tcn_range;
                current_ext_ok = false;
                if ((current_tqh.len <= extent_len_max) 
                    && (current_tqh.len >= extent_len_min)
                    && (current_tqh.num_tainted == current_tqh.len)) {
                    // length of this range matches our requirements 
                    // AND all of its bytes are tainted
                    current_ext_ok = true;                    
                }
                labels.clear();
            }
        }        
        if (ple->taint_query) {
            Panda__TaintQuery *tq = ple->taint_query;
            tcn_range = update_range(tq->tcn, tcn_range);
            card_range = update_range(ptr_to_set[tq->ptr].size(), card_range);
            /*
              for the current hypercall query for some extent, examine result
              for each query of an addr that saw tainted data.
              current extent is deemd unsuitable if any of the following are true
              1. tcn is too high (indicating this extent is too computationally distant from input)
              2. cardinality is too high (indicating too compilcated fn of input?)
              3. any of the labels associated with a byte has too high a liveness score
            */
            if ((tq->tcn > max_tcn) 
                || (ptr_to_set[tq->ptr].size() > max_card)) {
                current_ext_ok = false;
                continue;
            }
            // check for too-live data
            Ptr p = ple->taint_query->ptr;
            for ( Label l : ptr_to_set[p] ) {
                liveness_range = update_range(dd[l], liveness_range);
                if (dd[l] <= max_liveness) {               
                    labels.insert(l);
                }
                else {
                    // stop collecting labels -- this extent is unusable because some of its data is too live
                    current_ext_ok = false;                    
                    break;
                }
            }
        }
        if (in_ap && ple->instr != ap_instr_count) {
            in_ap = false;
            if (seen_first_tq) {
                // done with current attack point
                AttackPoint ap = { current_si.filename, current_si.linenum, ap_info };
                if ((u_ap.count(ap) == 0)
                    || (last_num_dua[ap] != u_dua.size())) {
                    // new attack point 
                    // OR number of dua has changed since last time we were here
                    // ok, this attack point can pair with *any* of the dead uncomplicated extents seen previously
                    for ( auto dua : u_dua ) {
                        Bug bug = std::make_pair(dua, ap);
                        injectable_bugs.insert(bug);
                    }
                    u_ap.insert(ap);
                    last_num_dua[ap] = u_dua.size();
                }
                ap_instr.push_back(ap_instr_count);
            }
        }
        if (!in_ap && ple->attack_point) {
            in_ap = true;
            ap_instr_count = ple->instr;
            ap_info = ple->attack_point->info;
        }                    
        
    }
    pandalog_close();



    printf ("%u dead-uncomplicated-available-data.  %u attack-points\n",
            (uint32_t) u_dua.size(), (uint32_t) u_ap.size());

    printf ("%u injectable bugs\n", (uint32_t) injectable_bugs.size());
    
    
    std::map < Dua, uint32_t > dua_ind;
    uint32_t i = 0;
    std::ofstream f;
    f.open("lava.duas", std::ios::out);
    for ( auto dua : u_dua ) {
        dua_ind[dua] = i;
        f << dua.str() << "\n";
        i ++;
    }
    f.close();
    std::map < AttackPoint, uint32_t > ap_ind;
    i=0;
    f.open("lava.aps", std::ios::out);
    i = 0;
    for ( auto ap : u_ap ) {
        ap_ind[ap] = i;
        f << ap.str() << "\n";
        i ++;
    }
    f.close();
    f.open("lava.bugs", std::ios::out);
    for ( auto bug : injectable_bugs ) {
        Dua dua = bug.first;
        AttackPoint ap = bug.second;
        f << dua_ind[dua] << "," << ap_ind[ap] << "\n";
    }
    f.close();
    
    


    f.open("lavastats.duas", std::ios::out);
    for ( auto i : dua_instr ) {
        float fr = ((float) i) / last_instr_count;
        f << fr << "\n";
    }
    f.close();
    f.open("lavastats.aps", std::ios::out);
    for ( auto i : ap_instr ) {
        float fr = ((float) i) / last_instr_count;
        f << fr << "\n";
    }
    f.close();
    

}
