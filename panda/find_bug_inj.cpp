/*
  NB: env variable PANDA points to git/panda
  
  g++ -g -o fbi   find_bug_inj.cpp ../src_clang/lavaDB.cpp ../../panda/qemu/panda/pandalog.c  ../../panda/qemu/panda/pandalog.pb-c.c  -L/usr/local/lib -lprotobuf-c  -I ../../panda/qemu -I ../../panda/qemu/panda  -lz -D PANDALOG_READER  -std=c++11  -O2
  

  ml = 0.5 means max liveness of any byte on extent is 0.5
  mtcn = 10 means max taint compute number of any byte on extent is 10
  mc =4 means max card of a taint labelset on any byte on extent is 4
  min maxl  = 1 1000 means extents must be between 1 and 1000 bytes long
  
  ./fbi pandalog lavadb ml mtcn mc minl maxl

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

#include <assert.h>

#include "pandalog.h"
#include "../src_clang/lavaDB.h"

// byte offset within extent queried for taint
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


std::map<uint32_t,std::string> ind2str;


typedef struct dua_struct {
    uint32_t filename;
    Line line;
    uint32_t lvalname;
    std::set < Label > labels;   
    std::set < Offset > bytes;
    float max_liveness;
    uint32_t max_tcn;
    uint32_t max_card;
    std::string str() const {
        std::stringstream crap1;
        crap1 << ind2str[filename] << "," << line << "," << ind2str[lvalname] << ",[";
        for ( auto l : labels ) crap1 << l << ",";
        crap1 << "][";
        for ( auto b : bytes ) crap1 << b << ",";
        crap1 << "]";
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
        if (max_liveness < other.max_liveness) return true;
        if (max_liveness > other.max_liveness) return false;
        if (max_tcn < other.max_tcn) return true;
        if (max_tcn > other.max_tcn) return false;
        if (max_card < other.max_card) return true;
        if (max_card > other.max_card) return false;
        if (labels < other.labels) return true;
        if (labels > other.labels) return false;
        return bytes < other.bytes;
    }
} Dua;

typedef struct attack_point_struct {
    uint32_t filename;
    Line line;
    uint32_t info;
    std::string str() const {
        std::stringstream crap1;
        crap1 << ind2str[filename] << "," << line << "," << ind2str[info];
        return crap1.str();
    }
    bool operator<(const struct attack_point_struct &other) const {
        if (filename < other.filename) return true;
        if (filename > other.filename) return false;
        if (line < other.line) return true;
        if (line > other.line) return false;
        return (info < other.info);
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


std::map<uint32_t,std::string> LoadIDB(std::string fn) {
    std::string sfn = std::string(fn);
    std::map<std::string,uint32_t> x = LoadDB(sfn);
    return InvertDB(x);
}



int main (int argc, char **argv) {

    // panda log file
    char *plf = argv[1];

    // maps from ind -> (filename, lvalname, attackpointname)
    ind2str = LoadIDB(argv[2]);
    printf ("%d strings in lavadb\n", (int) ind2str.size());
    
    get_last_instr(plf);

    float max_liveness = atof(argv[3]);
    printf ("maximum liveness score of %.2f\n", max_liveness);

    uint32_t max_card = atoi(argv[4]);
    printf ("max card of taint set returned by query = %d\n", max_card);

    uint32_t max_tcn = atoi(argv[5]);
    printf ("max tcn for addr = %d\n", max_tcn);

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
    bool seen_first_tq = false;
    std::set < Dua > u_dua;
    std::set < AttackPoint > u_ap;
    std::set < std::pair < Dua, AttackPoint > > injectable_bugs;
    std::map < AttackPoint, uint32_t > last_num_dua;

    std::vector <Instr> dua_instr;
    std::vector <Instr> ap_instr;
    uint32_t ap_info;
    std::set <Offset> ok_bytes;
    float c_max_liveness;
    uint32_t c_max_tcn, c_max_card;

    uint32_t num_queried_extents = 0;

    while (1) {
        ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        ii ++;
        if ((ii % 10000) == 0) {
            printf ("processed %lu of taint queries log.  %u dua.  %u ap.  %u injectable bugs\n", 
                    ii, (uint32_t) u_dua.size(), (uint32_t) u_ap.size(), (uint32_t) injectable_bugs.size());
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
        if (!in_hc) {
            if (ple->taint_query_hypercall) {
                // hypercall taint query on some exent
                // -- save buf / len / num tainted 
                // subsequent ple->taint_query entries will 
                // be details
                in_hc = true;
                num_queried_extents ++;
                current_tqh = *(ple->taint_query_hypercall);
                hc_instr_count = ple->instr;
                ok_bytes.clear();
                labels.clear();
                c_max_liveness = 0.0;
                c_max_tcn = c_max_card = 0;
                printf ("query %d bytes -- ", current_tqh.len);
            }
        }
        if (ple->taint_query) {
            Panda__TaintQuery *tq = ple->taint_query;
            // this tells us what byte in the extent this query was for
            uint32_t offset = tq->offset;
            /*
              this taint query is for a byte on the current extent under consideration
              We will decide that this byte is useable iff
              1. tcn is low enough (indicating that this byte is not too computationally distant from input)
              2. cardinality is low enough (indicating this byte not too compilcated a fn of inpu?)
              3. none of the labels in this byte's taint label set has a liveness score that is too high
            */            
            bool current_byte_ok = true;
            if ((tq->tcn <= max_tcn) 
                &&  (ptr_to_set[tq->ptr].size() <= max_card)) {
                if (tq->tcn > c_max_tcn) c_max_tcn = tq->tcn;
                if (ptr_to_set[tq->ptr].size() > c_max_card) c_max_card = ptr_to_set[tq->ptr].size();
                // check for too-live data on any label this byte derives form
                Ptr p = ple->taint_query->ptr;
                for ( Label l : ptr_to_set[p] ) {
                    if (dd[l] > max_liveness) {
                        current_byte_ok = false;
                        break;
                    }
                    // collect set of labels for the entire extent
                    if (dd[l] > c_max_liveness) c_max_liveness = dd[l];
                    labels.insert(l);       
                }
            }            
            if (current_byte_ok) {
                // add this byte to the list of ok bytes
                ok_bytes.insert(offset);
            }
        }
        if (in_hc && ple->instr != hc_instr_count) {
            // done with current hypercall.  
            if ((ok_bytes.size() >= 1) && (labels.size() >= 1)) {
                printf ("%d ok\n", ok_bytes.size());
                // at least one byte on this extent is ok
                seen_first_tq = true;
                // great -- extent we just looked at was deemed acceptable
                num_ext_ok ++;
                Dua dua = { current_si.filename, current_si.linenum, current_si.astnodename, labels, ok_bytes, c_max_liveness, c_max_tcn, c_max_card };
                // keeping track of dead, uncomplicated data extents we have
                // encountered so far in the trace
                u_dua.insert(dua);
                dua_instr.push_back(hc_instr_count);
            }
            else {
                printf ("discarded\n");
            }
            in_hc = false;
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

    printf ("%u queried extents\n", num_queried_extents);

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
