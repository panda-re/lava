/*
 NB: env variable PANDA points to git/panda
 
 g++ -g -o lfadd \
   lava_find_avail_dead_data.c \
   $PANDA/qemu/panda/pandalog.c \
   $PANDA/qemu/panda/pandalog.pb-c.c \
   -L/usr/local/lib -lprotobuf-c \
   -I $PANDA/qemu -I $PANDA/qemu/panda \
   -lz -D PANDALOG_READER  -std=c++11  -O2

 ./lfadd /nas/tleek/lava/results/dd-pcap-5000.pandalog  /nas/tleek/lava/results/qu-pcap-5000.pandalog 



*/
#define __STDC_FORMAT_MACROS

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "pandalog.h"

#include <map>
#include <set>

std::map <uint32_t, float> read_dead_data(char *pandalog_filename) {
    pandalog_open(pandalog_filename, "r");
    std::map <uint32_t, float> dd;
    while (1) {
        Panda__LogEntry *ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        if (ple->n_dead_data > 0) {
            printf ("\n");
            uint32_t i;
            for (i=0; i<ple->n_dead_data; i++) {
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



int main (int argc, char **argv) {

    char *inp = argv[1];
    char *ddf = argv[2];
    char *tqf = argv[3];

    struct stat st;
    stat(inp, &st);

    FILE *fp = fopen(inp, "r");
    uint8_t *inp_buf = (uint8_t *) malloc(st.st_size);
    int x = fread(inp_buf, 1, st.st_size, fp);    
    printf ("x=%d\n", x);

    float max_liveness = atof(argv[4]);
    printf ("maximum liveness score of %.2f\n", max_liveness);

    uint32_t max_card = atoi(argv[5]);
    printf ("max card of taint set returned by query = %d\n", max_card);

    uint32_t max_tcn = atoi(argv[6]);
    printf ("max tcn for addr = %d\n", max_tcn);

    uint32_t extent_len_min = atoi(argv[7]);
    uint32_t extent_len_max = atoi(argv[8]);
    printf ("extent len %d..%d\n", extent_len_min, extent_len_max);

    // read in dead data 
    std::map <uint32_t, float> dd = read_dead_data(ddf);
    printf ("done reading in dead data\n");

    // read taint query results and figure out which 
    // label is both available and least dead

    pandalog_open(tqf, "r");
    Panda__LogEntry *ple;
    std::map <uint64_t, std::set<uint32_t> > ptr_to_set;
    std::map <uint32_t, Panda__TaintQuery> avail_data;
    uint64_t ii=0;
    Panda__SrcInfo current_si;
    Panda__TaintQueryHypercall current_tqh;
    bool in_hc = false;
    uint64_t hc_instr_count;
    bool current_ext_ok = false;
    uint32_t num_ext_ok = 0;
    std::set<uint32_t> labels;
    uint32_t data[32];
    std::pair<float, float> liveness_range;
    std::pair<uint32_t, uint32_t> tcn_range, card_range;
    while (1) {
        ii ++;
        if ((ii % 1000000) == 0) {
            printf ("processed %lu of taint queries log. %d extents ok\n", ii, num_ext_ok);
        }

        ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        if (ple->taint_query_unique_label_set) {
            uint32_t i;
            for (i=0; i<ple->taint_query_unique_label_set->n_label; i++) {
                ptr_to_set[ple->taint_query_unique_label_set->ptr].insert(ple->taint_query_unique_label_set->label[i]);
            }
        }        
        if (ple->src_info) {
            // save this for later.
            current_si = *(ple->src_info);
        }
        if (in_hc && ple->instr != hc_instr_count) {
            // done with current hypercall.  
            if (current_ext_ok) {
                // great -- extent we just looked at was deemed acceptable
                printf ("\nFound some dead, uncomplicated data.\n  filename=[%s] astnodename=[%s] linenum=%d len=%d num_tainted=%d -- %u\n",
                        current_si.filename, 
                        current_si.astnodename,
                        current_si.linenum,
                        current_tqh.len,
                        current_tqh.num_tainted,
                        (uint32_t) labels.size());
                printf ("liveness=[%.2f,%.2f]  tcn=[%u,%u]   card=[%u,%u]\n",
                        liveness_range.first, liveness_range.second,
                        tcn_range.first, tcn_range.second,
                        card_range.first, card_range.second);
                printf ("labels:\n\t");
                for ( auto el : labels ) {
                    printf ("%u ", el);
                }
                printf ("\n");
                printf ("data corresponding to those labels:\n\t");
                for ( auto el : labels ) {                    
                    printf ("%02x ", inp_buf[el]);
                }
                printf ("\nactual data at query: \n\t");
                for ( uint32_t i=0; i<current_tqh.n_data; i++) {
                    printf ("%02x ", current_tqh.data[i]);
                }
                printf ("\n");
                num_ext_ok ++;
            }
            in_hc = false;
        }

        if (! in_hc) {
            if (ple->taint_query_hypercall) {
                // start of a new hypercall -- save buf / len / num tainted 
                current_tqh = *(ple->taint_query_hypercall);
                in_hc = true;
                hc_instr_count = ple->instr;
                current_ext_ok = false;
                liveness_range = std::make_pair(0.0,0.0);
                tcn_range = std::make_pair(0,0);
                card_range = tcn_range;
                if ((current_tqh.len <= extent_len_max) 
                    && (current_tqh.len >= extent_len_min)
                    && (current_tqh.num_tainted == current_tqh.len)) {
                    // length of this range matches our requirements 
                    // AND all of its bytes are tainted
                    current_ext_ok = true;                    
                    labels.clear();
                }
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
            for ( auto el : ptr_to_set[ple->taint_query->ptr] ) {
                liveness_range = update_range(dd[el], liveness_range);
                // and ignore data bytes that are too live
                if (dd[el] < max_liveness) {               
                    labels.insert(el);
                }
                else {
                    current_ext_ok = false;                    
                    break;
                }
            }

        }

    }
    pandalog_close();
}
