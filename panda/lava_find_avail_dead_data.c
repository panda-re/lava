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



int main (int argc, char **argv) {

    // read in dead data 
    std::map <uint32_t, float> dd = read_dead_data(argv[1]);
    printf ("done reading in dead data\n");

    // read taint query results and figure out which 
    // label is both available and least dead

    pandalog_open(argv[2], "r");
    Panda__LogEntry *ple;
    std::map <uint64_t, std::set<uint32_t> > ptr_to_set;
    std::set <uint32_t> avail_data;
    uint64_t ii=0;
    while (1) {
        ii ++;
        if ((ii % 10000) == 0) {
            printf ("processed %d of taint queries log\n", ii);
        }

        ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        if (ple->taint_query_unique_label_set) {
            //            printf (" taint query unqiue label set: ptr=%llu labels: ", ple->taint_query_unique_label_set->ptr);
            uint32_t i;
            for (i=0; i<ple->taint_query_unique_label_set->n_label; i++) {
                ptr_to_set[ple->taint_query_unique_label_set->ptr].insert(ple->taint_query_unique_label_set->label[i]);
            }
        }        
        if (ple->taint_query) {
            for ( auto el : ptr_to_set[ple->taint_query->ptr] ) {
                avail_data.insert(el);
            }
        }
    }
    pandalog_close();

    for ( auto el : avail_data ) {
        printf ("avail %d %.2f\n", el, dd[el]);
    }
}
