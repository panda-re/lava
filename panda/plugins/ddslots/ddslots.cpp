/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
  * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <iostream>
#include <sstream>
#include <map>
#include <vector>
#include <set>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

extern "C" {

//#include "qemu/osdep.h"
//#include "cpu.h"


//#include "config.h"
#include "qemu-common.h"
#include "panda/common.h"
#include "panda/rr/rr_log.h"
#include "panda/plog.h"

#include "panda/addr.h"
}


#include "panda/plugins/taint2/taint_ops.h"

#include "panda/plugins/taint2/taint2.h"
#include "panda/plugins/taint2/taint2_ext.h"

#include "panda/plugins/libfi/libfi.h"
#include "panda/plugins/libfi/libfi_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

using namespace std; 

#define MAX_STRLEN 4096
typedef uint64_t Instr;

enum DdTrackerType { DDS_ALLOC, DDS_FREE, DDS_READ, DDS_WRITE };

struct DdTrackerInfo {
    target_ulong pc;
    Instr instr;
    target_ulong start_addr;
    uint32_t size;
    DdTrackerType type;
};    

struct Slot {
    target_ulong pc;
    target_ulong va;
    Instr start;
    Instr end;
};

set<Slot> slots;   



typedef pair<target_ulong, size_t> ObjExt;

struct InstrInterval {
    pair<Instr, Instr> interval;

    InstrInterval(const Instr i1, const Instr i2) {
        interval = make_pair(i1, i2);
    }
    
    Instr start () const {
        return interval.first;
    }

    Instr end () const {
        return interval.second;
    }

    // returns true iff other is wholly contained in this one
    bool subsumes(InstrInterval &other_interval) {
        if (other_interval.start() >= start() 
            && other_interval.end() <= end())
            return true;
        return false;
    }

    bool dont_intersect(InstrInterval &other_interval) {
        return (other_interval.start() > end()
                || start() > other_interval.end());
    }

    // returns true iff these two intervals intersect
    bool intersect(InstrInterval &other_interval) {
        return !(dont_intersect(other_interval));
    }

    void expand_to_include(InstrInterval other_interval) {
        interval.first = min(start(), other_interval.start());
        interval.second = max(end(), other_interval.end());
    }

    string str() {
        stringstream ss;
        ss << "(" << (start()) << "," << (end()) << ")";
        return ss.str();
    }

    bool operator<(const InstrInterval &other) {
        if (start() == other.start())
            return end() < other.end();
        return (start() < other.start());
    }
            

};



struct InstrIntervalSet {
    set<InstrInterval> intervals;

    void iinsert(InstrInterval new_ii) {
        // if this interval subsumed by any other interval, discard it
        for (auto ii : intervals) {
            if (ii.subsumes(new_ii)) {
                cout << "subsumed by previously seen\n";
                return;
            }
        }
        // construct interval that contains new_ii plus every other interval 
        // that intersects with it
        InstrInterval ii_intersection = new_ii;
        vector<InstrInterval> to_remove;
        for (auto ii : intervals) {
            if (ii_intersection.intersect(ii)) {
                cout << "intersects with prior\n";
                ii_intersection.expand_to_include(ii);
                to_remove.push_back(ii);
            }
        }
        intervals.insert(ii_intersection);
        for (auto ii : to_remove) {
            intervals.erase(ii);
        }
    }

    size_t size() {
        return intervals.size();
    }

    string str() {
        stringstream ss;
        ss << (size()) << " : ";
        for (auto ii : intervals) {
            ss << ii.str() << ",";
        }
        return ss.str();
    }        
    
};


InstrIntervalSet instr_intervals;

target_ulong last_asid = 0;
Instr last_instr = 0;

uint32_t next_label=1;
target_ulong asid_of_interest=0;
map<uint32_t, DdTrackerInfo*> ddtim;

map<uint32_t, uint32_t> objects;

#if defined(TARGET_I386) && !defined(TARGET_X86_64)

hwaddr check_va(CPUState *env, target_ulong va) {
    hwaddr pa = panda_virt_to_phys(env, va);
    // not actually ram
    if (pa >= ram_size) return -1;
    return pa;
}


Instr max_instr = 0;
bool taint_on = false;
uint32_t *dds_count = NULL;


// sadly we have to check and then try to do these things at first available moment we can
static inline void dynamic_setup_stuff() {
    if (!taint_on) {
        taint_on = true;
        taint2_enable_taint();
    }
    if (max_instr == 0) {
        Instr i = replay_get_total_num_instructions();
        if (i != 0) max_instr = i;
        dds_count = (uint32_t *) calloc(max_instr, sizeof(uint32_t));
    }
}

void spit_ddtracker_info(DdTrackerInfo &info) {
    printf ("ddtracker_label [pc=0x%x instr=%" PRId64 " start_addr=0x%x size=%d type=%d]\n",
            info.pc, info.instr, info.start_addr, info.size, info.type);
}

static inline uint32_t
new_ddtracker_label(CPUState *env, target_ulong pc, target_ulong start_addr, 
                    uint32_t size, DdTrackerType typ) {
    uint32_t l = next_label;
    next_label ++;
    DdTrackerInfo *info = (DdTrackerInfo *) malloc(sizeof(DdTrackerInfo));
    info->pc = pc;
    info->instr = rr_get_guest_instr_count();
    printf ("label=%d typ=%d instr=%" PRId64"\n", l, typ, info->instr);
    info->start_addr = start_addr;
    info->size = size;
    info->type = typ;
    printf ("ddtim[%d]\n", l);
    spit_ddtracker_info(*info);
    ddtim[l] = info;    
    return l;
}

static inline uint32_t
new_alloc_label(CPUState *env, target_ulong pc, target_ulong start_addr, 
                uint32_t size) {
    return new_ddtracker_label(env, pc, start_addr, size, DDS_ALLOC);
}

static inline uint32_t 
new_free_label(CPUState *env, target_ulong pc, target_ulong start_addr, 
               uint32_t size) {
    return new_ddtracker_label(env, pc, start_addr, size, DDS_FREE);
}

static inline uint32_t 
new_read_label(CPUState *env, target_ulong pc, target_ulong start_addr,
               uint32_t size) {
    return new_ddtracker_label(env, pc, start_addr, size, DDS_READ);
}

static inline uint32_t 
new_write_label(CPUState *env, target_ulong pc, target_ulong start_addr, 
                uint32_t size) {
    return new_ddtracker_label(env, pc, start_addr, size, DDS_WRITE);
}    

static inline void
label_it(CPUState *env, target_ulong start_addr, uint32_t size, uint32_t l) {
    dynamic_setup_stuff();
    cout << "label_it start_addr=0x" << hex << start_addr << dec << " size=" << size << " l=" << l << "\n";
    target_ulong end_addr = start_addr + size;
    for (target_ulong va=start_addr; va<end_addr; va++) {
        hwaddr pa = check_va(env, va);
        if (pa == -1) continue;
        if (pa != -1) taint2_label_ram(pa, l);
    }
}

static inline void 
label_alloc(CPUState *env, target_ulong pc, target_ulong start_addr,
            uint32_t size) {
    uint32_t l = new_alloc_label(env, pc, start_addr, size);
    label_it(env, start_addr, size, l);
    // do we also want to label EAX since we know it contains a ptr?
}
    
// map from object start addr to size in bytes
void add_object(target_ulong start_addr, uint32_t size) {
    objects[start_addr] = size;
}

uint32_t lookup_object(uint32_t start_addr) {
    assert (objects.count(start_addr) != 0);
    return objects[start_addr];
}

bool resolve_object(uint32_t addr) {
    printf ("%u objects. resolve_object addr=0x%x\n", (uint32_t) objects.size(), addr);
    for (auto o : objects) {
        auto start = o.first;
        auto size = o.second;
//        printf ("obj 0x%x .. 0x%x\n", start, start+size);
        if (start <= addr && addr < start+size) {
            printf (" -- found object: start=0x%x size=%u\n", start, size);
            return true;
        }
    }
    printf (" -- didnt find object.\n");
    return false;
}

void remove_object(target_ulong start_addr, uint32_t size) {
    assert (objects.count(start_addr) != 0);
    objects.erase(start_addr);
}

bool right_asid(CPUState *env) {
    return (panda_current_asid(env) == asid_of_interest);
}    

uint32_t first_label;

int get_first_label_aux(uint32_t el, void *stuff) {
    if (first_label == -1) {
        first_label = el;
    }
    // done
    return 1;
}

int get_first_label(hwaddr pa)  {
    first_label = -1;
    taint2_labelset_ram_iter(pa, get_first_label_aux, NULL);
    return first_label;
}

DdTrackerInfo *get_ddtracker_info(hwaddr pa) {
    dynamic_setup_stuff();
    if (pa >= ram_size) return NULL;;
    uint32_t card = taint2_query_ram(pa);
    // discard untainted or weird taint
    if (card == 0 || card > 1) return NULL;
    // we also require tcn = 0
    uint32_t tcn = taint2_query_tcn_ram(pa);
    if (tcn != 0) return NULL;
    // taint looks ok -- get label
    uint32_t the_label = get_first_label(pa);
    assert(the_label != -1);
    printf ("get_ddtracker_info label=%d\n", the_label);
    spit_ddtracker_info(*ddtim[the_label]);
    return ddtim[the_label];
}

#define EAX ((CPUX86State *)((CPUState *)env->env_ptr))->regs[R_EAX]


void dds_alloc(CPUState *env, target_ulong pc, target_ulong start_addr, uint32_t size) {
    cout << "dds_alloc instr=" << ( rr_get_guest_instr_count() ) << " start_addr="
         << hex << start_addr << dec << " len=" << size << "\n";
    label_alloc(env, pc, start_addr, size);
    add_object(start_addr, size);
}


bool in_malloc;
bool in_calloc;
bool in_realloc;
bool in_mmap;
bool in_munmap;
bool in_free;
bool in_asprintf;
bool in_strdup;
bool in_strndup;

void malloc_enter(CPUState *env, target_ulong pc, uint8_t *args) {
    in_malloc = true;
}

// NB: void *malloc(size_t size);
// malloc returns ptr to beginning of region that has been malloced
void malloc_exit(CPUState *env, target_ulong pc, uint8_t *args) {
    in_malloc = false;
    dynamic_setup_stuff();
    if (!right_asid(env)) return;
    uint32_t size = *((uint32_t *) args);
    if (size == 0) return;
    target_ulong start_addr = EAX;
    printf ("ddslots malloc start_addr=0x%x size=%d\n", start_addr, size);
    dds_alloc(env, pc, start_addr, size);
}

void calloc_enter(CPUState *env, target_ulong pc, uint8_t *args) {
    in_calloc = true;
}

// void *calloc(size_t nmemb, size_t size);
void calloc_exit(CPUState *env, target_ulong pc, uint8_t *args) {
    in_calloc = false;
    dynamic_setup_stuff();
    if (!right_asid(env)) return;
    uint32_t nmemb = *((uint32_t *) args);
    uint32_t msize = *((uint32_t *) (args + 4));
    uint32_t size = nmemb * msize;
    if (size == 0) return;
    target_ulong start_addr = EAX;
    printf ("ddslots calloc start_addr=0x%x nmemb=%d msize=%d size=%d\n",
            start_addr, nmemb, msize, size);
    dds_alloc(env, pc, start_addr, size);
}



void record_slot(target_ulong pc, target_ulong va, Instr i1, Instr i2) {
    InstrInterval ii = InstrInterval(i1,i2);
    instr_intervals.iinsert(ii);
    cout << instr_intervals.str() <<"\n";
    for (Instr i=i1; i<=i2; i++) dds_count[i] ++;
}

// free or write both kill and provides us with dd slot. if data is written 
// or freed at instr i then everything between last (write, free, or read) and 
// there is a slot.  Right?
void kill(CPUState *env, target_ulong pc, target_ulong start_addr, uint32_t size, uint32_t label) {
    printf (" kill addr=0x%x size=%d label=%d\n", start_addr, size, label);
    target_ulong end_addr = start_addr + size;
    for (target_ulong va=start_addr; va<end_addr; va++) {
        hwaddr pa = check_va(env, va);
        if (pa == -1) continue;
        DdTrackerInfo *ddti = get_ddtracker_info(pa);
        // data at this addr is unsuitable (card / tcn) as a slot
        if (ddti == NULL) continue;
        // this is the only unacceptable label for the prior state of data a va
        assert (ddti->type != DDS_FREE);
        Instr slot_start = ddti->instr;
        Instr slot_end = rr_get_guest_instr_count();
        printf ("slot: pc=0x%x va=0x%x instr=%" PRId64 "..%" PRId64 " len=%" PRId64 "\n",
                pc, va, slot_start, slot_end, slot_end-slot_start);
        record_slot(pc, va, slot_start, slot_end);
        // apply the new label
        dynamic_setup_stuff();
        taint2_label_ram(pa, label);
    }        
}

void realloc_enter(CPUState *env, target_ulong pc, uint8_t *args) {
    in_realloc = true;
}

// void *realloc(void *ptr, size_t size);
void realloc_exit(CPUState *env, target_ulong pc, uint8_t *args) {
    in_realloc = false;
    dynamic_setup_stuff();
    if (!right_asid(env)) return;
    uint32_t old_ptr = *((uint32_t *) args);
    uint32_t new_size = *((uint32_t *) (args + 4));    
    if (new_size == 0) return;
    printf ("ddslots realloc old_ptr=0x%x new_size=%d\n", old_ptr, new_size);
    if (old_ptr == 0) {
        printf ("malloc in disguise\n");
        dds_alloc(env, pc, EAX, new_size);
        return;
    }
    // find the old size of this object
    uint32_t old_size = lookup_object(old_ptr);
    target_ulong new_ptr = EAX;
    if (new_size > old_size) {
        // it got bigger. the new part needs to be marked as allocated
        label_alloc(env, pc, new_ptr+old_size, new_size - old_size);
    }
    else {
        // it got smaller. free excess
        uint32_t start_free = new_ptr + new_size;
        uint32_t size_free = old_size - new_size;
        uint32_t label = new_free_label(env, pc, start_free, size_free);
        kill(env, pc, start_free, size_free, label);
    }
    // keep track of objects
    remove_object(old_ptr, old_size);
    add_object(old_ptr, new_size);
}        

void mmap_enter(CPUState *env, target_ulong pc, uint8_t *args) {
    in_mmap = true;
}

// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void mmap_exit(CPUState *env, target_ulong pc, uint8_t *args) {
    in_mmap = false;
    dynamic_setup_stuff();
    if (!right_asid(env)) return;
    uint32_t length = *((uint32_t *) (args + 4));
    uint32_t ptr = EAX;
    printf ("ddslots mmap ptr=0x%x length=%d\n", ptr, length);    
}

void munmap_enter(CPUState *env, target_ulong pc, uint8_t *args) {
    in_munmap = true;
}

// int munmap(void *addr, size_t length);
void munmap_exit(CPUState *env, target_ulong pc, uint8_t *args) {
    in_munmap = false;
    dynamic_setup_stuff();
    if (!right_asid(env)) return;
    uint32_t addr = *((uint32_t *) args);
    uint32_t length = *((uint32_t *) (args + 4));
    uint32_t retval = EAX;
    printf ("ddslots munmap addr=0x%x length=%d retval=%d\n", addr, length, retval);
}


// NB: void free(void *ptr);
void free_enter(CPUState *env, target_ulong pc, uint8_t *args) {
    in_free = true;
    dynamic_setup_stuff();
    if (!right_asid(env)) return;
    uint32_t ptr = *((uint32_t *) args);
    printf ("ddslots free ptr=0x%x\n", ptr);
    // no-op
    if (ptr == 0) return;
    assert (resolve_object(ptr));
    uint32_t size = lookup_object(ptr);
    printf ("free_exit ptr=0x%x size=%d\n", ptr, size);
    uint32_t label = new_free_label(env, pc, ptr, size);
    kill(env, pc, ptr, size, label);
    // keep track of objects
    remove_object(ptr, size);
}


// NB: void free(void *ptr);
void free_exit(CPUState *env, target_ulong pc, uint8_t *args) {
    in_free = false;
}

void asprintf_enter(CPUState *env, target_ulong pc, uint8_t *args) {
    in_asprintf = true;
}

// int asprintf(char **strp, const char *fmt, ...);
// int vasprintf(char **strp, const char *fmt, va_list ap);
void asprintf_exit(CPUState *env, target_ulong pc, uint8_t *args) {
    in_asprintf = false;
    dynamic_setup_stuff();
    if (!right_asid(env)) return;
    uint32_t strp = *((uint32_t *) args);
    uint32_t p;
    int rv = panda_virtual_memory_read(env, strp, (uint8_t *) &p, 4);
    // fail
    if (rv == -1) return;
    uint32_t numbytes = EAX;
    // error?
    if (numbytes == -1) return;    
    printf ("ddslots asprintf p=0x%x numbytes=%d\n", p, numbytes);
    // NB: add 1 to numbytes because asprintf returns the number of bytes 
    // written but doesn't includie the '\0'
    dds_alloc(env, pc, p, numbytes+1);
}


void dds_strndup(CPUState *env, target_ulong pc, uint32_t p, int n) {
    uint32_t max_len = (n==-1) ? MAX_STRLEN : n;
    uint32_t i;
    for (i=0; i<max_len; i++) {
        uint8_t c;
        int rv = panda_virtual_memory_read(env, p+i, (uint8_t *) &c, 1);
        // this seems bad
        assert (rv != -1);
        // end of string
        if (c == 0) break;
    }
    printf ("ddslots str[n]dup p=0x%x n=%d\n", p, i);
    dds_alloc(env, pc, p, i);
}

void strdup_enter(CPUState *env, target_ulong pc, uint8_t *args) {
    in_strdup = true;
}

// char *strdup(const char *s);
void strdup_exit(CPUState *env, target_ulong pc, uint8_t *args) {
    in_strdup = false;
    dynamic_setup_stuff();
    if (!right_asid(env)) return;
    uint32_t p = EAX;
    dds_strndup(env, pc, p, -1);
}

void strndup_enter(CPUState *env, target_ulong pc, uint8_t *args) {
    in_strndup = true;
}

// char *strndup(const char *s, size_t n);
void strndup_exit(CPUState *env, target_ulong pc, uint8_t *args) {
    in_strndup = false;
    dynamic_setup_stuff();
    if (!right_asid(env)) return;
    uint32_t p = EAX;
    uint32_t n = *((uint32_t *) (args + 4));
    dds_strndup(env, pc, p, n);
}


// DISABLED!
// ok you'd think that a read or write of untainted data was a problem
// if its a read then wasn't there a previous write?  
// if its a write then wasn't there a previous read?  
// well, this seems to break down early in program execution when the
// loader is setting things up, at least.  
void check_all_tainted(CPUState *env, target_ulong start_vaddr, target_ulong size) {
#if 0
    target_ulong end_vaddr = start_vaddr + size;
    for (target_ulong va=start_vaddr; va<end_vaddr; va++) {
        hwaddr pa = check_va(env, va);
        if (pa == -1) continue;
        uint32_t card = taint2_query_ram(pa);
        // not tainted memory
        assert (card != 0);
    }
#endif
}
    
bool ignore_rw() {
    return (in_malloc
            || in_calloc
            || in_free
            || in_realloc
            || in_mmap
            || in_munmap
            || in_asprintf
            || in_strdup
            || in_strndup); 
}

// before virtual mem write
int vwrite (CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, 
            void *buf) {
    dynamic_setup_stuff();
    if (!right_asid(env)) return 0;
    if (ignore_rw()) {
        cout << " ... in malloc.c fn -- ignoring write\n";
        return 0;
    }
    printf ("vwrite addr=0x%x size=%d\n", addr, size);
    check_all_tainted(env, addr, size);
    // make sure this is a write to a heap object we know about
//    if (!resolve_object(addr) 
//        || !resolve_object(addr+size-1)) {
//        cout << "** write overflow detected
    uint32_t label = new_write_label(env, pc, addr, size);
    kill(env, pc, addr, size, label);    
    return 0;
}

// before read of virtual memory
int vread(CPUState *env, target_ulong pc, target_ulong addr, 
           target_ulong size) {
    dynamic_setup_stuff();
    if (!right_asid(env)) return 0;
    if (ignore_rw()) {
        cout << " .. in malloc.c fn -- ignoring read\n";
        return 0;
    }
    printf ("vread addr=0x%x size=%d\n", addr, size);
    check_all_tainted(env, addr, size);
    target_ulong end_addr = addr + size;
    uint32_t l = new_read_label(env, pc, addr, size);
    for (target_ulong va=addr; va<end_addr; va++) {
        hwaddr pa = check_va(env, va);
        if (pa == -1) continue;
        if (!resolve_object(va)) {
            cout << "** read overflow detected @ 0x" << hex << va << dec << " -- ignoring\n";
            continue;
        }
        // NB: no slot here -- no need to read the current label
        // apply the read label
        taint2_label_ram(pa, l);
    }
    return 0;
}

Instr start_instr;

#define ESP    ((CPUX86State *)((CPUState *)env->env_ptr))->regs[R_ESP]


// this is keeping track of instr intervals for this asid
int before_bb(CPUState *env, TranslationBlock *tb) { 
    target_ulong asid = panda_current_asid(env);
    Instr instr = rr_get_guest_instr_count();
    if (last_asid != asid) {
        cout << "asid changed to 0x" << hex << asid << dec << "\n";
        // asid changed 
        if (asid == asid_of_interest) {
            // start of an interval of interest
            start_instr = instr;
        }
        if (last_asid == asid_of_interest) {
            // end of an interval of interest
#if 0
            InstrInterval ii = make_pair(start_instr, instr);
            instr_intervals.insert(ii);
#endif
        }
    }
    last_asid = asid;
    last_instr = instr;
    return 0;
}

int after_bb(CPUState *env, TranslationBlock *tb) { 
    dynamic_setup_stuff();
    if (EAX == 0x88e8480) {
        Instr instr = rr_get_guest_instr_count();
        printf ("instr=%" PRId64 " pc=0x%x after_bb eax=0x%x\n", instr, tb->pc, EAX);
    }
    return 0;
}

#endif       

bool init_plugin(void *self) {
    printf ("Initializing ddslots (dead-data slots) plugin\n");
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    panda_arg_list *args = panda_get_args("general");
    const char *asid_s = panda_parse_string(args, "asid", NULL);
    asid_of_interest = strtoul(asid_s, NULL, 16);
    cout << "asid of interest is 0x" << hex << asid_of_interest << dec << "\n";
    panda_require("taint2");
    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();
    // make taint2 api available and turn on taint
    assert(init_taint2_api());
    // virt mem read and write callbacks
    panda_cb pcb;    
    pcb.virt_mem_before_write = vwrite;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
    pcb.virt_mem_before_read = vread;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);

    pcb.before_block_exec = before_bb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.after_block_exec = after_bb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    // and make lib fn introspection api available
    panda_require("libfi");
    assert(init_libfi_api());
    libfi_add_callback((char *) "glibc", (char *) "plt!malloc",    /*enter=*/1, 1, malloc_enter);
    libfi_add_callback((char *) "glibc", (char *) "plt!malloc",    /*enter=*/0, 1, malloc_exit);
    libfi_add_callback((char *) "glibc", (char *) "plt!calloc",    /*enter=*/1, 2, calloc_enter);
    libfi_add_callback((char *) "glibc", (char *) "plt!calloc",    /*enter=*/0, 2, calloc_exit);
    libfi_add_callback((char *) "glibc", (char *) "plt!realloc",   /*enter=*/1, 2, realloc_enter);
    libfi_add_callback((char *) "glibc", (char *) "plt!realloc",   /*enter=*/0, 2, realloc_exit);
    libfi_add_callback((char *) "glibc", (char *) "plt!asprintf",  /*enter=*/1, 2, asprintf_enter);
    libfi_add_callback((char *) "glibc", (char *) "plt!asprintf",  /*enter=*/0, 2, asprintf_exit);
    libfi_add_callback((char *) "glibc", (char *) "plt!vasprintf", /*enter=*/1, 2, asprintf_enter);
    libfi_add_callback((char *) "glibc", (char *) "plt!vasprintf", /*enter=*/0, 2, asprintf_exit);
    libfi_add_callback((char *) "glibc", (char *) "plt!strdup",    /*enter=*/1, 2, strdup_enter);    
    libfi_add_callback((char *) "glibc", (char *) "plt!strdup",    /*enter=*/0, 2, strdup_exit);    
    libfi_add_callback((char *) "glibc", (char *) "plt!free",      /*enter=*/1, 1, free_enter);
    libfi_add_callback((char *) "glibc", (char *) "plt!free",      /*enter=*/0, 1, free_exit);
    libfi_add_callback((char *) "glibc", (char *) "plt!mmap",      /*enter=*/1, 2, mmap_enter);
    libfi_add_callback((char *) "glibc", (char *) "plt!mmap64",    /*enter=*/0, 2, mmap_exit);
    libfi_add_callback((char *) "glibc", (char *) "plt!munmap",    /*enter=*/1, 1, munmap_enter);
    libfi_add_callback((char *) "glibc", (char *) "plt!munmap",    /*enter=*/0, 1, munmap_exit);
#endif 
    return true;
}

void uninit_plugin(void *self) {

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    cout << instr_intervals.str() << "\n";
    for (Instr i=0; i<max_instr; i++) 
        if (dds_count[i] != 0) 
            printf ("dds_count %" PRId64 " %d\n", i, dds_count[i]);
#endif
    cout << "ddslots uninit\n";
}

