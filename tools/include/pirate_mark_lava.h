#ifndef __PIRATE_MARK_LAVA_H__
#define __PIRATE_MARK_LAVA_H__

// For LAVA use only
#define LAVA_MAGIC 0xabcd

// Define architecture-specific register names, WIP
#if defined(CONFIG_X86_64) || defined(__x86_64__)
    #define REG0 rax
    #define REG1 rdi
#elif defined(CONFIG_I386) || (defined(__i386__) && !defined(__x86_64__))
    #define REG0 eax
    #define REG1 ebx
#elif defined(CONFIG_ARM) || defined(__arm__)
    #define REG0 r0
    #define REG1 r1
#elif defined(CONFIG_ARM64) || defined(__aarch64__)
    #define REG0 x0
    #define REG1 x1
#else
    #error "Unsupported architecture"
#endif

// Taken from here
// https://github.com/panda-re/libhc/blob/main/hypercall.h
#include "hypercall.h"
#include "panda_hypercall_struct.h"

static const int LABEL_BUFFER = 7;
static const int LABEL_BUFFER_POS = 8;
static const int QUERY_BUFFER = 9;
static const int GUEST_UTIL_DONE = 10;
static const int LAVA_QUERY_BUFFER = 11;
static const int LAVA_ATTACK_POINT = 12;
static const int LAVA_PRI_QUERY_POINT = 13;

// see tools/lavaTool/include/LavaMatchHandler.h
static inline 
void vm_lava_attack_point(lavaint ast_loc_id, unsigned long linenum, lavaint info) {
  volatile PandaHypercallStruct phs = {0};
  phs.magic = LAVA_MAGIC;
  phs.action = LAVA_ATTACK_POINT;
  phs.src_filename = ast_loc_id;
  phs.src_linenum = linenum;
  phs.info = info;
  phs.insertion_point = 0;  // this signals that there isnt an insertion point
  igloo_hypercall(LAVA_MAGIC, (unsigned long) &phs);
}

// Right now, this only can work for x86-64, but the principle carries for other architectures
// see /tools/lavaTool/include/PriQueryPointHandler.h
// NOTE: You can NOT use the hypercall directly, it will not work because then srcInfo on 
// TaintQueryPri will point to the hypercall function NOT the source code!
#define vm_lava_pri_query_point(ast_loc_id, line_num, extra_info) do { \
    volatile PandaHypercallStruct phs = {0}; \
    phs.magic = LAVA_MAGIC; \
    phs.action = LAVA_PRI_QUERY_POINT; \
    phs.src_filename = ast_loc_id; \
    phs.src_linenum = line_num; \
    phs.insertion_point = 1; \
    phs.info = extra_info; \
    DECLARE_REGISTER(0, rax, LAVA_MAGIC) \
    DECLARE_REGISTER(1, rdi, (unsigned long) &phs) \
    ASM() \
} while (0)

#endif
