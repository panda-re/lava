#ifndef __PIRATE_MARK_LAVA_H__
#define __PIRATE_MARK_LAVA_H__

// https://github.com/panda-re/libhc/blob/main/hypercall.h
#include <panda/hypercall.h>
// https://github.com/panda-re/panda/blob/dev/panda/include/panda/lava_hypercall_struct.h
#include <panda/lava_hypercall_struct.h>

static const int LABEL_BUFFER = 7;
static const int LABEL_BUFFER_POS = 8;
static const int QUERY_BUFFER = 9;
static const int GUEST_UTIL_DONE = 10;
static const int LAVA_QUERY_BUFFER = 11;
static const int LAVA_ATTACK_POINT = 12;
static const int LAVA_PRI_QUERY_POINT = 13;

// see tools/lavaTool/include/LavaMatchHandler.h
static inline
void vm_lava_attack_point(unsigned int ast_loc_id, unsigned long linenum, unsigned int info) {
  volatile PandaHypercallStruct phs = {0};
  phs.magic = LAVA_MAGIC;
  phs.action = LAVA_ATTACK_POINT;
  phs.src_filename = ast_loc_id;
  phs.src_linenum = linenum;
  phs.info = info;
  phs.insertion_point = 0;  // this signals that there isn't an insertion point
  igloo_hypercall(LAVA_MAGIC, (unsigned long) &phs);
}

// see /tools/lavaTool/include/PriQueryPointHandler.h
// NOTE: We use always_inline to ensure the hypercall executes inline,
// and nodebug to hide it from PANDA's dwarfdump.py which crashes on inlined subprograms.
// We avoid using igloo_hypercall directly as this ensures srcInfo is on TaintQueryPri
// and points to the correct source code line rather than the hypercall function wrapper.
static inline __attribute__((always_inline, nodebug))
void vm_lava_pri_query_point(unsigned int ast_loc_id, unsigned long line_num, unsigned long extra_info) {
    volatile PandaHypercallStruct phs = {0};
    phs.magic = LAVA_MAGIC;
    phs.action = LAVA_PRI_QUERY_POINT;
    phs.src_filename = ast_loc_id;
    phs.src_linenum = line_num;
    phs.insertion_point = 1;
    phs.info = extra_info;

#if defined(CONFIG_X86_64) || defined(__x86_64__)
    DECLARE_REGISTER(0, rax, LAVA_MAGIC)
    DECLARE_REGISTER(1, rdi, (unsigned long) &phs)
    ASM()
#elif defined(CONFIG_I386) || (defined(__i386__) && !defined(__x86_64__))
    DECLARE_REGISTER(0, eax, LAVA_MAGIC)
    DECLARE_REGISTER(1, ebx, (unsigned long) &phs)
    ASM()
#elif defined(CONFIG_ARM) || defined(__arm__)
    DECLARE_REGISTER(0, r7, LAVA_MAGIC)
    DECLARE_REGISTER(1, r0, (unsigned long) &phs)
    ASM()
#elif defined(CONFIG_ARM64) || defined(__aarch64__)
    DECLARE_REGISTER(0, x8, LAVA_MAGIC)
    DECLARE_REGISTER(1, x0, (unsigned long) &phs)
    ASM()
#endif
}

#endif