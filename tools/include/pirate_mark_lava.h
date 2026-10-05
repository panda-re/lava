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

// On x86, a hypercall is a bare cpuid. Under PANDA replay, hypercaller handles it and
// helper_cpuid returns early, so eax/ebx/ecx/edx are left untouched. During record (no
// plugins) the real cpuid runs and overwrites all four. panda/hypercall.h's ASM() and
// igloo_hypercall only declare eax, so the compiler may keep a live value in rbx/rcx/rdx
// across the hypercall (rbx is callee-saved and never restored). That value then differs
// between record and replay, and the replay diverges ("guest instruction counts disagree").
// Declaring every register cpuid writes as clobbered makes both runs behave the same.
#if defined(__x86_64__)
#define LAVA_HYPERCALL(ptr) do { \
    unsigned long lava_hc_rax = LAVA_MAGIC; \
    asm volatile("cpuid" : "+a"(lava_hc_rax) : "D"((unsigned long) (ptr)) \
                 : "rbx", "rcx", "rdx", "memory"); \
  } while (0)
#elif defined(__i386__)
#define LAVA_HYPERCALL(ptr) do { \
    unsigned long lava_hc_eax = LAVA_MAGIC; \
    unsigned long lava_hc_ebx = (unsigned long) (ptr); \
    asm volatile("cpuid" : "+a"(lava_hc_eax), "+b"(lava_hc_ebx) \
                 : : "ecx", "edx", "memory"); \
  } while (0)
#endif

// see tools/lavaTool/include/LavaMatchHandler.h
static inline
void vm_lava_attack_point(unsigned int ast_loc_id, unsigned long linenum, unsigned int info) {
  volatile PandaHypercallStruct phs = {0};
  phs.action = LAVA_ATTACK_POINT;
  phs.src_filename = ast_loc_id;
  phs.src_linenum = linenum;
  phs.info = info;
  phs.insertion_point = 0;  // this signals that there isn't an insertion point
#ifdef LAVA_HYPERCALL
  LAVA_HYPERCALL(&phs);
#else
  igloo_hypercall(LAVA_MAGIC, (unsigned long) &phs);
#endif
}

// see /tools/lavaTool/include/PriQueryPointHandler.h
// NOTE: We use always_inline to ensure the hypercall executes inline,
// and nodebug to hide it from PANDA's dwarfdump.py which crashes on inlined subprograms.
// We avoid using igloo_hypercall directly as this ensures srcInfo is on TaintQueryPri
// and points to the correct source code line rather than the hypercall function wrapper.
static inline __attribute__((always_inline, nodebug))
void vm_lava_pri_query_point(unsigned int ast_loc_id, unsigned long line_num, unsigned long extra_info) {
    volatile PandaHypercallStruct phs = {0};
    phs.action = LAVA_PRI_QUERY_POINT;
    phs.src_filename = ast_loc_id;
    phs.src_linenum = line_num;
    phs.insertion_point = 1;
    phs.info = extra_info;

#if defined(__x86_64__) || defined(__i386__)
    LAVA_HYPERCALL(&phs);
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