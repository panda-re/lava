#ifndef __PIRATE_MARK_LAVA_H__
#define __PIRATE_MARK_LAVA_H__

// For LAVA use only

/*
 * Keep me in sync between PANDA and LAVA repos
 */

#include "panda_hypercall_struct.h"

#define TARGET_I386

#if !defined(TARGET_I386) && !defined(TARGET_ARM)
#error "Define your architecture (TARGET_I386 or TARGET_ARM) with -D"
#endif

static const int LABEL_BUFFER = 7;
static const int LABEL_BUFFER_POS = 8;
static const int QUERY_BUFFER = 9;
static const int GUEST_UTIL_DONE = 10;
static const int LAVA_QUERY_BUFFER = 11;
static const int LAVA_ATTACK_POINT = 12;
static const int LAVA_PRI_QUERY_POINT = 13;

/*
typedef struct panda_hypercall_struct {
    lavaint magic;
    lavaint action;             // label / query / etc
    lavaint buf;                // ptr to memory we want labeled or queried or
    lavaint len;                // number of bytes to label or query or
    lavaint label_num;          // if labeling, this is the label number.  if querying this should be zero
    lavaint src_column;         // column on source line
    lavaint src_filename;       // char * to filename.
    lavaint src_linenum;        // line number
    lavaint src_ast_node_name;  // the name of the l-value queries
    lavaint info;               // general info
} PandaHypercallStruct;
*/
#ifdef TARGET_I386
static inline
void hypercall(void *buf, unsigned long len, long label, unsigned long off,
    void *pmli, int action) {
  int eax = action;
  void *ebx = buf;
  unsigned long ecx = len;
  unsigned long edx = off;
  long edi = label;
  void *esi = pmli;

  asm __volatile__
      ("mov  %0, %%eax \t\n\
        mov  %1, %%ebx \t\n\
        mov  %2, %%ecx \t\n\
        mov  %3, %%edx \t\n\
        mov  %4, %%edi \t\n\
        mov  %5, %%esi \t\n\
        cpuid \t\n\
       "
      : /* no output registers */
      : "g" (eax), "g" (ebx), "g" (ecx), "g" (edx), "g" (edi), "g" (esi) /* input operands */
       : "eax", "ebx", "ecx", "edx", "edi", "esi" /* clobbered registers */
      );
  return;
}

static
void hypercall2(volatile PandaHypercallStruct *phs) {
#if defined(__PIC__)
    volatile int __attribute__ ((visibility ("hidden"))) lava_save_nodua = 0;
    __asm__ volatile ("xchgl %%ebx, %1\n\t"      \
                      "cpuid\n\t"                \
                      "xchgl %%ebx, %1"          \
        : "=a" (phs), "=r" (lava_save_nodua)                \
        : "0" (phs), "1" (lava_save_nodua)                  \
        : "ecx", "edx", "memory");
#else
    __asm__ volatile ("cpuid"                    \
        : "=a" (phs)                             \
        : "0" (phs)                              \
        : "ebx", "ecx", "edx", "memory");
#endif
    return;
}
#endif // TARGET_I386

#if 0
#ifdef TARGET_ARM
inline
void hypercall(void *buf, unsigned long len, long label, unsigned long off, int action) {
    unsigned long r0 = action;
    void *r1 = buf;
    unsigned long r2 = len;
    unsigned long r3 = off;
    long r4 = label;

    asm __volatile__
      ("push {%%r0-%%r4} \t\n\
        mov %%r0, %0 \t\n\
        mov %%r1, %1 \t\n\
        mov %%r2, %2 \t\n\
        mov %%r3, %3 \t\n\
        mov %%r4, %4 \t\n\
        mcr p7, 0, r0, c0, c0, 0 \t\n\
        pop {%%r0-%%r4} \t\n"

      : /* no output registers */
      : "r" (r0), "r" (r1), "r" (r2), "r" (r3), "r" (r4) /* input operands */
      : "r0", "r1", "r2", "r3", "r4" /* clobbered registers */
      );
    return;
}
#endif // TARGET_ARM
#endif

/* buf is the address of the buffer to be labeled
 * label is the label to be applied to the buffer
 * len is the length of the buffer to be labeled */
static inline
void vm_label_buffer(void *buf, int label, unsigned long len,
    void *pmli) {
  hypercall(buf, len, label, 0, pmli, LABEL_BUFFER);
  return;
}

/* buf is the address of the buffer to be labeled
 * len is the length of the buffer to be labeled
 * offset is currently managed by file seeking in the utils */
static inline
void vm_label_buffer_pos(void *buf, unsigned long len, int offset,
    void *pmli) {
  hypercall(buf, len, 0, offset, pmli, LABEL_BUFFER_POS);
  return;
}

/* buf is the address of the buffer to be queried
 * len is the length of the buffer to be queried
 * offset is currently managed by file seeking in the utils */
static inline
void vm_query_buffer(void *buf, unsigned long len, int offset,
    void *pmli) {
  hypercall(buf, len, 0, offset, pmli, QUERY_BUFFER);
  return;
}

static inline
void vm_lava_query_buffer(const void *buf, unsigned long len,
                          lavaint src_filename, lavaint src_ast_node_name,
                          unsigned long linenum, lavaint ins) {
  volatile PandaHypercallStruct phs = {0};
  phs.magic = 0xabcd;
  phs.action = LAVA_QUERY_BUFFER;
  phs.buf = (lavaint) buf;
  phs.len = len;
  phs.label_num = 0; // unused;
  phs.src_filename = src_filename;
  phs.src_ast_node_name = src_ast_node_name;
  phs.src_linenum = linenum;
  phs.insertion_point = ins;
  hypercall2(&phs);
}

static inline
void vm_lava_attack_point(lavaint src_filename, unsigned long linenum, lavaint info) {
  volatile PandaHypercallStruct phs = {0};
  phs.magic = 0xabcd;
  phs.action = LAVA_ATTACK_POINT;
  phs.src_filename = src_filename;
  phs.src_linenum = linenum;
  phs.info = info;
  phs.insertion_point = 0;  // this signals that there isnt an insertion point
  hypercall2(&phs);
}
/*
inline void vm_lava_pri_query_point(lavaint ast_node) __attribute__ ((always_inline));
void vm_lava_pri_query_point(lavaint ast_node){
    volatile PandaHypercallStruct phs;
    volatile PandaHypercallStruct *phs_addr = &phs;
    phs.magic = 0xabcd;
    phs.action = LAVA_PRI_QUERY_POINT;
    //phs.src_filename = src_filename;
    //phs.src_linenum = linenum;
    phs.info = ast_node;
    phs.insertion_point = 0;  // this signals that there isnt an insertion point
#if defined(__PIC__)
    volatile int lava_save_nodua = 0;
    __asm__ volatile ("xchgl %%ebx, %1\n\t"      \
                      "cpuid\n\t"                \
                      "xchgl %%ebx, %1"          \
        : "=a" (phs_addr), "=r" (lava_save_nodua)           \
        : "0" (phs_addr), "1" (lava_save_nodua)             \
        : "ecx", "edx", "memory");
#else
    __asm__ volatile ("cpuid"                    \
        : "=a" (phs_addr)                        \
        : "0" (phs_addr)                         \
        : "ebx", "ecx", "edx", "memory");
#endif
    return;
}
*/
static inline
void vm_lava_attack_point2(lavaint ast_loc_id, unsigned long linenum, lavaint info) {
  volatile PandaHypercallStruct phs = {0};
  phs.magic = 0xabcd;
  phs.action = LAVA_ATTACK_POINT;
  phs.src_filename = ast_loc_id;
  phs.src_linenum = linenum;
  phs.info = info;
  phs.insertion_point = 0;  // this signals that there isnt an insertion point
  hypercall2(&phs);
}

static inline
void vm_lava_pri_query_point2(lavaint src_filename, unsigned long linenum,
        lavaint src_ast_node_name) {
  volatile PandaHypercallStruct phs = {0};
  phs.magic = 0xabcd;
  phs.action = LAVA_PRI_QUERY_POINT;
  phs.src_filename = src_filename;
  phs.src_linenum = linenum;
  phs.src_ast_node_name = src_ast_node_name;
  // always insert before
  phs.insertion_point = 1;
  hypercall2(&phs);
}

#if defined(__PIC__)
#define ASM_PART __asm__ volatile ("xchgl %%ebx, %1\n\t"   \
                                   "cpuid\n\t"             \
                                   "xchgl %%ebx, %1"       \
        : "=a" (phs_addr), "=r" (lava_save_nodua)                     \
        : "0" (phs_addr), "1" (lava_save_nodua)                       \
        : "ecx", "edx", "memory");
#else
#define ASM_PART __asm__ volatile ("cpuid"                 \
        : "=a" (phs_addr)                                  \
        : "0" (phs_addr)                                   \
        : "ebx", "ecx", "edx", "memory");
#endif

#if defined(__PIC__)
#define vm_lava_pri_query_point(ast_loc_id, lineno, extra_info) \
    do {                                                   \
    volatile PandaHypercallStruct phs;                     \
    volatile PandaHypercallStruct *phs_addr = &phs;        \
    phs.magic = 0xabcd;                                    \
    phs.action = LAVA_PRI_QUERY_POINT;                     \
    phs.src_filename = ast_loc_id;                         \
    phs.src_linenum = lineno;                              \
    phs.insertion_point = 0;                               \
    volatile int __attribute__ ((visibility ("hidden"))) lava_save_nodua = 0;                                 \
    __asm__ volatile ("xchgl %%ebx, %1\n\t"                \
                      "cpuid\n\t"                          \
                      "xchgl %%ebx, %1"                    \
        : "=a" (phs_addr), "=r" (lava_save_nodua)                     \
        : "0" (phs_addr), "1" (lava_save_nodua)                       \
        : "ecx", "edx", "memory");                         \
    } while(0)

#else
#define vm_lava_pri_query_point(ast_loc_id, lineno, extra_info) \
    do {                                                   \
    volatile PandaHypercallStruct phs;                     \
    volatile PandaHypercallStruct *phs_addr = &phs;        \
    phs.magic = 0xabcd;                                    \
    phs.action = LAVA_PRI_QUERY_POINT;                     \
    phs.src_filename = ast_loc_id;                         \
    phs.src_linenum = lineno;                              \
    phs.insertion_point = 0;                               \
    phs.info = extra_info;                                 \
    __asm__ volatile ("cpuid"                              \
        : "=a" (phs_addr)                                  \
        : "0" (phs_addr)                                   \
        : "ebx", "ecx", "edx", "memory");                  \
    } while(0)
#endif

/*
static inline void vm_lava_attack_point2(lavaint src_filename, unsigned long linenum, lavaint info) __attribute__ ((always_inline));
static inline
void vm_lava_attack_point2(lavaint src_filename, unsigned long linenum, lavaint info) {
    volatile PandaHypercallStruct phs;
    volatile PandaHypercallStruct *phs_addr = &phs;
    phs.magic = 0xabcd;
    phs.action = LAVA_ATTACK_POINT;
    phs.src_filename = src_filename;
    phs.src_linenum = linenum;
    phs.info = info;
    phs.insertion_point = 0;  // this signals that there isnt an insertion point
#if defined(__PIC__)
    volatile int lava_save_nodua = 0;
    __asm__ volatile ("xchgl %%ebx, %1\n\t"      \
                      "cpuid\n\t"                \
                      "xchgl %%ebx, %1"          \
        : "=a" (phs_addr), "=r" (lava_save_nodua)           \
        : "0" (phs_addr), "1" (lava_save_nodua)             \
        : "ecx", "edx", "memory");
#else
    __asm__ volatile ("cpuid"                    \
        : "=a" (phs_addr)                        \
        : "0" (phs_addr)                         \
        : "ebx", "ecx", "edx", "memory");
#endif
    return;
}
*/
//inline void vm_lava_pri_query_point(int ast_node_id) __attribute__ ((always_inline));
//static inline void vm_lava_pri_query_point (int ast_node_id) {
    //__asm__ volatile ("nop");
    //return;
//}

static inline
void vm_guest_util_done(void){
    hypercall(0, 0, 0, 0, 0, GUEST_UTIL_DONE);
}

#endif
