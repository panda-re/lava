
#define DECLARE_REGISTER(x,y,z) register unsigned long reg##x asm(#y) = z;
#define COMMA ,
#if defined(CONFIG_ARM64) || defined(__aarch64__)
    #define REGISTER1 DECLARE_REGISTER(0,x8,num)
    #define REGISTER2 REGISTER1 DECLARE_REGISTER(1,x0,arg1)
    #define REGISTER3 REGISTER2 DECLARE_REGISTER(2,x1,arg2)
    #define REGISTER4 REGISTER3 DECLARE_REGISTER(3,x2,arg3)
    #define REGISTER5 REGISTER4 DECLARE_REGISTER(4,x3,arg4)

    #define ASM(x)  asm volatile(\
       "msr S0_0_c5_c0_0, xzr"\
        : "+r"(reg1)\
        : "r"(reg0) x \
        : "memory" \
    );
    #define RETURN  return reg1;
#elif defined(CONFIG_ARM) || defined(__arm__)
    #define REGISTER1 DECLARE_REGISTER(0,r7,num)
    #define REGISTER2 REGISTER1 DECLARE_REGISTER(1,r0,arg1)
    #define REGISTER3 REGISTER2 DECLARE_REGISTER(2,r1,arg2)
    #define REGISTER4 REGISTER3 DECLARE_REGISTER(3,r2,arg3)
    #define REGISTER5 REGISTER4 DECLARE_REGISTER(4,r3,arg4)

    #define ASM(x)  asm volatile(\
       "mcr p7, 0, r0, c0, c0, 0"\
        : "+r"(reg1)\
        : "r"(reg0) x \
        : "memory" \
    );
    #define RETURN return reg1;

#elif defined(CONFIG_MIPS) || defined(mips) || defined(__mips__) || defined(__mips) || defined(__mips64)
    #define REGISTER1 DECLARE_REGISTER(0,v0,num)
    #define REGISTER2 REGISTER1 DECLARE_REGISTER(1,a0,arg1)
    #define REGISTER3 REGISTER2 DECLARE_REGISTER(2,a1,arg2)
    #define REGISTER4 REGISTER3 DECLARE_REGISTER(3,a2,arg3)
    #define REGISTER5 REGISTER4 DECLARE_REGISTER(4,a3,arg4)
    #define ASM(x)  asm volatile(\
       "movz $0, $0, $0"\
        : "+r"(reg0) \
        : "r"(reg1) x \
        : "memory" \
    );
    #define RETURN  return reg0;
#elif defined(CONFIG_X86_64) || defined(__x86_64__)
    #define REGISTER1 DECLARE_REGISTER(0,rax,num)
    #define REGISTER2 REGISTER1 DECLARE_REGISTER(1,rdi,arg1)
    #define REGISTER3 REGISTER2 DECLARE_REGISTER(2,rsi,arg2)
    #define REGISTER4 REGISTER3 DECLARE_REGISTER(3,rdx,arg3)
    #define REGISTER5 REGISTER4 DECLARE_REGISTER(4,r10,arg4)

    #define ASM(x) asm volatile(\
        "cpuid"\
        : "+r"(reg0) \
        : "r"(reg1) x  \
        : "memory" );
    #define RETURN return reg0;
#elif defined(CONFIG_I386) || (defined(__i386__) && !defined(__x86_64__))
    #define REGISTER1 DECLARE_REGISTER(0,eax,num)
    #define REGISTER2 REGISTER1 DECLARE_REGISTER(1,ebx,arg1)
    #define REGISTER3 REGISTER2 DECLARE_REGISTER(2,ecx,arg2)
    #define REGISTER4 REGISTER3 DECLARE_REGISTER(3,edx,arg3)
    #define REGISTER5 REGISTER4 DECLARE_REGISTER(4,esi,arg4)

    #define ASM(x) asm volatile(\
        "cpuid"\
        : "+r"(reg0) \
        : "r"(reg1) x  \
        : "memory" \
    );
    #define RETURN return reg0;
#elif defined(CONFIG_LOONGARCH64) || defined(__loongarch64)
    #define REGISTER1 DECLARE_REGISTER(0,a7,num)
    #define REGISTER2 REGISTER1 DECLARE_REGISTER(1,a0,arg1)
    #define REGISTER3 REGISTER2 DECLARE_REGISTER(2,a1,arg2)
    #define REGISTER4 REGISTER3 DECLARE_REGISTER(3,a2,arg3)
    #define REGISTER5 REGISTER4 DECLARE_REGISTER(4,a3,arg4)

    #define ASM(x)  asm volatile( \
       "cpucfg $r0, $r0" \
        : "+r" (reg1) \
        : "r" (reg0) x \
        : "memory" \
    );
    #define RETURN return reg1;
#elif defined(CONFIG_PPC64) || defined(CONFIG_PPC) || defined(__powerpc__) || defined(__powerpc64__)
    #define REGISTER1 DECLARE_REGISTER(0,r0,num)
    #define REGISTER2 REGISTER1 DECLARE_REGISTER(1,r3,arg1)
    #define REGISTER3 REGISTER2 DECLARE_REGISTER(2,r4,arg2)
    #define REGISTER4 REGISTER3 DECLARE_REGISTER(3,r5,arg3)
    #define REGISTER5 REGISTER4 DECLARE_REGISTER(4,r6,arg4)

    #define ASM(x) asm volatile(\
        "xori 10, 10, 0"\
        : "+r"(reg1) \
        : "r"(reg0) x  \
        : "memory" \
    );
    #define RETURN return reg1;
#elif defined(CONFIG_RISCV) || defined(__riscv)
    #define REGISTER1 DECLARE_REGISTER(0,a7,num)
    #define REGISTER2 REGISTER1 DECLARE_REGISTER(1,a0,arg1)
    #define REGISTER3 REGISTER2 DECLARE_REGISTER(2,a1,arg2)
    #define REGISTER4 REGISTER3 DECLARE_REGISTER(3,a2,arg3)
    #define REGISTER5 REGISTER4 DECLARE_REGISTER(4,a3,arg4)

    #define ASM(x) asm volatile(\
        "xori x0, x0, 0"\
        : "+r"(reg1) \
        : "r"(reg0) x  \
        : "memory" \
    );
    #define RETURN return reg1;
#else
#error "not supported"
#endif
static inline unsigned long igloo_hypercall(unsigned long num, unsigned long arg1){
    REGISTER2
    ASM()
    RETURN
}
static inline unsigned long igloo_hypercall2(unsigned long num, unsigned long arg1, unsigned long arg2){
    REGISTER3
    ASM(COMMA"r"(reg2))
    RETURN
}

static inline unsigned long igloo_hypercall3(unsigned long num, unsigned long arg1, unsigned long arg2, unsigned long arg3){
    REGISTER4
    ASM(COMMA "r"(reg2)COMMA "r"(reg3))
    RETURN
}
static inline unsigned long igloo_hypercall4(unsigned long num, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4){
    REGISTER5
    ASM(COMMA "r"(reg2)COMMA "r"(reg3)COMMA "r"(reg4))
    RETURN
}

#ifdef MAGIC_VALUE
#define RETRY 0xDEADBEEF
static inline int hc(int hc_type, void **s,int len) {
    uint64_t ret = hc_type;
    int y = 0;
    do {
        ret = MAGIC_VALUE;
        volatile int x = 0;
        for(int i = 0; i< len; i++) {
            x |= *(((int*)s[i])+y);
        }
        y++;
        ret = igloo_hypercall3(MAGIC_VALUE,(unsigned long)hc_type,(unsigned long)s,(unsigned long)len);
    } while (ret == RETRY);

    return ret;
}
#endif
