
#include <map>
#include <vector>
#include "panda/plugin.h"

extern "C" {
#include "panda/plog.h"
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#include "pri/pri_types.h"
#include "pri/pri_ext.h"
#include "pri/pri.h"

// needed for accessing type information on linux/elf based systems
#include "dwarf2/dwarf2_types.h"
#include "dwarf2/dwarf2_ext.h"

#include "stackprob_int_fns.h"

bool init_plugin(void *);
void uninit_plugin(void *);
}

static bool debug = false;

#define dprintf(...) if (debug) { printf(__VA_ARGS__); fflush(stdout); }


struct args {
    target_ulong pc_;
    target_ulong sp_;
};

std::map<target_ulong, target_ulong> stackoff;

target_ulong stack_retaddr_offset(target_ulong funcaddr) {
    return stackoff[funcaddr];
}

void find_var(void *var_ty_void, const char *var_nm, LocType loc_t, target_ulong loc, void *in_args) {
    struct args *args = (struct args*)in_args;
    if (strcmp(var_nm, "lava_chaff_var_0") == 0) {
        switch (loc_t) {
            case LocMem:
            {
                target_ulong framebase = dwarf2_get_cur_fp(first_cpu, args->pc_);
                //target_ulong retaddr = 0;
                //panda_virtual_memory_read(first_cpu, args->sp_, (uint8_t*)&retaddr, sizeof(target_ulong));
                //fprintf(stderr, "Target %s : addr[%x] Loc %x - cur framebase %x (%x) - ESP %x retaddr[%x]\n", var_nm, args->pc_, loc, framebase, framebase-loc, args->sp_, retaddr);
                stackoff[args->pc_] = framebase - loc;
                break;
            }
            case LocReg:
            case LocConst:
            case LocErr:
                break;
            default:
                assert(false);
        }
    }
}

void on_call(CPUState *cpu, target_ulong pc) {
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    //target_ulong retaddr = 0;
    //panda_virtual_memory_read(cpu, env->regs[R_ESP], (uint8_t*)&retaddr, sizeof(target_ulong));
    //fprintf(stderr, "[CHAFF] Function Call at %x - ESP %x : [%x]\n", pc, env->regs[R_ESP], retaddr);

    if (stackoff.count(pc) != 0)
        return;

    // Find address of `int lava_chaff_var_0`
    struct args args = {pc, env->regs[R_ESP]};
    pri_funct_livevar_iter(cpu, pc, (liveVarCB) find_var, (void *)&args);
}

bool init_plugin(void *self) {
    panda_arg_list *args = panda_get_args("stackprob");
    debug = panda_parse_bool_opt(args, "debug", "enable debug output");

    panda_require("callstack_instr");
    assert(init_callstack_instr_api());
    panda_require("pri");
    assert(init_pri_api());
    panda_require("dwarf2");
    assert(init_dwarf2_api());

    //panda_enable_precise_pc();
    //panda_enable_memcb();

    PPP_REG_CB("callstack_instr", on_call, on_call);

    return true;
}

void uninit_plugin(void *self) {
}
