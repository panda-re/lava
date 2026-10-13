#ifndef PRIQUERYPOINTHANDLER_H
#define PRIQUERYPOINTHANDLER_H

using namespace clang;

/*
  This code is used both to inject 'queries' used during taint analysis but
  also to inject bug parts (mostly DUA siphoning (first half of bug) but also
  stack pivot).

  First use is to instrument code with vm_lava_pri_query_point calls.
  These get inserted in between stmts in a compound statement.

  Thus, if code was

  stmt; stmt; stmt

  Then this handler will change it to

  query; stmt; query; stmt; query; stmt; query

  The idea is these act as sentinels in the source.  We know exactly
  where they are, semantically, since we inserted them.  Then, we run
  the program augmented with these under PANDA and record.  Then when
  we replay, under taint analysis.  The calls to
  vm_lava_pri_query_point talk to the PANDA 'hypervisor' to tell it
  exactly where we are in the program at each point in the trace.  At
  each of these query points, PANDA uses PRI (program introspection
  using debug dwarf info) to know what are the local variables, what
  are they named, and where are they in memory or registers.  PANDA
  queries these in-scope items for taint and anything found to be
  tainted is logged along with taint-compute number and other info to
  the pandalog.  The pandalog is consumed by the
  find_bugs_injectable.cpp program to identify DUAs (which
  additionally have liveness constraints).

  When lavaTool.cpp is used during bug injection, we insert DUA
  'siphoning' code in exactly the same place as the corresponding
  vm_lava_pri_query_points.  We also can add stack-pivot style
  exploitable bugs, using these locations as attack points.

*/


struct PriQueryPointHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor

    // DUA names are address expressions built from "(*X)", "*(X)", ".field" and "&(...)", e.g.
    // "&((*((*ctxt).node)).children)". Every pointer that the name dereferences must be non-null
    // before the siphon reads through it, so return "X1 && X2 && ..." with one check per "*"
    // operand, inner (shorter) pointers first: "(ctxt) && (((*ctxt).node))".
    // (The old version only peeled leading '*'s, so a name like the one above was guarded by the
    // always-true "&(...)" and crashed whenever ctxt->node was NULL.)
    std::string GenerateNullChecks(const std::string &Expr) {
        std::vector<std::string> operands;
        for (size_t i = 0; i < Expr.size(); i++) {
            if (Expr[i] != '*') {
                continue;
            }
            size_t j = i + 1;
            std::string operand;
            if (j < Expr.size() && Expr[j] == '(') {
                int depth = 0;
                size_t k = j;
                for (; k < Expr.size(); k++) {
                    if (Expr[k] == '(') depth++;
                    else if (Expr[k] == ')' && --depth == 0) break;
                }
                if (k >= Expr.size()) {
                    continue; // unbalanced; leave it unguarded rather than emit bad C
                }
                operand = Expr.substr(j, k - j + 1);
            } else {
                size_t k = j;
                while (k < Expr.size() && (isalnum((unsigned char)Expr[k]) || Expr[k] == '_')) {
                    k++;
                }
                operand = Expr.substr(j, k - j);
            }
            if (!operand.empty() &&
                std::find(operands.begin(), operands.end(), operand) == operands.end()) {
                operands.push_back(operand);
            }
        }
        // An inner pointer is a substring of every outer one, so shorter first is inner first.
        std::stable_sort(operands.begin(), operands.end(),
                [](const std::string &a, const std::string &b) { return a.size() < b.size(); });
        std::string Checks;
        for (const std::string &operand : operands) {
            if (!Checks.empty()) {
                Checks += " && ";
            }
            Checks += "(" + operand + ")";
        }
        return Checks;
    }

    // create code that siphons dua bytes into a global
    // for dua x, offset o, generates:
    // lava_set(slot, *(const unsigned int *)(((const unsigned char *)x)+o)
    // Each lval gets an if clause containing one siphon
    std::string SiphonsForLocation(ASTLoc ast_loc) {
        std::stringstream result_ss;
        // We iterate over variables (lvals) that LAVA identified as "siphons" (data sources)
        for (const LvalBytes &lval_bytes : map_get_default(siphons_at, ast_loc)) {
            // Get the string name from DWARF (e.g., "**p")
            std::string ast_name = lval_bytes.lval->ast_name;

            // Generate the safety checks using our new local helper
            std::string nntests = GenerateNullChecks(ast_name);
            if (!nntests.empty()) {
                nntests += " && ";
            }

            // Generate the LAVA instrumentation code:
            // If (Safe) { Siphon(Value); }
            result_ss << LIf(nntests + ast_name, Set(lval_bytes)).render() << "\n";
        }

        for (const LvalBytes &lval_bytes : map_get_default(extra_siphons_at, ast_loc)) {
            // Same guard as the siphons above: the name may dereference pointers that are NULL here.
            std::string nntests = GenerateNullChecks(lval_bytes.lval->ast_name);
            if (!nntests.empty()) {
                nntests += " && ";
            }
            result_ss << LIf(nntests + lval_bytes.lval->ast_name,
                    LavaSetExtra(lval_bytes.lval, lval_bytes.selected,
                                 extra_data_slots.at(lval_bytes))).render() << "\n";
        }

        std::string result = result_ss.str();
        if (!result.empty()) {
            debug(PRI) << " Injecting dua siphon at " << ast_loc << "\n";
            debug(PRI) << "    Text: " << result << "\n";
        }
        siphons_at.erase(ast_loc); // Only inject once.
        extra_siphons_at.erase(ast_loc);
        return result;
    }

    // Architecture-neutral AST helper for divide-by-zero / crash injection
    LExpr InjectDivByZero(LExpr extra_val) {
        std::string code = "do { "
                       "(void)(" + extra_val.render() + "); "
                       "__builtin_trap(); "
                       "} while (0)";
       return LBlock({LStr(code)});
    }

    std::string AttackChaffBugs(ASTLoc ast_loc) {
        std::stringstream result_ss;
        auto key = std::make_pair(ast_loc, AttackPoint::QUERY_POINT);

        for (const Bug *bug : map_get_default(bugs_with_atp_at, key)) {
            // 1. CHAFF_DIVZERO (or DebugInject evaluation mode for CONST bugs)
            if (bug->type == Bug::CHAFF_DIVZERO || 
                ((bug->type == Bug::CHAFF_STACK_UNUSED || bug->type == Bug::CHAFF_STACK_CONST || bug->type == Bug::CHAFF_HEAP_CONST) && DebugInject)) {
                const DuaBytes *extra_dua_bytes = db->load<DuaBytes>(bug->extra_duas[0]);
                LvalBytes extra_bytes(extra_dua_bytes);
                LExpr checker = Test(bug) && LFunc("lava_check_state", { LDecimal(extra_data_slots[extra_bytes]) });

                result_ss << LIf(checker.render(), {
                    InjectDivByZero(LavaGetExtra(extra_data_slots.at(extra_bytes)))
                });

            // 2. CHAFF_STACK_UNUSED
            } else if (bug->type == Bug::CHAFF_STACK_UNUSED) {
                if (DebugInject) {
                    result_ss << LIf(Test(bug).render(), { InjectDivByZero(LStr("0")) });
                } else {
                    // Evaluates target pointer width at target compile time via sizeof(void*)
                    // Explicitly casts to (char*) so subtraction moves by raw bytes, not pointer elements
                    result_ss << LIf(Test(bug).render(), {
                        LFunc("memcpy", {
                            LStr("(void*)((char*)&lava_chaff_var_2 - sizeof(void*))"),
                            LRandomBytes(16),
                            LStr("sizeof(void*) * 2")
                        }),
                        LAssign(LDeref(LStr(ARG_NAME)), LStr("*(int *)&lava_chaff_var_2"))
                    });
                }
            // 3. CHAFF_STACK_CONST
            } else if (bug->type == Bug::CHAFF_STACK_CONST) {
                const DuaBytes *extra_dua_bytes = db->load<DuaBytes>(bug->extra_duas[0]);
                LvalBytes extra_bytes(extra_dua_bytes);
                LExpr checker = Test(bug) && LFunc("lava_check_state", { LDecimal(extra_data_slots[extra_bytes]) });

                // Target byte offset calculation evaluated at compile-time
                std::string target_offset = std::to_string(bug->stackoff) + " + sizeof(void*)";
                result_ss << LIf(checker.render(), {
                    LAssign(
                    LDeref(
                    LCast("void**",
                        LBinop("+", LStr("(char*)&lava_chaff_var_2"), LStr(target_offset))
                        )
                    ),
                    LCast("void*", LavaGetExtra(extra_data_slots.at(extra_bytes)))
                    )
                });
            // 4. CHAFF_HEAP_CONST, TODO: It is likely broken, because it only works on an old glibc
            } else if (bug->type == Bug::CHAFF_HEAP_CONST) {
                const DuaBytes *extra_dua_bytes = db->load<DuaBytes>(bug->extra_duas[0]);
                LvalBytes extra_bytes(extra_dua_bytes);
                LExpr checker = Test(bug) && LFunc("lava_check_state", { LDecimal(extra_data_slots[extra_bytes]) });

                result_ss << LIf(checker.render(), {
                    LIfDef("__x86_64__", {
                        LBlock({
                            LAssign(LStr("void *lava_chaff_pointer"), LFunc("malloc", {LHex(0x20)})),
                            LAssign(LStr("*((long long*)(((char*)lava_chaff_pointer)+0x10))"), LDecimal(32)),
                            LAssign(LStr("*((long long*)(((char*)lava_chaff_pointer)+0x20))"), LDecimal(24)),
                            LAssign(LStr("*((long long*)(((char*)lava_chaff_pointer)+0x28))"), LavaGetExtra(extra_data_slots.at(extra_bytes)))
                        })
                    }),
                    LIfDef("__i386__", {
                        LBlock({
                            LAssign(LStr("void *lava_chaff_pointer"), LFunc("malloc", {LHex(0x20)})),
                            LAssign(LStr("*((int*)(((char*)lava_chaff_pointer)+0x18))"), LDecimal(16)),
                            LAssign(LStr("*((int*)(((char*)lava_chaff_pointer)+0x20))"), LDecimal(12)),
                            LAssign(LStr("*((int*)(((char*)lava_chaff_pointer)+0x24))"), LavaGetExtra(extra_data_slots.at(extra_bytes)))
                        })
                    })
                });
            }
        }
        return result_ss.str();
    }

    std::string AttackRetBuffer(ASTLoc ast_loc) {
        std::stringstream result_ss;
        auto key = std::make_pair(ast_loc, AttackPoint::QUERY_POINT);
        for (const Bug *bug : map_get_default(bugs_with_atp_at, key)) {
            if (bug->type == Bug::RET_BUFFER) {
                const DuaBytes *buffer = db->load<DuaBytes>(bug->extra_duas[0]);

                // 1. Build the cross-architecture inline assembly payload
                auto asm_payload = LBlock({
                    LIfDef("__aarch64__", {
                        // AArch64: Pivot SP -> Load Link Register (x30) from new stack -> Return
                        LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) + LDecimal(buffer->selected.low) },
                             { "mov sp, %0", "ldr x30, [sp], #8", "ret" })
                    }),
                    LIfDef("__arm__", {
                        // ARM32 (ARMv5T Compatible): Pivot SP -> Load Multiple Full Descending (pop) into PC
                        LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) + LDecimal(buffer->selected.low) },
                             { "mov sp, %0", "ldmfd sp!, {pc}" })
                    }),
                    LIfDef("__x86_64__", {
                        // x86_64: Pivot RSP -> Return
                        LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) + LDecimal(buffer->selected.low) },
                             { "movq %0, %%rsp", "ret" })
                    }),
                    LIfDef("__i386__", {
                        // x86_32: Pivot ESP -> Return
                        LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) + LDecimal(buffer->selected.low) },
                             { "movl %0, %%esp", "ret" })
                    })
                });

                // 2. Inject the payload with or without the Competition Logger
                if (ArgCompetition) {
                    result_ss << LIf(Test(bug).render(), {
                        LBlock({
                            // It's always safe to call lavalog here since we're in the if
                            LFunc("LAVALOG", {LDecimal(1), LDecimal(1), LDecimal(bug->id)}),
                            asm_payload
                        })
                    });
                } else {
                    result_ss << LIf(Test(bug).render(), {
                        asm_payload
                    });
                }
            }
        }
        return result_ss.str();
    }

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        const Stmt *toSiphon = Result.Nodes.getNodeAs<Stmt>("stmt");
        const SourceManager &sm = *Result.SourceManager;

        if (ArgDataflow) {
            auto fnname = get_containing_function_name(Result, *toSiphon);

            // only instrument this stmt
            // if it's in the body of a function that is on our whitelist
            if (fninstr(fnname)) {
                debug(PRI) << "PriQueryPointHandler: Containing function is in whitelist " << fnname.second << " : " << fnname.first << "\n";
            }
            else {
                debug(PRI) << "PriQueryPointHandler: Containing function is NOT in whitelist " << fnname.second << " : " << fnname.first << "\n";
                return;
            }

            debug(PRI) << "PriQueryPointHandler handle: ok to instrument " << fnname.second << "\n";
        }

        ASTLoc ast_loc = GetASTLoc(sm, toSiphon);
        debug(PRI) << "Have a query point @ " << ast_loc << "!\n";

        // For a "case X:"/"default:" label, insert AFTER the label(s)
        const Stmt *insertAt = toSiphon;
        while (const SwitchCase *sc = dyn_cast<SwitchCase>(insertAt)) {
            insertAt = sc->getSubStmt();
        }

        std::string before;
        if (LavaAction == LavaQueries) {
            // this is used in first pass clang tool, adding queries
            // to be intercepted by panda to query taint on in-scope variables
            before = "; " + LFunc("vm_lava_pri_query_point", {
                LDecimal(GetStringID(StringIDs, ast_loc)),
                LDecimal(ast_loc.begin.line),
                LStr("lava_chaff_var_2")}).render() + "; ";    // Pass the func addr through hypercall

            num_taint_queries += 1;
        } else if (LavaAction == LavaInjectBugs) {
            // This is used in second pass clang tool, injecting bugs.
            // This part is just about inserting DUA siphon, the first half of the bug.
            // Well, not quite.  We are also considering all such code / trace
            // locations as potential inject points for attack point that is
            // stack-pivot-then-return.  Ugh.
            before = SiphonsForLocation(ast_loc) + AttackRetBuffer(ast_loc) + AttackChaffBugs(ast_loc);
            // Safely erase the key AFTER all attacks have been processed
            auto key = std::make_pair(ast_loc, AttackPoint::QUERY_POINT);
            bugs_with_atp_at.erase(key);
        }

        if (LavaAction == LavaInjectBugs) {
            for (const LExpr &expr : map_get_default(extra_overconst_expr, ast_loc)) {
                Mod.Change(insertAt).InsertBefore(expr.render());
            }
            extra_overconst_expr.erase(ast_loc);
        }

        // Ensure lava_set/lava_set_extra always comes first
        Mod.Change(insertAt).InsertBefore(before);
    }
};

#endif
