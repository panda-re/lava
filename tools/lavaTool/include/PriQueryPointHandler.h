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
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    // create code that siphons dua bytes into a global
    // for dua x, offset o, generates:
    // lava_set(slot, *(const unsigned int *)(((const unsigned char *)x)+o)
    // Each lval gets an if clause containing one siphon
    std::string SiphonsForLocation(LavaASTLoc ast_loc) {
        std::stringstream result_ss;
        for (const LvalBytes &lval_bytes : map_get_default(siphons_at, ast_loc)) {
#ifdef SAFE_SIPHON
            // NB: lava_bytes.lval->ast_name is a string that came from
            // libdwarf.  So it could be something like
            // ((*((**(pdtbl)).pub)).sent_table))
            // We need to test pdtbl, *pdtbl and (**pdtbl).pub
            // to make sure they are all not null to reduce risk of
            // runtime segfault?
            std::string nntests = (createNonNullTests(lval_bytes.lval->ast_name));
            if (nntests.size() > 0)
                nntests = nntests + " && ";
            result_ss << LIf(nntests + lval_bytes.lval->ast_name, Set(lval_bytes));
#else
            result_ss << Set(lval_bytes);
#endif
        }

        for (const LvalBytes &lval_bytes : map_get_default(extra_siphons_at, ast_loc)) {
            result_ss << LavaSetExtra(
                    lval_bytes.lval, lval_bytes.selected,
                    extra_data_slots.at(lval_bytes));
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

    std::string AttackChaffBugs(LavaASTLoc ast_loc) {
        std::stringstream result_ss;
        auto key = std::make_pair(ast_loc, AttackPoint::QUERY_POINT);
        for (const Bug *bug : map_get_default(bugs_with_atp_at, key)) {
            if (bug->type == Bug::CHAFF_STACK_UNUSED) {
                result_ss << LIf(Test(bug).render(), {
                        LFunc("memcpy", {LStr("lava_chaff_var_1"),
                                LRandomBytes(UNUSED_RANDOM_BYTES, 8), LDecimal(8)}),
                        LAssign(LDeref(LStr(ARG_NAME)), LStr("lava_chaff_var_0"))});
#ifdef TRIG_UNUSED
                "__asm__ __volatile__(\"xorl %ebx, %ebx;divl %ebx;\");\n";
#endif
            } else if (bug->type == Bug::CHAFF_STACK_CONST) {
                const DuaBytes *extra_dua_bytes = db->load<DuaBytes>(bug->extra_duas[0]);
                LvalBytes extra_bytes(extra_dua_bytes);
                LExpr checker = Test(bug) && LFunc("lava_check_const", {
                        LDecimal(extra_data_slots[extra_bytes]),
                        LHex(0xffffffff)
                        });
                result_ss << LIf(checker.render(), {
                        LAssign(LDeref(
                                LCast("int*",
                                    LBinop("+",
                                        LStr("lava_chaff_var_2"),
                                        LHex(bug->stackoff + 4)))), // Add 4 to overwrite return address
                                LavaGetExtra(extra_data_slots.at(extra_bytes)))});
            } else if (bug->type == Bug::CHAFF_HEAP_CONST) {
                const DuaBytes *extra_dua_bytes = db->load<DuaBytes>(bug->extra_duas[0]);
                LvalBytes extra_bytes(extra_dua_bytes);
                LExpr checker = Test(bug) && LFunc("lava_check_const", {
                        LDecimal(extra_data_slots[extra_bytes]),
                        LHex(0xffffffff)
                        });
                result_ss << LIf(checker.render(), {
                        LAssign(LStr("void *lava_chaff_pointer"), LFunc("malloc", {LHex(0x20)})),
                        LAssign(LStr("*((int*)(((char*)lava_chaff_pointer)+0x18))"), LDecimal(16)),
                        LAssign(LStr("*((int*)(((char*)lava_chaff_pointer)+0x20))"), LDecimal(12)),
                        LAssign(LStr("*((int*)(((char*)lava_chaff_pointer)+0x24))"),
                                LavaGetExtra(extra_data_slots.at(extra_bytes)))});
            }
        }
        bugs_with_atp_at.erase(key); // Only inject once.
        return result_ss.str();
    }

    std::string AttackRetBuffer(LavaASTLoc ast_loc) {
        std::stringstream result_ss;
        auto key = std::make_pair(ast_loc, AttackPoint::QUERY_POINT);
        for (const Bug *bug : map_get_default(bugs_with_atp_at, key)) {
            if (bug->type == Bug::RET_BUFFER) {
                const DuaBytes *buffer = db->load<DuaBytes>(bug->extra_duas[0]);
                if (ArgCompetition) {
                    result_ss << LIf(Test(bug).render(), {
                            LBlock({
                                //It's always safe to call lavalog here since we're in the if
                                LFunc("LAVALOG", {LDecimal(1), LDecimal(1), LDecimal(bug->id)}),
                                LIfDef("__x86_64__", {
                                    LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) +
                                        LDecimal(buffer->selected.low), },
                                        { "movq %0, %%rsp", "ret" }),
                                    LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) +
                                        LDecimal(buffer->selected.low), },
                                        { "movl %0, %%esp", "ret" })})})});
                } else{
                    result_ss << LIf(Test(bug).render(), {
                                LIfDef("__x86_64__", {
                                    LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) +
                                        LDecimal(buffer->selected.low), },
                                        { "movq %0, %%rsp", "ret" }),
                                    LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) +
                                        LDecimal(buffer->selected.low), },
                                        { "movl %0, %%esp", "ret" })})});
                }
            }
        }
        bugs_with_atp_at.erase(key); // Only inject once.
        return result_ss.str();
    }

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        const Stmt *toSiphon = Result.Nodes.getNodeAs<Stmt>("stmt");
        const SourceManager &sm = *Result.SourceManager;

#ifdef LEGACY_CHAFF_BUGS
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
#endif

        LavaASTLoc ast_loc = GetASTLoc(sm, toSiphon);
        debug(PRI) << "Have a query point @ " << ast_loc << "!\n";

        std::string before;
        if (LavaAction == LavaQueries) {
            // this is used in first pass clang tool, adding queries
            // to be intercepted by panda to query taint on in-scope variables
#ifdef LEGACY_CHAFF_BUGS
            before = "; " + LFunc("vm_lava_pri_query_point", {
#else
            before = "; " + LFunc("vm_chaff_pri_query_point", {
#endif
                LDecimal(GetStringID(StringIDs, ast_loc)),
                LDecimal(ast_loc.begin.line),
                LStr("&lava_chaff_var_2")}).render() + "; ";    // Pass the func addr through hypercall

            num_taint_queries += 1;
        } else if (LavaAction == LavaInjectBugs) {
            // This is used in second pass clang tool, injecting bugs.
            // This part is just about inserting DUA siphon, the first half of the bug.
            // Well, not quite.  We are also considering all such code / trace
            // locations as potential inject points for attack point that is
            // stack-pivot-then-return.  Ugh.
            before = SiphonsForLocation(ast_loc) + AttackRetBuffer(ast_loc) + AttackChaffBugs(ast_loc);
        }
        Mod.Change(toSiphon).InsertBefore(before);

        if (LavaAction == LavaInjectBugs) {
            std::stringstream result_ss;
            for (const LExpr &expr : map_get_default(extra_overconst_expr, ast_loc)) {
                result_ss << expr;
                Mod.Change(toSiphon).InsertBefore(result_ss.str());
            }
            extra_overconst_expr.erase(ast_loc);
        }
    }
};

#endif
