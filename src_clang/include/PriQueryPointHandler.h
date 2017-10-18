using namespace clang;

struct PriQueryPointHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    // create code that siphons dua bytes into a global
    // for dua x, offset o, generates:
    // lava_set(slot, *(const unsigned int *)(((const unsigned char *)x)+o)
    // Each lval gets an if clause containing one siphon
    std::string SiphonsForLocation(LavaASTLoc ast_loc) {
        std::stringstream result_ss;
        for (const LvalBytes &lval_bytes : map_get_default(siphons_at, ast_loc)) {
            result_ss << LIf(lval_bytes.lval->ast_name, Set(lval_bytes));
        }

        std::string result = result_ss.str();
        if (!result.empty()) {
            debug(INJECT) << " Injecting dua siphon at " << ast_loc << "\n";
            debug(INJECT) << "    Text: " << result << "\n";
        }
        siphons_at.erase(ast_loc); // Only inject once.
        return result;
    }

    std::string AttackRetBuffer(LavaASTLoc ast_loc) {
        std::stringstream result_ss;
        auto key = std::make_pair(ast_loc, AttackPoint::QUERY_POINT);
        for (const Bug *bug : map_get_default(bugs_with_atp_at, key)) {
            if (bug->type == Bug::RET_BUFFER) {
                const DuaBytes *buffer = db->load<DuaBytes>(bug->extra_duas[0]);
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
        bugs_with_atp_at.erase(key); // Only inject once.
        return result_ss.str();
    }

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        const Stmt *toSiphon = Result.Nodes.getNodeAs<Stmt>("stmt");
        const SourceManager &sm = *Result.SourceManager;

        LavaASTLoc ast_loc = GetASTLoc(sm, toSiphon);
        debug(INJECT) << "Have a query point @ " << ast_loc << "!\n";

        std::string before;
        if (LavaAction == LavaQueries) {
            before = "; " + LFunc("vm_lava_pri_query_point", {
                LDecimal(GetStringID(StringIDs, ast_loc)),
                LDecimal(ast_loc.begin.line),
                LDecimal(0)}).render() + "; ";

            num_taint_queries += 1;
        } else if (LavaAction == LavaInjectBugs) {
            before = SiphonsForLocation(ast_loc) + AttackRetBuffer(ast_loc);
        }
        Mod.Change(toSiphon).InsertBefore(before);
    }
};


