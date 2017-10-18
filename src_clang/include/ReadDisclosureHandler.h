using namespace clang;

struct ReadDisclosureHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;
        const CallExpr *callExpr = Result.Nodes.getNodeAs<CallExpr>("call_expression");

        LExpr addend = LDecimal(0);
        // iterate through all the arguments in the call expression
        for (auto it = callExpr->arg_begin(); it != callExpr->arg_end(); ++it) {
            const Expr *arg = dyn_cast<Expr>(*it);
            if (arg) {
                if (arg->IgnoreImpCasts()->isLValue() && arg->getType()->isIntegerType()) {
                    LavaASTLoc ast_loc = GetASTLoc(sm, arg);
                    Mod.Change(arg);
                    if (LavaAction == LavaQueries)  {
                        addend = LavaAtpQuery(GetASTLoc(sm, arg),
                                AttackPoint::PRINTF_LEAK);
                        Mod.Add(addend, nullptr);
                    } else if (LavaAction == LavaInjectBugs) {
                        const std::vector<const Bug*> &injectable_bugs =
                            map_get_default(bugs_with_atp_at,
                                    std::make_pair(ast_loc, AttackPoint::PRINTF_LEAK));
                        for (const Bug *bug : injectable_bugs) {
                            Mod.Parenthesize()
                                .InsertBefore(Test(bug).render() +
                                        " ? &(" + ExprStr(arg) + ") : ");
                        }
                    }

                }
            }
        }
    }
};

