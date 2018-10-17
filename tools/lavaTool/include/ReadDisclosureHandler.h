#ifndef READDISCLOSUREHANDLER_H
#define READDISCLOSUREHANDLER_H

using namespace clang;

const Stmt* findParent(const Stmt *expr, ASTContext *ctx) {
    const Stmt* ST = NULL;
    const Stmt* old = NULL;
    int i = 0;
    debug(INJECT) << "===============PRE COMP "<< (i) <<  "==============\n";
    expr->dump();
    debug(INJECT) << "===============PRE COMP "<< (i) <<  "==============\n";
    while(true) {
        const auto& parents = ctx->getParents(*expr);
        if (parents.empty()) {
            llvm::errs() << "Can not find parent\n";
            return NULL;
        }
        llvm::errs() << "Find parent size = " << parents.size() << "\n";
        ST = parents[0].get<Stmt>();
        if (!ST)
            continue;

        debug(INJECT) << "===============PRE COMP "<< (++i) <<  "==============\n";
        ST->dump();
        debug(INJECT) << "===============PRE COMP END " << (i) << "==============\n";

        if (isa<CompoundStmt>(ST))
            break;
        old = ST;
    }
    return ST;
}

struct ReadDisclosureHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;
        const CallExpr *callExpr = Result.Nodes.getNodeAs<CallExpr>("call_expression");
        const Stmt *cexpr = Result.Nodes.getNodeAs<Stmt>("call_expression");
        //debug(INJECT) << ((findParent(cexpr, Result.Context)) ? "true" : "false") << "\n";
        const Stmt* pre_compound = findParent(cexpr, Result.Context);

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

#endif
