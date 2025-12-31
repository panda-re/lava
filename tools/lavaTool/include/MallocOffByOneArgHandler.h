#ifndef MALLOC_OFF_BY_ONE_H
#define MALLOC_OFF_BY_ONE_H

using namespace clang;

struct MallocOffByOneArgHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler;

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;
        const CallExpr *callExpr = Result.Nodes.getNodeAs<CallExpr>("call_expression");

        if (ArgDataflow) {
            auto fnname = get_containing_function_name(Result, *callExpr);

            // only instrument this printf with a read disclosure
            // if it's in the body of a function that is on our whitelist
            if (fninstr(fnname)) {
                debug(INJECT) << "MallocOffByOneHandler: Containing function is in whitelist " << fnname.second << " : " << fnname.first << "\n";
            }
            else {
                debug(INJECT) << "MallocOffByOneHandler: Containing function is NOT in whitelist " << fnname.second << " : " << fnname.first << "\n";
                return;
            }

            debug(INJECT) << "MallocOffByOneHandler handle: ok to instrument " << fnname.second << "\n";
        }

        LExpr addend = LDecimal(0);
        const Expr *size_arg = callExpr->getArg(callExpr->getNumArgs() - 1);
	if (size_arg) {
        	ASTLoc ast_loc = GetASTLoc(sm, size_arg);
		Mod.Change(size_arg);
		if (LavaAction == LavaQueries)  {
		    addend = LavaAtpQuery(ast_loc,
					AttackPoint::MALLOC_OFF_BY_ONE);
		    num_atp_queries++;
		    Mod.Add(addend, nullptr);
		} else if (LavaAction == LavaInjectBugs) {

		    const std::vector<const Bug*> &injectable_bugs =
				    map_get_default(bugs_with_atp_at,
					    std::make_pair(ast_loc, AttackPoint::MALLOC_OFF_BY_ONE));
		    for (const Bug *bug : injectable_bugs) {
			Mod.Parenthesize().InsertBefore(Test(bug).render() + " ? (" + ExprStr(size_arg) + " - 1 ) : ");
		    }
		}
	}
    }
};

#endif
