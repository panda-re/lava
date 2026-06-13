#ifndef MALLOC_OFF_BY_ONE_H
#define MALLOC_OFF_BY_ONE_H

using namespace clang;

/**
 * @struct MallocOffByOneArgHandler
 * @brief AST Matcher Handler for injecting MALLOC_OFF_BY_ONE vulnerabilities.
 *
 * This handler targets 'malloc' function calls inside whitelisted functions.
 * - In LavaQueries pass: It registers an Attack Point (ATP) query for dataflow profiling.
 * - In LavaInjectBugs pass: It rewrites the allocation size argument using an inline
 * ternary operator to decrement the requested byte size by 1 when triggered.
 */
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
        const Expr *raw_arg = callExpr->getArg(callExpr->getNumArgs() - 1);
        const Expr *size_arg = raw_arg->IgnoreParenImpCasts();
	    if (size_arg) {
            ASTLoc ast_loc = GetASTLoc(sm, size_arg);
            debug(INJECT) << "[DEBUG] MallocOffByOne ASTLoc evaluated as: " << ast_loc << "\n";
		    Mod.Change(size_arg);

		    if (LavaAction == LavaQueries)  {
		        addend = LavaAtpQuery(ast_loc, AttackPoint::MALLOC_OFF_BY_ONE);
		        num_atp_queries++;
		        Mod.Add(addend, nullptr);
		    } else if (LavaAction == LavaInjectBugs) {
		        const std::vector<const Bug*> &injectable_bugs = map_get_default(bugs_with_atp_at,
					std::make_pair(ast_loc, AttackPoint::MALLOC_OFF_BY_ONE));

                if (injectable_bugs.empty()) {
                    debug(INJECT) << "[DEBUG - MALLOC] No bugs mapped to this ASTLoc during injection for malloc off by one!\n";
                }

		        for (const Bug *bug : injectable_bugs) {
                    debug(INJECT) << "[DEBUG - MALLOC] Successfully found bug " << bug->id << ". Injecting...\n";
                    // =========================================================================
                    // WORKED-OUT INJECTION EXAMPLE:
                    // 
                    // Given original source: malloc(sizeof(file_entry))
                    // 1. Mod.Change(size_arg) focuses our target on "sizeof(file_entry)"
                    // 2. ExprStr(size_arg) stringifies the target node -> "sizeof(file_entry)"
                    // 3. Test(bug).render() generates the runtime switch -> "lava_get(42) == 1"
                    // 4. InsertBefore() prepends the ternary branch condition.
                    // 5. Parenthesize() wraps everything in outer () to maintain C precedence.
                    // 
                    // Resulting source code text (We can think about throwing smaller numbers 
                    // dynamically instead of hardcoding 4, but this should trigger memory erros
                    // without ASAN):
                    // malloc((lava_get(42) == 1 ? (4) : sizeof(file_entry)))
                    // =========================================================================
                    Mod.Parenthesize().InsertBefore(Test(bug).render() + " ? (4) : ");
		        }
		    }
	    }
    }
};

#endif
