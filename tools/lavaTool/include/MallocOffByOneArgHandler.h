#ifndef MALLOC_OFF_BY_ONE_H
#define MALLOC_OFF_BY_ONE_H

#include <cstdlib> // For srand() and rand()
#include <string>  // For std::to_string()

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

                    // 1. Create a deterministic random generator based on the bug ID
                    // This ensures FuzzBench builds the exact same binary every time!
                    srand(bug->id); 
                    
                    std::string buggy_size_expr;
                    clang::Expr::EvalResult EvalRes;
                    const ASTContext &Ctx = *Result.Context;

                    // 2. The LLVM 14 Superpower: Try to evaluate the size statically!
                    if (size_arg->EvaluateAsInt(EvalRes, Ctx)) {
                        int64_t exact_size = EvalRes.Val.getInt().getExtValue();
                        debug(INJECT) << "[DEBUG] LLVM evaluated malloc size statically as: " << exact_size << " bytes.\n";

                        if (exact_size > 16) {
                            // If it's a large struct, subtract a random amount between 16 and (size/2)
                            // This guarantees we break glibc's 16-byte padding!
                            int offset = 16 + (rand() % (exact_size / 2));
                            buggy_size_expr = "(" + ExprStr(size_arg) + " - " + std::to_string(offset) + ")";
                        } else {
                            // If it's a tiny allocation (e.g., malloc(10)), we subtract a larger number.
                            // WHY? Because size_t is unsigned! 10 - 24 = 18446744073709551598.
                            // malloc will attempt to allocate 18 Exabytes, instantly fail, and return NULL.
                            // Dereferencing the NULL pointer creates a highly realistic instant crash!
                            int offset = exact_size + (rand() % 16) + 1;
                            buggy_size_expr = "(" + ExprStr(size_arg) + " - " + std::to_string(offset) + ")";
                        }
                    } else {
                        // 3. Fallback: LLVM couldn't evaluate it (e.g., it's a variable `malloc(n)`).
                        // Use the "Missing Multiplier" bug realism technique. 
                        // Dividing by 2, 4, or 8 looks exactly like a developer forgot a `sizeof()`
                        int divisor = (rand() % 2 == 0) ? 2 : 4; 
                        buggy_size_expr = "(" + ExprStr(size_arg) + " / " + std::to_string(divisor) + ")";
                        debug(INJECT) << "[DEBUG] Dynamic size detected. Injecting division by " << divisor << ".\n";
                    }
                    // =========================================================================
                    // WORKED-OUT INJECTION EXAMPLE:
                    // Original code: malloc(sizeof(file_entry))
                    // malloc((lava_get(42) == 1 ? (4) : sizeof(file_entry)))
                    // =========================================================================
                    Mod.Parenthesize().InsertBefore(Test(bug).render() + " ? " + buggy_size_expr + " : ");
		        }
		    }
	    }
    }
};

#endif
