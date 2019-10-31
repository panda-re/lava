#ifndef MATCHFINDER_H
#define MATCHFINDER_H

#include "LavaMatchHandler.h"
#include "FunctionArgHandler.h"
#include "MemoryAccessHandler.h"
#include "PriQueryPointHandler.h"
#include "ReadDisclosureHandler.h"
#include "FuncDuplicationHandler.h"
#include "VarDeclArgAdditionHandler.h"
#include "FuncDeclArgAdditionHandler.h"
#include "ChaffFuncDeclArgAdditionHandler.h"
#include "FieldDeclArgAdditionHandler.h"
#include "FunctionPointerFieldHandler.h"
#include "CallExprArgAdditionalHandler.h"
#include "FunctionPointerTypedefHandler.h"

// Must match value in scripts/fninstr.py
//#define IGNORE_FN_PTRS

using clang::tooling::ClangTool;
using clang::tooling::Replacement;
using clang::tooling::getAbsolutePath;
using clang::tooling::CommonOptionsParser;
using clang::tooling::SourceFileCallbacks;
using clang::tooling::TranslationUnitReplacements;


/*******************************
 * Matcher Handlers
 *******************************/

namespace clang {
    namespace ast_matchers {
        AST_MATCHER(Expr, isAttackableMatcher){
            const Expr *ce = &Node;
            return IsArgAttackable(ce);
        }

        AST_MATCHER(VarDecl, isStaticLocalDeclMatcher){
            const VarDecl *vd = &Node;
            return vd->isStaticLocal();
        }

        AST_MATCHER_P(CallExpr, forEachArgMatcher,
                internal::Matcher<Expr>, InnerMatcher) {
            BoundNodesTreeBuilder Result;
            bool Matched = false;
            for ( const auto *I : Node.arguments()) {
                //for (const auto *I : Node.inits()) {
                BoundNodesTreeBuilder InitBuilder(*Builder);
                if (InnerMatcher.matches(*I, Finder, &InitBuilder)) {
                    Matched = true;
                    Result.addMatch(InitBuilder);
                }
            }
            *Builder = std::move(Result);
            return Matched;
        }
    }
}


class LavaMatchFinder : public MatchFinder, public SourceFileCallbacks {
public:
    LavaMatchFinder() : Mod(Insert) {

        // This is a write to array element or pointer
        // i.e. we have *p = ... or x[i] = ...
        // Really the 'p' or 'i' is what gets matched
        // This is a potential attack point.
        StatementMatcher memoryAccessMatcher =
            allOf(
                expr(anyOf(
                         // "lhs" part matches i in x[i] or p in *p
                    arraySubscriptExpr(
                        hasIndex(ignoringImpCasts(
                                expr().bind("innerExpr")))),
                    unaryOperator(hasOperatorName("*"),
                        hasUnaryOperand(ignoringImpCasts(
                                expr().bind("innerExpr")))))).bind("lhs"),
                anyOf(
                    // and this means above "lhs" in tree is assignment
                    // where LHS matches our already bound "lhs"
                    // in which case RHS binds to "rhs"
                    expr(hasAncestor(binaryOperator(allOf(
                                    hasOperatorName("="),
                                    hasRHS(ignoringImpCasts(
                                            expr().bind("rhs"))),
                                    hasLHS(ignoringImpCasts(expr(
                                                equalsBoundNode("lhs")))))))),
                    anything()), // this is a "maybe" construction.
                hasAncestor(functionDecl()), // makes sure that we are't in a global variable declaration
                // make sure we aren't in static local variable initializer which must be constant
                unless(hasAncestor(varDecl(isStaticLocalDeclMatcher()))));

#ifdef LEGACY_CHAFF_BUGS
        addMatcher(memoryAccessMatcher, makeHandler<MemoryAccessHandler>());
#endif

        // This matches every stmt in a compound statement
        // So "stmt" in
        // stmt; stmt'; stmt''; stmt'''; etc
        // Used to add pri queries (in turn used by PANDA to know where it is
        // in the source whe querying taint).  Also used to insert DUA siphons
        // (first half of a bug) but also stack-pivot second-half of bug.
        addMatcher(
                stmt(hasParent(compoundStmt())).bind("stmt"),
                makeHandler<PriQueryPointHandler>()
                );
        addMatcher(
                functionDecl().bind("funcDecl"),
                makeHandler<ChaffFuncDeclArgAdditionHandler>());

#ifdef LEGACY_CHAFF_BUGS
        addMatcher(
                callExpr(
                    forEachArgMatcher(expr(isAttackableMatcher()).bind("arg"))).bind("call"),
                makeHandler<FunctionArgHandler>()
                );
#endif



        // fortenforge's matchers (for data_flow argument addition)
        if (ArgDataflow && LavaAction == LavaInjectBugs) {
// Skip Handling Function Pointers In Chaff Bugs
#ifndef LEGACY_CHAFF_BUGS
            addMatcher(
                    callExpr().bind("callExpr"),
                    makeHandler<CallExprArgAdditionHandler>());

#else
            // function declarations & definition.  Decl without body is prototype
            addMatcher(
                    functionDecl().bind("funcDecl"),
                    makeHandler<FuncDeclArgAdditionHandler>());

            // Function call
            addMatcher(
                fieldDecl().bind("fielddecl"),
                makeHandler<FieldDeclArgAdditionHandler>());


            addMatcher(
                varDecl().bind("vardecl"),
                makeHandler<VarDeclArgAdditionHandler>());

            // function calls (direct or via fn pointer)
#ifndef IGNORE_FN_PTRS
            addMatcher(
                    callExpr().bind("callExpr"),
                    makeHandler<CallExprArgAdditionHandler>());

            // Match typedefs for function pointers
            addMatcher(
                typedefDecl().bind("typedefdecl"),
                makeHandler<FunctionPointerTypedefHandler>());
#endif
#endif

        // printf read disclosures - currently disabled
        /* addMatcher(
                callExpr(
                    callee(functionDecl(hasName("::printf"))),
                    unless(argumentCountIs(1))).bind("call_expression"),
                makeHandler<ReadDisclosureHandler>()
                ); */
        }
    }
    virtual bool handleBeginSource(CompilerInstance &CI, StringRef Filename) override {
        Insert.clear();
        Mod.Reset(&CI.getLangOpts(), &CI.getSourceManager());
        TUReplace.Replacements.clear();
        TUReplace.MainSourceFile = Filename;
        CurrentCI = &CI;

        debug(INJECT) << "*** handleBeginSource for: " << Filename << "\n";

        std::stringstream logging_macros;
        logging_macros << "#ifdef LAVA_LOGGING\n" // enable logging with (LAVA_LOGGING, FULL_LAVA_LOGGING) and (DUA_LOGGING) flags. Logging requires stdio to be included
                       << "#define LAVALOG(bugid, x, trigger)  ({(trigger && fprintf(stderr, \"\\nLAVALOG: %d: %s:%d\\n\", bugid, __FILE__, __LINE__)), (x);})\n"
                       << "#endif\n"

                    << "#ifdef FULL_LAVA_LOGGING\n"
                        << "#define LAVALOG(bugid, x, trigger)  ({(trigger && fprintf(stderr, \"\\nLAVALOG: %d: %s:%d\\n\", bugid, __FILE__, __LINE__), (!trigger && fprintf(stderr, \"\\nLAVALOG_MISS: %d: %s:%d\\n\", bugid, __FILE__, __LINE__))) && fflush(0), (x);})\n"
                    << "#endif\n"

                    << "#ifndef LAVALOG\n"
                        << "#define LAVALOG(y,x,z)  (x)\n"
                    << "#endif\n"

                    << "#ifdef DUA_LOGGING\n"
                        << "#define DFLOG(idx, val)  ({fprintf(stderr, \"\\nDFLOG:%d=%d: %s:%d\\n\", idx, val, __FILE__, __LINE__) && fflush(0), data_flow[idx]=val;})\n"
                    << "#else\n"
                        << "#define DFLOG(idx, val) {data_flow[idx]=val;}\n"
                    << "#endif\n";

        std::string insert_at_top;
        if (LavaAction == LavaQueries) {
            insert_at_top = "#include \"pirate_mark_lava.h\"\n";
        } else if (LavaAction == LavaInjectBugs) {
            insert_at_top.append(logging_macros.str());
#ifdef LEGACY_CHAFF_BUGS
            if (!ArgDataflow)
#endif
            {
                std::stringstream top;
                if (main_files.count(getAbsolutePath(Filename)) > 0) {
                    top << "unsigned int lava_val[" << data_slots.size() << "] = {0};\n"
                        << "unsigned int lava_extra[" << extra_data_slots.size() << "] = {0};\n"
                        << "unsigned int lava_state[" << extra_data_slots.size() << "] = {0};\n"
                        << "void *lava_chaff_pointer = (void*)0;\n";
                } else {
                    top << "extern unsigned int lava_val;\n"
                        << "extern unsigned int lava_extra;\n"
                        << "extern unsigned int lava_state;\n"
                        << "extern void *lava_chaff_pointer;\n";
                }
                top << ""
                    //<< "void lava_set(unsigned int, unsigned int);\n"
                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_set(slot, val) { \\\n"
                    //<< "#ifdef DUA_LOGGING\n"
                    //    << "fprintf(stderr, \"\\nlava_set:%d=%d: %s:%d\\n\", slot, val, __FILE__, __LINE__);\n"
                    //    << "fflush(NULL);\n"
                    //<< "#endif\n"
                    << "lava_val[slot] = val&0xffff; }\n"
                    //<< "unsigned int lava_get(unsigned int);\n"
                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_get(slot)  lava_val[slot] \n"
                    //<< "void lava_set_extra(unsigned int, unsigned int);\n"
                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_set_extra(slot, val) { \\\n"
                    << "lava_extra[slot] = val; lava_state[slot]=0; }\n"
                    //<< "unsigned int lava_get_extra(unsigned int);\n"
                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_get_extra(slot) lava_extra[slot] \n"

                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_check_const_high_1(slot) "
                    << "((!(((lava_extra[slot])>>16)&4)) && (!(lava_extra[slot]>>31)))\n"
                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_check_const_high_2(slot) "
                    << "((!(((lava_extra[slot])>>18)&1)) && (__builtin_popcount(lava_extra[slot]&0xff000000)<7))\n"
                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_check_const_high_3(slot) "
                    << "(__builtin_clz(lava_extra[slot])>4)\n"
                    << "#define lava_check_const_high_4(slot) "
                    << "((((int)lava_extra[slot])>((int)-1)) && ((lava_extra[slot]>>16)&0x0101))\n"
                    << "#define lava_check_const_high_5(slot) "
                    << "((__builtin_clz(lava_extra[slot])>4) && (((((lava_extra[slot]>>16)*0xfe)&0xf0f0)&0xffff)==0xf0f0))\n"
                    << "#define lava_check_const_high_6(slot) "
                    << "((((((lava_extra[slot]>>16)*0xfe)&0xf0f0)&0xffff)==0xf0f0) && (!(((lava_extra[slot])>>18)&1)))\n"

                    << "#define lava_check_const_high_pass(slot) "
                    << "((!(lava_extra[slot]>>31)) && ((((lava_extra[slot]>>16)*0xfe)&0xf0f0)==0xf0f0))\n"

                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_update_const_high(slot) "
                    << "{ lava_state[slot]|=1; }\n"

                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_check_const_low(slot, val) "
                    << "(lava_extra[slot]&val)\n"

                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_update_const_low(slot) "
                    << "{ lava_state[slot]|=2; }\n"

                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_check_state(slot) "
                    << "(lava_state[slot] == 3)\n";       // exactly 2 constraints
                insert_at_top.append(top.str());
            }
        }

        debug(INJECT) << "Inserting macros and lava_set/get or dataflow at top of file\n";
        TUReplace.Replacements.emplace_back(Filename, 0, 0, insert_at_top);

        for (auto it = MatchHandlers.begin();
                it != MatchHandlers.end(); it++) {
            (*it)->LangOpts = &CI.getLangOpts();
        }

        return true;
    }

    virtual void handleEndSource() override {
        debug(INJECT) << "*** handleEndSource\n";

        Insert.render(CurrentCI->getSourceManager(), TUReplace.Replacements);
        std::error_code EC;
        llvm::raw_fd_ostream YamlFile(TUReplace.MainSourceFile + ".yaml",
                EC, llvm::sys::fs::F_RW);
        yaml::Output Yaml(YamlFile);
        Yaml << TUReplace;
    }

    template<class Handler>
    LavaMatchHandler *makeHandler() {
        MatchHandlers.emplace_back(new Handler(Mod));
        return MatchHandlers.back().get();
    }

private:
    Insertions Insert;
    Modifier Mod;
    TranslationUnitReplacements TUReplace;
    std::vector<std::unique_ptr<LavaMatchHandler>> MatchHandlers;
    CompilerInstance *CurrentCI = nullptr;
};
#endif
