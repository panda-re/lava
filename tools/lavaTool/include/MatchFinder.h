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
                        << "void *lava_chaff_pointer = (void*)0;\n"
                        << "char lava_patch_array[0x10000] __attribute__((section(\".orz\"))) = {1};\n";
                } else {
                    top << "extern unsigned int lava_val[];\n"
                        << "extern unsigned int lava_extra[];\n"
                        << "extern unsigned int lava_state[];\n"
                        << "extern void *lava_chaff_pointer;\n";
                        //<< "extern char lava_patch_array[];\n";
                }
                top << ""
                    << "float lava_tempval;\n"
                    << "#define MOD(X, Y) ((X)%(Y))\n"
                    << "#define P2(X, Y) MOD((MOD((X), (Y))*MOD((X), (Y))), (Y))\n"
                    << "#define MULTI(X, Y, Z) MOD((MOD((X), (Z))*MOD((Y), (Z))), (Z))\n"
                    << "#define P4(X, Y) P2(P2(X, Y), Y)\n"
                    << "#define P5(X, Y) MULTI(P4(X, Y), (X), (Y))\n"
                    << "#define P8(X, Y) P4(P4(X, Y), Y)\n"
                    << "#define P11(X, Y) MULTI(P2(P5(X,Y),Y), (X), (Y))\n"
                    << "#define P16(X, Y) P8(P8(X, Y), Y)\n"
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
                    //<< "#define lava_check_const_high_1(slot) "
                    // 1. (regview) << "((!(((lava_extra[slot])>>16)&4)) && (!(lava_extra[slot]>>31)))\n"
                    // 2. (zipread) << "((!(__builtin_popcount((lava_extra[slot]>>16)&0x5aa5)&2)) && (__builtin_clz(lava_extra[slot])))\n"
                    // 3. (graphland) << "(((P16(lava_extra[slot]>>16, 0x1337)^P5(lava_extra[slot]>>16, 0x1337))&0xf0)==0xf0) && (((P8(lava_extra[slot]>>24, 137)+P11(lava_extra[slot]>>24, 137))&0x55)==0x55)\n"
                    // 4. (mp3ninja) << "((lava_tempval=(lava_extra[slot]>>16),__builtin_popcount(*(int*)&lava_tempval)>11) && (lava_tempval=(lava_extra[slot]>>16),lava_tempval=(__builtin_powif(lava_tempval,7)),(*(int*)&lava_tempval)&1))\n"
                    //<< "__attribute__((visibility(\"default\")))\n"
                    //<< "#define lava_check_const_high_2(slot) "
                    // 1. (regview) << "((!(((lava_extra[slot])>>18)&1)) && (__builtin_popcount(lava_extra[slot]&0xff000000)<7))\n"
                    // 2. (zipread) << "((__builtin_bswap32(lava_extra[slot])&3) && (__builtin_clz(lava_extra[slot]&0xdeadbeef)>3)) \n"
                    // 3. (graphland) << "(((P5(lava_extra[slot]>>24, 7557)*P4(lava_extra[slot]>>24, 4657))&0xff)!=0) && (((P8(lava_extra[slot]>>16, 349)+P2(lava_extra[slot]>>16, 439))&0xff)==0x55)\n"
                    // 4. (mp3ninja) << "((lava_tempval=(lava_extra[slot]>>16),__builtin_ffs(*(int*)&lava_tempval)>15) && (lava_tempval=(lava_extra[slot]>>16),__builtin_popcount(*(int*)&lava_tempval)>11))\n"
                    //<< "__attribute__((visibility(\"default\")))\n"
                    //<< "#define lava_check_const_high_3(slot) "
                    // 1. (regview) << "(__builtin_clz(lava_extra[slot])>4)\n"
                    // 2. (zipread) << "(__builtin_parity((lava_extra[slot])>>16) && ((__builtin_ctz(__builtin_bswap32(lava_extra[slot])))>3))\n"
                    // 3. (graphland) << "((lava_tempval=(lava_extra[slot]>>16),((*(int*)(&lava_tempval))&0xf000000)==0x5000000) && (lava_tempval=(lava_extra[slot]>>16),((*(int*)(&lava_tempval))&0xf000)<0x7000) && ((int)(lava_extra[slot]>>16)>0))\n"
                    // 4. (mp3ninja) << "((lava_tempval=(lava_extra[slot]>>16),__builtin_ffs(*(int*)&lava_tempval)>15) && (lava_tempval=((lava_extra[slot]>>16)^0x5555),__builtin_clz(*(int*)&lava_tempval)))\n"
                    //<< "#define lava_check_const_high_4(slot) "
                    // 1. (regview) << "((((int)lava_extra[slot])>((int)-1)) && ((lava_extra[slot]>>16)&0x0101))\n"
                    // 2. (zipread) << "(((((lava_extra[slot]>>16)*0xfe)&0xf0f0)==0xf0f0) && (__builtin_ffs(lava_extra[slot]>>16)>3))\n"
                    // 3. (graphland) << "(lava_tempval=((lava_extra[slot]>>16)&0xffff),((P8((*(int*)(&lava_tempval))>>24,37)^P2((*(int*)(&lava_tempval))>>24,23))&0xff)==0) && (lava_tempval=((lava_extra[slot]>>16)&0xffff),lava_tempval=(__builtin_powif(lava_tempval,8)+__builtin_powif(lava_tempval,3)),((*(int*)&lava_tempval)&0x50505050)==0x40000040)\n"
                    // 4. (mp3ninja) << "((lava_tempval=(lava_extra[slot]>>16),lava_tempval=__builtin_powif(lava_tempval,__builtin_ctz(*(int*)&lava_tempval)),__builtin_parity(*(int*)&lava_tempval)) && (lava_tempval=(lava_extra[slot]>>16),lava_tempval*=1337,(*(int*)&lava_tempval)&0xf0==0xf0))\n"
                    //<< "#define lava_check_const_high_5(slot) "
                    // 1. (regview) << "((__builtin_clz(lava_extra[slot])>4) && (((((lava_extra[slot]>>16)*0xfe)&0xf0f0)&0xffff)==0xf0f0))\n"
                    // 2. (zipread) << "((__builtin_parity((lava_extra[slot]>>16)&0x5aa5)) && (!((lava_extra[slot]>>16)&0x9009)))\n"
                    // 3. (graphland) << "(((lava_extra[slot]>>16)*(lava_extra[slot]>>16)+(lava_extra[slot]>>16)+1)&7==5) && (lava_tempval=(lava_extra[slot]>>16),((P8((*(int*)(&lava_tempval))>>24,37)^P2((*(int*)(&lava_tempval))>>24,23))&0xff)==0)\n"
                    // 4. (mp3ninja) << "((lava_tempval=(lava_extra[slot]>>16),lava_tempval+=0xdeadbeef,(*(int*)&lava_tempval)%10>5) && (lava_tempval=(lava_extra[slot]>>16),lava_tempval*=1337,(*(int*)&lava_tempval)&0xf0==0xf0))\n"
                    //<< "#define lava_check_const_high_6(slot) "
                    // 1. (regview) << "((((((lava_extra[slot]>>16)*0xfe)&0xf0f0)&0xffff)==0xf0f0) && (!(((lava_extra[slot])>>18)&1)))\n"
                    // 2. (zipread) << "((__builtin_ffs(lava_extra[slot]>>16)>3) && (__builtin_clz(lava_extra[slot])>4))\n"
                    // 3. (graphland) << "(__builtin_clz(lava_extra[slot])) && ((P8(lava_extra[slot]>>16, 349)*P2(lava_extra[slot]>>16, 439))&0xf == (P8(lava_extra[slot]>>16, 349)+P2(lava_extra[slot]>>16, 439))&0xf)\n"
                    // 4. (mp3ninja) << "((lava_tempval=(lava_extra[slot]>>16)^0x5555,lava_tempval=(__builtin_powif(lava_tempval,__builtin_popcount(*(int*)&lava_tempval)%7)),(__builtin_popcount(*(int*)&lava_tempval)&0xf)==7) && (lava_tempval=(lava_extra[slot]>>16),lava_tempval/=0xbeefdead,(*(int*)&lava_tempval)>5))\n"

                    //<< "#define lava_check_const_high_pass(slot) "
                    // 1. (regview) << "((!(lava_extra[slot]>>31)) && ((((lava_extra[slot]>>16)*0xfe)&0xf0f0)==0xf0f0))\n"
                    // 2. (zipread) << "((__builtin_clz(lava_extra[slot])) && (!(__builtin_parity((lava_extra[slot])>>16))))\n"
                    // 3. (graphland) << "(lava_tempval=((lava_extra[slot]>>16)&0xffff),lava_tempval=(__builtin_powif(lava_tempval,8)+__builtin_powif(lava_tempval,3)),((*(int*)&lava_tempval)&0x50505050)==0x40000040) && (__builtin_clz(lava_extra[slot]))\n"
                    // 4. (mp3ninja) << "((lava_tempval=(lava_extra[slot]>>16),lava_tempval=(__builtin_powif(lava_tempval,7)),(*(int*)&lava_tempval)&1) && (lava_tempval=((lava_extra[slot]>>16)^0x5555),__builtin_clz(*(int*)&lava_tempval)))\n"

                    << "#define lava_check_const_high(slot) "
                    << "(((lava_extra[slot]>>16)&0xffff)==0x0011)\n"
                    //<< "__attribute__((visibility(\"default\")))\n"
                    << "#define lava_update_const_high(slot) "
                    << "{ lava_state[slot]|=1; }\n"

                    //<< "__attribute__((visibility(\"default\")))\n"
                    //<< "#define lava_check_const_low(slot, val) "
                    //<< "(lava_extra[slot]&val)\n"
                    << "#define lava_check_const_low_1(slot) "
                    << "((!(__builtin_popcount(lava_extra[slot]&0x5aa5)&2)) && (__builtin_clz(lava_extra[slot]<<16)))\n"
                    << "#define lava_check_const_low_2(slot) "
                    << "((lava_tempval=(lava_extra[slot]&0xffff),__builtin_ffs(*(int*)&lava_tempval)>15) && (lava_tempval=(lava_extra[slot]&0xffff),__builtin_popcount(*(int*)&lava_tempval)>11))\n"
                    << "#define lava_check_const_low_3(slot) "
                    << "((lava_tempval=(lava_extra[slot]&0xffff),((*(int*)(&lava_tempval))&0xf000000)==0x5000000) && (lava_tempval=(lava_extra[slot]&0xffff),((*(int*)(&lava_tempval))&0xf000)<0x7000))\n"
                    << "#define lava_check_const_low_4(slot) "
                    << "(((((lava_extra[slot]&0xffff)*0xfe)&0xf0f0)==0xf0f0) && (__builtin_ffs(lava_extra[slot])>3))\n"
                    << "#define lava_check_const_low_5(slot) "
                    << "((lava_tempval=(lava_extra[slot]&0xffff),lava_tempval+=0xdeadbeef,((*(int*)&lava_tempval)%10)>5) && (lava_tempval=(lava_extra[slot]&0xffff),lava_tempval*=1337,((*(int*)&lava_tempval)&0xf0)==0xf0))\n"
                    << "#define lava_check_const_low_6(slot) "
                    << "((lava_tempval=((lava_extra[slot])&0xffff),lava_tempval=(__builtin_powif(lava_tempval,8)+__builtin_powif(lava_tempval,3)),((*(int*)&lava_tempval)&0x50505050)==0x40000040) && (__builtin_clz(lava_extra[slot]<<16)))\n"

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
