#include "FunctionArgHandler.h"
#include "MemoryAccessHandler.h"
#include "PriQueryPointHandler.h"
#include "ReadDisclosureHandler.h"
#include "FuncDuplicationHandler.h"
#include "FuncDeclArgAdditionHandler.h"
#include "FunctionPointerFieldHandler.h"
#include "CallExprArgAdditionalHandler.h"

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

class GenericMatchFinder {
public:
    GenericMatchFinder() : Mod(Insert) {}

    template<class Handler>
    LavaMatchHandler *makeHandler() {
        MatchHandlers.emplace_back(new Handler(Mod));
        return MatchHandlers.back().get();
    }

protected:
    Insertions Insert;
    Modifier Mod;
    TranslationUnitReplacements TUReplace;
    std::vector<std::unique_ptr<LavaMatchHandler>> MatchHandlers;
    CompilerInstance *CurrentCI = nullptr;

};

// Rahul's Parameters Injection
class LavaStageOneFinder : public MatchFinder,
                        public GenericMatchFinder,
                        public SourceFileCallbacks {
public:
    LavaStageOneFinder() : GenericMatchFinder() {
        if (ArgDataflow && LavaAction == LavaInjectBugs) {
            addMatcher(
                    functionDecl().bind("funcDecl"),
                    makeHandler<FuncDeclArgAdditionHandler>());
            addMatcher(
                    callExpr().bind("callExpr"),
                    makeHandler<CallExprArgAdditionHandler>());
            addMatcher(
                    fieldDecl(anyOf(hasName("as_number"), hasName("as_string"))).bind("fieldDecl"),
                    makeHandler<FunctionPointerFieldHandler>());
        }
    }

    virtual bool handleBeginSource(CompilerInstance &CI, StringRef Filename) override {
        Insert.clear();
        Mod.Reset(&CI.getLangOpts(), &CI.getSourceManager());
        TUReplace.Replacements.clear();
        TUReplace.MainSourceFile = Filename;
        CurrentCI = &CI;

        debug(INJECT) << "*** handleBeginSource for: " << Filename << "\n";

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

};

// Andrea's function duplication
class LavaStageTwoFinder : public MatchFinder,
                        public GenericMatchFinder,
                        public SourceFileCallbacks {
public:
    LavaStageTwoFinder() : GenericMatchFinder() {
        addMatcher(
                functionDecl().bind("funcDecl"),
                makeHandler<FuncDuplicationHandler>());
    }

    virtual bool handleBeginSource(CompilerInstance &CI, StringRef Filename) override {
        Insert.clear();
        Mod.Reset(&CI.getLangOpts(), &CI.getSourceManager());
        TUReplace.Replacements.clear();
        TUReplace.MainSourceFile = Filename;
        CurrentCI = &CI;

        debug(INJECT) << "*** handleBeginSource for: " << Filename << "\n";

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

};

// Final Lava bugs injection pass
class LavaStageThreeFinder : public MatchFinder,
                        public GenericMatchFinder,
                        public SourceFileCallbacks {
public:
    LavaStageThreeFinder() : GenericMatchFinder() {
        StatementMatcher memoryAccessMatcher =
            allOf(
                expr(anyOf(
                    arraySubscriptExpr(
                        hasIndex(ignoringImpCasts(
                                expr().bind("innerExpr")))),
                    unaryOperator(hasOperatorName("*"),
                        hasUnaryOperand(ignoringImpCasts(
                                expr().bind("innerExpr")))))).bind("lhs"),
                anyOf(
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

        addMatcher(
                stmt(hasParent(compoundStmt())).bind("stmt"),
                makeHandler<PriQueryPointHandler>()
                );

        addMatcher(
                callExpr(
                    forEachArgMatcher(expr(isAttackableMatcher()).bind("arg"))),
                makeHandler<FunctionArgHandler>()
                );

        addMatcher(memoryAccessMatcher, makeHandler<MemoryAccessHandler>());

        addMatcher(
                callExpr(
                    callee(functionDecl(hasName("::printf"))),
                    unless(argumentCountIs(1))).bind("call_expression"),
                makeHandler<ReadDisclosureHandler>()
                );
    }

    virtual bool handleBeginSource(CompilerInstance &CI, StringRef Filename) override {
        Insert.clear();
        Mod.Reset(&CI.getLangOpts(), &CI.getSourceManager());
        TUReplace.Replacements.clear();
        TUReplace.MainSourceFile = Filename;
        CurrentCI = &CI;

        debug(INJECT) << "*** handleBeginSource for: " << Filename << "\n";

        std::string insert_at_top;
        if (LavaAction == LavaQueries) {
            insert_at_top = "#include \"pirate_mark_lava.h\"\n";
        } else if (LavaAction == LavaInjectBugs && !ArgDataflow) {
            if (main_files.count(getAbsolutePath(Filename)) > 0) {
                std::stringstream top;
                top << "static unsigned int lava_val[" << data_slots.size() << "] = {0};\n"
                    << "void lava_set(unsigned int, unsigned int);\n"
                    << "__attribute__((visibility(\"default\")))\n"
                    << "void lava_set(unsigned int slot, unsigned int val) { lava_val[slot] = val; }\n"
                    << "unsigned int lava_get(unsigned int);\n"
                    << "__attribute__((visibility(\"default\")))\n"
                    << "unsigned int lava_get(unsigned int slot) { return lava_val[slot]; }\n";
                insert_at_top = top.str();
            } else {
                insert_at_top =
                    "void lava_set(unsigned int bn, unsigned int val);\n"
                    "extern unsigned int lava_get(unsigned int);\n";
            }
        }

        debug(INJECT) << "Inserting at top of file: \n" << insert_at_top;
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

};


class LavaMatchFinder : public MatchFinder,
                        public GenericMatchFinder,
                        public SourceFileCallbacks {
public:
    LavaMatchFinder() : GenericMatchFinder() {
        StatementMatcher memoryAccessMatcher =
            allOf(
                expr(anyOf(
                    arraySubscriptExpr(
                        hasIndex(ignoringImpCasts(
                                expr().bind("innerExpr")))),
                    unaryOperator(hasOperatorName("*"),
                        hasUnaryOperand(ignoringImpCasts(
                                expr().bind("innerExpr")))))).bind("lhs"),
                anyOf(
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

        addMatcher(
                stmt(hasParent(compoundStmt())).bind("stmt"),
                makeHandler<PriQueryPointHandler>()
                );

        addMatcher(
                callExpr(
                    forEachArgMatcher(expr(isAttackableMatcher()).bind("arg"))),
                makeHandler<FunctionArgHandler>()
                );

        addMatcher(memoryAccessMatcher, makeHandler<MemoryAccessHandler>());

        // fortenforge's matchers (for argument addition)
        if (ArgDataflow && LavaAction == LavaInjectBugs) {
            addMatcher(
                    functionDecl().bind("funcDecl"),
                    makeHandler<FuncDeclArgAdditionHandler>());
            addMatcher(
                    callExpr().bind("callExpr"),
                    makeHandler<CallExprArgAdditionHandler>());
            addMatcher(
                    fieldDecl(anyOf(hasName("as_number"), hasName("as_string"))).bind("fieldDecl"),
                    makeHandler<FunctionPointerFieldHandler>());
        }

        addMatcher(
                callExpr(
                    callee(functionDecl(hasName("::printf"))),
                    unless(argumentCountIs(1))).bind("call_expression"),
                makeHandler<ReadDisclosureHandler>()
                );
    }

    virtual bool handleBeginSource(CompilerInstance &CI, StringRef Filename) override {
        Insert.clear();
        Mod.Reset(&CI.getLangOpts(), &CI.getSourceManager());
        TUReplace.Replacements.clear();
        TUReplace.MainSourceFile = Filename;
        CurrentCI = &CI;

        debug(INJECT) << "*** handleBeginSource for: " << Filename << "\n";

        std::string insert_at_top;
        if (LavaAction == LavaQueries) {
            insert_at_top = "#include \"pirate_mark_lava.h\"\n";
        } else if (LavaAction == LavaInjectBugs && !ArgDataflow) {
            if (main_files.count(getAbsolutePath(Filename)) > 0) {
                std::stringstream top;
                top << "static unsigned int lava_val[" << data_slots.size() << "] = {0};\n"
                    << "void lava_set(unsigned int, unsigned int);\n"
                    << "__attribute__((visibility(\"default\")))\n"
                    << "void lava_set(unsigned int slot, unsigned int val) { lava_val[slot] = val; }\n"
                    << "unsigned int lava_get(unsigned int);\n"
                    << "__attribute__((visibility(\"default\")))\n"
                    << "unsigned int lava_get(unsigned int slot) { return lava_val[slot]; }\n";
                insert_at_top = top.str();
            } else {
                insert_at_top =
                    "void lava_set(unsigned int bn, unsigned int val);\n"
                    "extern unsigned int lava_get(unsigned int);\n";
            }
        }

        debug(INJECT) << "Inserting at top of file: \n" << insert_at_top;
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

};

