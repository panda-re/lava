// Clang rewriter to initialize all uninitialized variables
// to '={0}' (AKA null for any type)

// It's a bit messy because it duplicates some classes
// from LavaMatchHandler.h that we can't use directly
// because that file does too many other things

#include "lava.hxx"
#include "lexpr.hxx"

#include "Insertions.h"
#include "Modifier.h"

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <iostream>

#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"

#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"

#include "clang/Frontend/CompilerInstance.h"

#include "llvm/Support/CommandLine.h"

#define LOG (1 << 0)
#define INI (1 << 1)
#define DEBUG_FLAGS (INI | LOG)

using namespace clang::tooling;
using namespace llvm;
using namespace clang;
using namespace clang::ast_matchers;
using namespace std;

static llvm::raw_null_ostream null_ostream;
#define debug(flag) ((DEBUG_FLAGS & (flag)) ? static_cast<llvm::raw_ostream&>(llvm::errs()) : static_cast<llvm::raw_ostream&>(null_ostream))


static cl::OptionCategory LavaInitCategory("LAVA Init Tool");
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp(
    "\nRewrite source to explicitly initialize all variables to 0.\n");

// TODO: replace MyMatchHandler with LavaMatchHandler from LavaMatchHandler.h
struct MyMatchHandler : public MatchFinder::MatchCallback {
    MyMatchHandler(Modifier &Mod) : Mod(Mod) {}

    virtual void handle(const MatchFinder::MatchResult &Result) = 0;

    virtual void run(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;
        auto nodesMap = Result.Nodes.getMap();

        debug(LOG) << "====== Found Match =====\n";
        assert(Mod.sm != nullptr);
        handle(Result); // If we don't crash, do we hit the HandleBeginSource?
    }

    const LangOptions *LangOpts = nullptr;
protected:
    Modifier &Mod;
};

// Here we initialize all the uninitialized variables
struct InitHandler : public MyMatchHandler {
    using MyMatchHandler::MyMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;

        // get our DeclStmt containing the varDecl
        const DeclStmt *declS = Result.Nodes.getNodeAs<DeclStmt>("decl");
        if (declS == NULL) return;

        // Cast the DeclStmt to a general-purpose Stmt
        const Stmt *s = dyn_cast<Stmt>(declS);
        if (s == NULL) return;

        debug(INI) << "Adding new initialization\n";
        Mod.Change(s).InsertAfterRel(1, "={0}");
    }
};

// This is a modified version of LavaMatchFinder in MatchFinder.h
// It just has different callbacks.
// TODO: make a parent class that they can both use
class Initializer : public MatchFinder, public SourceFileCallbacks {
public:
    Initializer() : Mod(Insert) {
        addMatcher(
            declStmt(has(varDecl(unless(hasInitializer(anything()))).bind("var_decl")))
                .bind("decl"),
            makeHandler<InitHandler>()
        );
    }

    virtual bool handleBeginSource(CompilerInstance &CI) override {
        Insert.clear();
        Mod.Reset(&CI.getLangOpts(), &CI.getSourceManager());
        TUReplace.Replacements.clear();
        TUReplace.MainSourceFile = CI.getSourceManager().getFileEntryForID(CI.getSourceManager().getMainFileID())->getName().str(); // Convert StringRef to std::string
        CurrentCI = &CI;

        debug(LOG) << "*** handleBeginSource for: " << TUReplace.MainSourceFile << "\n";

        for (auto it = MatchHandlers.begin(); it != MatchHandlers.end(); it++) {
            (*it)->LangOpts = &CI.getLangOpts();
        }
        return true;
    }

    virtual void handleEndSource() override {
        debug(LOG) << "*** handleEndSource\n";

        // Now 'render' our changes into the produced .yaml file
        Insert.render(CurrentCI->getSourceManager(), TUReplace.Replacements);
        std::error_code EC;
        llvm::raw_fd_ostream YamlFile(TUReplace.MainSourceFile + ".yaml",
                EC, llvm::sys::fs::OF_None);
        yaml::Output Yaml(YamlFile);
        Yaml << TUReplace;
    }

    template<class Handler>
    MyMatchHandler *makeHandler() {
        MatchHandlers.emplace_back(new Handler(Mod));
        return MatchHandlers.back().get();
    }

private:
    Insertions Insert;
    Modifier Mod;
    TranslationUnitReplacements TUReplace;
    std::vector<std::unique_ptr<MyMatchHandler>> MatchHandlers;
    CompilerInstance *CurrentCI = nullptr;
};


int main(int argc, const char **argv) {
    CommonOptionsParser OptionsParser(argc, argv, LavaInitCategory);
    ClangTool Tool(OptionsParser.getCompilations(),
                   OptionsParser.getSourcePathList());

    Initializer Init;
    int rv = Tool.run(newFrontendActionFactory(&Init, &Init).get());

    return rv;
}
