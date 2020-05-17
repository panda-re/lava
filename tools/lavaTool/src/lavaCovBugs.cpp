// Clang rewriter to add a trivial bug into functions we can't get coverage of

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
#include <vector>
#include <utility>

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
#define COV (1 << 1)
#define MATCHER (1 << 2)
#define DEBUG_FLAGS ( COV | LOG | MATCHER )
using namespace clang::tooling;
using namespace llvm;
using namespace clang;
using namespace clang::ast_matchers;
using namespace std;

static llvm::raw_null_ostream null_ostream;
#define debug(flag) ((DEBUG_FLAGS & (flag)) ? llvm::errs() : null_ostream)

static cl::OptionCategory LavaCovBugsCategory("LAVA Coverage Bug Tool");
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp(
    "\nRewrite source to add bugs everywhere\n");
static cl::opt<unsigned int> ArgRandSeed("randseed",
    cl::desc("Value to use as random seed when selecting which bugs to add"),
    cl::cat(LavaCovBugsCategory),
    cl::init(0));

// TODO: replace MyMatchHandler with LavaMatchHandler from LavaMatchHandler.h
struct MyMatchHandler : public MatchFinder::MatchCallback {
    MyMatchHandler(Modifier &Mod) : Mod(Mod) {}

    virtual void handle(const MatchFinder::MatchResult &Result) = 0;

    virtual void run(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;
        auto nodesMap = Result.Nodes.getMap();

        //debug(LOG) << "====== Found Match =====\n";
        assert(Mod.sm != nullptr);
        handle(Result); // If we don't crash, do we hit the HandleBeginSource?
    }

    const LangOptions *LangOpts = nullptr;
protected:
    Modifier &Mod;
};

struct CovBugHandler : public MyMatchHandler {
    using MyMatchHandler::MyMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;

        // get our DeclStmt containing the varDecl
        const Stmt *s = Result.Nodes.getNodeAs<Stmt>("stmt");
        if (s == NULL) return;

        if (rand() % 100 > 5) {
            return; // Skip 95% of injection opportunities
        }
        //debug(COV) << "Adding new COV bug\n";

        auto sl = s->getLocStart();
        unsigned int lineNum = sm.getExpansionLineNumber(sl);

        std::string before;
        before = "; " + LFunc("LAVABUG",
            {LDecimal(lineNum)}).render() + "; ";

        Mod.Change(s).InsertBefore(before);
    }
};

// This is a modified version of LavaMatchFinder in MatchFinder.h
class CovBugs : public MatchFinder, public SourceFileCallbacks {
public:
    CovBugs() : Mod(Insert) {
        // This matches every stmt in a compound statement
        // So "stmt" in
        // stmt; stmt'; stmt''; stmt'''; etc
        // Used to add pri queries (in turn used by PANDA to know where it is
        // in the source whe querying taint).  Also used to insert DUA siphons
        // (first half of a bug) but also stack-pivot second-half of bug.
        addMatcher(
                stmt(hasParent(compoundStmt())).bind("stmt"),
                makeHandler<CovBugHandler>()
                );
    }

    virtual bool handleBeginSource(CompilerInstance &CI, StringRef Filename) override {
        Insert.clear();
        Mod.Reset(&CI.getLangOpts(), &CI.getSourceManager());
        TUReplace.Replacements.clear();
        TUReplace.MainSourceFile = Filename;
        CurrentCI = &CI;

        debug(LOG) << "*** handleBeginSource for: " << Filename << "\n";

        std::stringstream logging_macros;

        logging_macros << "#ifdef LAVA_LOGGING\n"
                       << "#define LAVABUG(x) {x==lavaval ? (fprintf(stderr, \"\\nLAVALOG_COV: %d: %s:%d\\n\", x, __FILE__, __LINE__), *(int*)x = 0) : x; }\n"
                       << "#else\n"
                       << "#define LAVABUG(x) {x==lavaval ? (*(int*)x = 0) : x; }\n"
                       << "#endif\n";

        TUReplace.Replacements.emplace_back(Filename, 0, 0, logging_macros.str());

        for (auto it = MatchHandlers.begin();
                it != MatchHandlers.end(); it++) {
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
                EC, llvm::sys::fs::F_RW);
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
    CommonOptionsParser OptionsParser(argc, argv, LavaCovBugsCategory);
    ClangTool Tool(OptionsParser.getCompilations(),
                   OptionsParser.getSourcePathList());

    // First split up the UncoveredFuncs list into an array of arrays
    // which we'll then use to decide if we should inject and also
    // modify after we do inject
    srand(ArgRandSeed);

    CovBugs Init;
    int rv = Tool.run(newFrontendActionFactory(&Init, &Init).get());
    return rv;
}
