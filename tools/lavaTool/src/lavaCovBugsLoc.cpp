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
#define INI (1 << 1)
#define DEBUG_FLAGS ( INI | LOG )

using namespace clang::tooling;
using namespace llvm;
using namespace clang;
using namespace clang::ast_matchers;
using namespace std;

typedef std::pair<std::string, vector<int>> func_pair_t;
vector<func_pair_t> funcs;

static llvm::raw_null_ostream null_ostream;
#define debug(flag) ((DEBUG_FLAGS & (flag)) ? llvm::errs() : null_ostream)

static cl::OptionCategory LavaCovBugsCategory("LAVA Coverage Bug Tool");
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp(
    "\nRewrite source to add trivial bugs at requested locations\n");

static cl::opt<string> UncoveredFuncs("funcs",
    cl::desc("List of function_name:(l1,l2),function_name2:(l1,l2) to add bugs to"),
    cl::cat(LavaCovBugsCategory),
    cl::init("XXX"));

// TODO: replace MyMatchHandler with LavaMatchHandler from LavaMatchHandler.h
struct MyMatchHandler : public MatchFinder::MatchCallback {
    MyMatchHandler(Modifier &Mod) : Mod(Mod) {}

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;

        debug(LOG) << "====== HANDLING =====\n";

        // get our return stmt as a statement
        const ReturnStmt *r = Result.Nodes.getNodeAs<ReturnStmt>("returnStmt");
        if (r == NULL) return;
        debug(LOG) << "\t have returnStmt\n";

        const Stmt *s = dyn_cast<Stmt>(r);
        if (s == NULL) return;
        debug(LOG) << "\t have stmt\n";

        auto sl = s->getLocStart();
        unsigned int lineNum = sm.getExpansionLineNumber(sl);

        std::string before;
        before = "; " + LFunc("LAVABUG",
            {LDecimal(lineNum)}).render() + "; ";

        Mod.Change(s).InsertBefore(before);
    }

    virtual void run(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;
        auto nodesMap = Result.Nodes.getMap();

        // get the stmt and decide if we should handle this
        const Stmt *s = Result.Nodes.getNodeAs<Stmt>("returnStmt");
        if (s == NULL) return;

        auto sl = s->getLocStart();
        unsigned int lineNum = sm.getExpansionLineNumber(sl);

        // Check if we need to instrument this line number
        bool instrument=false;
        string fn_name;
        for (auto i = funcs.begin(); i != funcs.end(); ++i){
            //printf("%s: ", i->first.c_str()); // Func name
            for (auto j:i->second)  {
                if (j == lineNum) {
                    fn_name=i->first;
                    printf("Instrument line %d in %s\n", lineNum, fn_name.c_str());
                    instrument=true;
                    break;
                }
            }
        }

        if (instrument) {
            debug(LOG) << "====== Found Match to instrument =====\n";
            assert(Mod.sm != nullptr);

            handle(Result); // If we don't crash, do we hit the HandleBeginSource?
        }
    }

    const LangOptions *LangOpts = nullptr;
protected:
    Modifier &Mod;
};

// This is a modified version of LavaMatchFinder in MatchFinder.h. Slightly modified from lavaCovBugs.cpp
class CovBugs : public MatchFinder, public SourceFileCallbacks {
public:
    CovBugs() : Mod(Insert) {
        // This matches every return stmt in a compound statement
        // So "stmt" in
        // stmt; stmt'; stmt''; stmt'''; etc
        // Used to add pri queries (in turn used by PANDA to know where it is
        // in the source whe querying taint).  Also used to insert DUA siphons
        // (first half of a bug) but also stack-pivot second-half of bug.
        addMatcher(
                returnStmt().bind("returnStmt"),
                makeHandler<MyMatchHandler>()
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
                       << "#define LAVABUG(bugid)  ({(fprintf(stderr, \"\\nLAVALOG: %d: %s:%d\\n\", bugid, __FILE__, __LINE__)), *(int*)x = x);})\n"
                       << "#else\n"
                       << "#define LAVABUG(x) {(*(int*)x = x);}\n"
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

int parse_funcs() { 
    // Parse input argument to build funcs vector of function names->lines
    size_t lastpos = 0;
    size_t curpos = 0;
    size_t endpos = 0;
    // For each function, pull out list of lines
    while((curpos = UncoveredFuncs.find(":[", lastpos)) != std::string::npos) {
        endpos = UncoveredFuncs.find("]", curpos);
        string fname = UncoveredFuncs.substr(lastpos, curpos-lastpos);
        curpos+=2; // Skip :[


        string loc_str = UncoveredFuncs.substr(curpos, endpos-curpos);

        //printf("%s: %s\n", fname.c_str(), UncoveredFuncs.substr(curpos, endpos-curpos).c_str());

        size_t loc_c = 0;
        size_t last_loc_c = 0;
        int loc;
        vector<int> locs;
        while((loc_c = loc_str.find(",", last_loc_c)) != std::string::npos) {
            string this_loc = loc_str.substr(last_loc_c, loc_c-last_loc_c);
            //printf("%s: %s\n", fname.c_str(), this_loc.c_str());
            loc = atoi(this_loc.c_str());
            locs.push_back(loc);

            last_loc_c = loc_c+1;
        }

        // Final one after parsing all comas
        if (last_loc_c != 0) {
            string this_loc = loc_str.substr(last_loc_c);
            loc = atoi(this_loc.c_str());
            locs.push_back(loc);
            //printf("%s: %s\n", fname.c_str(), this_loc.c_str());
        }

        lastpos = endpos+2;

        // Now update funcs vector
        func_pair_t p = make_pair(fname, locs);
        funcs.push_back(p);
    }

    // Debug print
    for (auto i = funcs.begin(); i != funcs.end(); ++i){
        printf("%s: ", i->first.c_str());
        for (auto j:i->second)  {
            printf("%d, ", j);
        }
        printf("\n");
    }
}

int main(int argc, const char **argv) {
    CommonOptionsParser OptionsParser(argc, argv, LavaCovBugsCategory);
    ClangTool Tool(OptionsParser.getCompilations(),
                   OptionsParser.getSourcePathList());

    // First split up the UncoveredFuncs list into an array of arrays
    // which we'll then use to decide if we should inject and also
    // modify after we do inject

    if (strcmp(UncoveredFuncs.c_str(), "XXX") == 0) {
        printf("Error, --funcs required\n");
        return 1;
    }

    // input: func_name:[1,2,3], ...
    parse_funcs(); // Parse into funcs vector<str, vector<int>>

    CovBugs Init;
    int rv = Tool.run(newFrontendActionFactory(&Init, &Init).get());

    return rv;
}
