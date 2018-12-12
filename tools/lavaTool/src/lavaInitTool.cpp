// TODO splitting this into its own tool doesn't work prior to the mbr-merge
// It needs to include Insertions and Mod classes which the mbr-branch has refactored
// out of lavatool. On the current branch, these are part of lavaTool and it's not
// worth fixing it since we're about to merge into MBR

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

#include "llvm/Support/CommandLine.h"

#include "Insertions.h"
#include "Modifier.h"

#define LOG (1 << 0)
#define INI (1 << 1)
#define DEBUG_FLAGS INI // ( INI | LOG )

using namespace clang::tooling;
using namespace llvm;using namespace clang;
using namespace clang;
using namespace clang::ast_matchers;

using namespace std;


static llvm::raw_null_ostream null_ostream;
#define debug(flag) ((DEBUG_FLAGS & (flag)) ? llvm::errs() : null_ostream)

// globals to track our changes
Insertions Insert;
Modifier Mod;

static cl::OptionCategory LavaInitCategory("LAVA Init Tool");
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp(
    "\nRewrite source to explicitly initialize all variables to 0.\n");

class Initializer : public MatchFinder::MatchCallback {
    public:
    virtual void run(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;

        /* We don't actually need this
        // Get varDecl and make sure it isn't alrady initailized
        const VarDecl *varDecl = Result.Nodes.getNodeAs<VarDecl>("var_decl");
        if (varDecl == NULL) return;
        assert(varDecl != NULL && varDecl->getInit() == NULL); // Must not be initialized already
        */

        // get our DeclStmt containing the varDecl
        const DeclStmt *declS = Result.Nodes.getNodeAs<DeclStmt>("decl");
        if (declS == NULL) return;

        // Cast the DeclStmt to a general-purpose Stmt
        const Stmt *s = dyn_cast<Stmt>(declS);
        if (s == NULL) return;

        // TODO, can we log the real location here?
        // Get the ASTLoc of our stmt
        //LavaASTLoc ast_loc = GetASTLoc(sm, s);
        //debug(INI) << "Have to initialize variable @ " << ast_loc << "!\n";
        debug(INI) << "Initialize something \n";

        Mod.Change(s).InsertAfterRel(1, "={0}");
    }
};



int main(int argc, const char **argv) {
    CommonOptionsParser OptionsParser(argc, argv, LavaInitCategory);
    ClangTool Tool(OptionsParser.getCompilations(),
                   OptionsParser.getSourcePathList());

    MatchFinder Finder;
    Initializer init;

    Finder.addMatcher(
        declStmt(hasDescendant(varDecl(unless(hasInitializer(anything()))).bind("var_decl")))
            .bind("decl"),
        &init
    );

    int rv = Tool.run(newFrontendActionFactory(&Finder).get());

    //TODO  apply modifications and rewrite file
    return rv;
}

