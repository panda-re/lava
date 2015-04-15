#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;

// instruction count
typedef uint64_t Instr;
// taint label (input byte #)
typedef uint32_t Label;
// line number
typedef uint32_t Line;
// Taint Compute Number
typedef uint32_t Tcn;
// ptr used to ref a label set
typedef uint64_t Ptr;

typedef struct dua_struct {
    std::string filename;
    Line line;
    std::string lvalname;
    std::set < Label > labels;   
    std::string str() const {
        std::stringstream crap1;
        crap1 << filename << "," << line << "," << lvalname << ",[";
        for ( auto l : labels ) {
            crap1 << l << ",";
        }
        crap1 << "]";
        return crap1.str();
    }    

    attack_point_struct(const istream& is) {
        std::string temp;
        std::getline(is, filename, ',');
        std::getline(is, temp, ',');
        line = std::stoul(temp);
        std::getline(is, lvalname, ',');
        assert(is.get() == '[');
        while (is.peek() != ']') {
            std::getline(is, temp, ',');
            labels.insert(std::stoul(temp));
        }
        std::getline(is, temp);
    }

    bool operator<(const struct dua_struct &other) const {
        return (str() < other.str());
    }
} Dua;
std::vector<Dua> duas;

typedef struct attack_point_struct {
    std::string filename;
    Line line;
    std::string type;
    std::string str() const {
        std::stringstream crap1;
        crap1 << filename << "," << line << "," << type;
        return crap1.str();
    }

    attack_point_struct(const istream& is) {
        std::string temp;
        std::getline(is, filename, ',');
        std::getline(is, temp, ',');
        line = std::stoul(temp);
        std::getline(is, type);
    }

    bool operator<(const struct attack_point_struct &other) const {
        return (str() < other.str());
    }
} AttackPoint;
std::vector<AttackPoint> aps;

static llvm::cl::OptionCategory
    TransformationCategory("Lava Insert Bug Transformation");

static Matcher<CallExpr> memcpyMatcher = callExpr(hasName("memcpy")).bind("id");

static ifstream dd_ifstream, ap_ifstream, bug_ifstream;

class LavaInsertBugASTVisitor :
    public RecursiveASTVisitor<LavaInsertBugASTVisitor> {
public:
    LavaInsertBugASTVisitor(Rewriter &rewriter,
        std::vector< VarDecl* > &globalVars) :
            rewriter(rewriter), globalVars(globalVars)  {}

    bool TraverseDecl(Decl *d) {
        if (!d) return true;

        SourceManager &sm = rewriter.getSourceMgr();
        if (sm.isInMainFile(d->getLocation()))
            return RecursiveASTVisitor<LavaInsertBugASTVisitor>::TraverseDecl(d);
        
        return true;
    }

    bool VisitFunctionDecl(FunctionDecl *f) {
        if (f->hasBody()) {
        }
    }

    // give me an expr and i'll return the string repr from original source
    std::string ExprStr(Expr *e) {
        const clang::LangOptions &LangOpts = rewriter.getLangOpts();
        clang::PrintingPolicy Policy(LangOpts);
        std::string TypeS;
        llvm::raw_string_ostream s(TypeS);
        e->printPretty(s, 0, Policy);
        return s.str();
    }

private:
    std::vector< VarDecl* > &globalVars;
    Rewriter &rewriter;
};


class LavaInsertBugASTConsumer : public ASTConsumer {
public:
    LavaInsertBugASTConsumer(Rewriter &rewriter) :
        visitor(rewriter, globalVars) {}

    bool HandleTopLevelDecl(DeclGroupRef DR) override {
    // iterates through decls
        for (DeclGroupRef::iterator b = DR.begin(), e = DR.end(); b != e; ++b) {
            // for debug
            //(*b)->dump();
            VarDecl *vd = dyn_cast<VarDecl>(*b);
            if (vd) {
                if (vd->isFileVarDecl() && vd->hasGlobalStorage())
                {
                    globalVars.push_back(vd);
                }  
            }
            else
                visitor.TraverseDecl(*b);
        }
        return true;
    }

private:
    LavaInsertBugASTVisitor visitor;
    std::vector< VarDecl* > globalVars;
};

/*
 * clang::FrontendAction
 *      ^
 * clang::ASTFrontendAction
 *      ^
 * clang::PluginASTAction
 *
 * This inheritance pattern allows this class (and the classes above) to be used
 * as both a libTooling tool, and a Clang plugin.  In the libTooling case, the
 * plugin-specific methods just aren't utilized.
 */
class LavaInsertBugFrontendAction : public PluginASTAction {
public:
    LavaInsertBugFrontendAction() {}
  
    void EndSourceFileAction() override {
        SourceManager &sm = rewriter.getSourceMgr();
        llvm::errs() << "** EndSourceFileAction for: "
                     << sm.getFileEntryForID(sm.getMainFileID())->getName()
                     << "\n";

        // Last thing: include the right file
        // Now using our separate LAVA version
        rewriter.InsertText(sm.getLocForStartOfFile(sm.getMainFileID()),
            "#include \"pirate_mark_lava.h\"\n", true, true);
        rewriter.overwriteChangedFiles();
    }

    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                     StringRef file) override {
        rewriter.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
        llvm::errs() << "** Creating AST consumer for: " << file << "\n";
        return llvm::make_unique<LavaInsertBugASTConsumer>(rewriter);
    }

    /**************************************************************************/
    // Plugin-specific functions
    bool ParseArgs(const CompilerInstance &CI,
            const std::vector<std::string>& args) override {
        // No args currently
        return true;
    }
    
    void PrintHelp(llvm::raw_ostream& ros) {
        ros << "Help for insert-bug plugin goes here\n";
    }

private:
    Rewriter rewriter;
};

/*
 * Usage: build/taintQueryTool <C file> --
 */

int main(int argc, const char **argv) {
    std::string path(argv[argc - 1]);
    dd_ifstream.open(path + ".duas");
    ap_ifstream.open(path + ".bugs");
    bug_ifstream.open(path + ".aps");
    argc -= 1;

    while (!dd_ifstream.eof()) {
        dds.emplace_back(dd_ifstream);
    }
    while (!ap_ifstream.eof()) {
        aps.emplace_back(ap_ifstream);
    }

    CommonOptionsParser op(argc, argv, TransformationCategory);

    ClangTool Tool(op.getCompilations(), op.getSourcePathList());

    return Tool.run(
        newFrontendActionFactory<LavaInsertBugFrontendAction>().get());
}
