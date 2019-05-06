
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "clang/Lex/Lexer.h"
#include <iostream>
#include <fstream>

#include <odb/pgsql/database.hxx>
#include "lava-odb.hxx"
#include "lava.hxx"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
using namespace llvm;
using namespace llvm::sys::fs;
using namespace llvm::sys::path;

using namespace odb::core;
std::unique_ptr<odb::pgsql::database> db;
std::vector<std::shared_ptr<SourceLval>> _lvals;
std::set<uint64_t> finallvals;
std::map<uint64_t, LavaASTLoc> movedlocs;

static cl::opt<std::string> SourceDir("src-prefix",
    cl::desc("/home/tonyhu/Desktop/lava/lava/test_clang/XXX"),
    cl::init(""));
static cl::opt<std::string> BugDB("db",
    cl::desc("Database Name"),
    cl::init(""));

Loc::Loc(const FullSourceLoc &full_loc)
    : line(full_loc.getExpansionLineNumber()),
    column(full_loc.getExpansionColumnNumber()) {}

namespace {

std::string StripPrefix(std::string filename, std::string prefix) {
    size_t prefix_len = prefix.length();
    if (filename.compare(0, prefix_len, prefix) != 0) {
        printf("Not a prefix!\n");
        assert(false);
    }
    while (filename[prefix_len] == '/') prefix_len++;
    return filename.substr(prefix_len);
}

LavaASTLoc GetASTLoc(const SourceManager &sm, const Stmt *s) {
    FullSourceLoc fullLocStart(sm.getExpansionLoc(s->getLocStart()), sm);
    FullSourceLoc fullLocEnd(sm.getExpansionLoc(s->getLocEnd()), sm);
    std::string src_filename = StripPrefix(
            getAbsolutePath(sm.getFilename(fullLocStart)), SourceDir);
    size_t findhint = 0;
    while (src_filename.find("/../", findhint) != std::string::npos)
    {
        auto matchindex = src_filename.find("/../", findhint);
        if (matchindex >= 2 && src_filename[matchindex-1] == '.' && src_filename[matchindex-2] == '.')  { findhint = matchindex + 4; continue; }
        auto pos0 = src_filename.rfind('/', matchindex - 1);
        if (pos0 != std::string::npos)
            src_filename.erase(pos0, matchindex + 3 - pos0);
        else
            src_filename.erase(0, matchindex + 4);
    }
    return LavaASTLoc(src_filename, fullLocStart, fullLocEnd);
}

bool locInScope(const SourceManager &sm, const CompoundStmt *body, const SourceLval *sourcelval)
{
    LavaASTLoc loccomp = GetASTLoc(sm, body);
    LavaASTLoc locdua  = sourcelval->loc;
    return loccomp.filename == locdua.filename
        && (!(locdua.begin < loccomp.begin))
        && (!(loccomp.end < locdua.end));
}

std::vector<std::string> xtractMembers(const SourceLval *sourcelval)
{
    std::string astname = sourcelval->ast_name;
    std::vector<std::string> result;
    auto it = std::find_if_not(astname.begin(), astname.end(), [&](const char c) { return c == '(' || c == '*' || c == '&'; });
    while (it != astname.end())
    {
        auto previt = it;
        it = std::find_if(previt, astname.end(), [&](const char c) { return c == ')'; });
        result.push_back(std::string(previt, it));
        it = std::find_if_not(it, astname.end(), [&](const char c) { return c == '.' || c == ')'; });
    }
    return result;
}

class TestMatcher : public MatchFinder::MatchCallback {
public :
    bool rhsExprCheck(const Expr *expr, const std::vector<std::string> lvalelem)
    {
        bool isvalid = false;
        auto cur_expr = expr->IgnoreParenCasts();
        std::vector<std::string> cmpelem;
        while(true)
        {
            if (auto declref = dyn_cast<DeclRefExpr>(cur_expr)) {
                cmpelem.insert(cmpelem.begin(), declref->getFoundDecl()->getNameAsString());
                break;
            } else if (auto member = dyn_cast<MemberExpr>(cur_expr)) {
                cmpelem.insert(cmpelem.begin(), member->getMemberDecl()->getNameAsString());
                cur_expr = member->getBase()->IgnoreParenCasts();
            } else if (auto binop = dyn_cast<BinaryOperator>(cur_expr)) {
                if (binop->isAssignmentOp())
                {
                    return rhsExprCheck(binop->getRHS(), lvalelem);
                } else {
                    return rhsExprCheck(binop->getRHS(), lvalelem)
                        || rhsExprCheck(binop->getLHS(), lvalelem);
                }
            } else if (auto condop = dyn_cast<ConditionalOperator>(cur_expr)) {
                if (condop->getRHS())
                    isvalid = rhsExprCheck(condop->getRHS(), lvalelem);
                if (condop->getLHS())
                    isvalid = isvalid || rhsExprCheck(condop->getLHS(), lvalelem);
                return isvalid;
            } else if (auto uniop = dyn_cast<UnaryOperator>(cur_expr)) {
                cur_expr = uniop->getSubExpr()->IgnoreParenCasts();
            } else if (auto list = dyn_cast<InitListExpr>(cur_expr)) {
                for (unsigned i = 0; i < list->getNumInits(); i++)
                    isvalid = isvalid || rhsExprCheck(list->getInit(i), lvalelem);
                return isvalid;
            } else if (auto call = dyn_cast<CallExpr>(cur_expr)) {
                // TODO: Pointer? '&'?
                for (auto i = 0; i < call->getNumArgs(); i++)
                    isvalid = isvalid || rhsExprCheck(call->getArg(i), lvalelem);
                return isvalid;
            } else if (auto array = dyn_cast<ArraySubscriptExpr>(cur_expr)) {
                // TODO: Make it compatible with the lval->ast_name expr '&'
                cur_expr = array->getBase()->IgnoreParenCasts();
            } else if (auto intlit = dyn_cast<IntegerLiteral>(cur_expr)) {
                break;
            } else {
                std::cerr << "Warning Member Type Unknown\n";
                cur_expr->dump();
                break;
            }
        }

        if (cmpelem.size() == 0)    return false;
        // Fix for nginx partially initialized dua: strict node matching
        if (lvalelem.size() != cmpelem.size())  return false;

        for (size_t i = 0; i < std::min(lvalelem.size(), cmpelem.size()); i++)
        {
            if (lvalelem[i] != cmpelem[i])
            {
                return false;
            }
        }

        return true;
    }


    const Stmt *scopeCheck(const SourceManager &sm, const CompoundStmt *body, const SourceLval *sourcelval)
    {
        const Stmt *result = nullptr;

        // Check locInScope
        if (!locInScope(sm, body, sourcelval))  return nullptr;

        std::vector<std::string> lvalelem = xtractMembers(sourcelval);
        for (auto stmtit = body->body_begin(); stmtit != body->body_end(); stmtit++)
        {
            // Start Testing Code
            if (auto declstmt = dyn_cast<DeclStmt>(*stmtit))
            {
                for (auto sdeclit = declstmt->decl_begin();
                        sdeclit != declstmt->decl_end();
                        sdeclit++)
                {
                    const VarDecl *vardecl = dyn_cast<VarDecl>(*sdeclit);
                    if (auto initexpr = vardecl->getAnyInitializer())
                    {
                        if (rhsExprCheck(initexpr, lvalelem)
                           && std::next(stmtit) != body->body_end())
                            return *std::next(stmtit);
                    }
                }
            } else if (auto nestedcomp = dyn_cast<CompoundStmt>(*stmtit)) {
                // Check nested CompoundStmt in recursive
                // locInScope is checked in the recursive call,
                // so we dont have to do it here
                // In doing so, we are able to check the DUA Init in the outer
                // scope, and move the DUA siphon within the current scope
                result = scopeCheck(sm, nestedcomp, sourcelval);
                if (result) return result;
                // Dont RETURN since we need to continue our check afterward
            } else if (auto forexpr = dyn_cast<ForStmt>(*stmtit)) {
                //forexpr->getInit()->dump();
                //forexpr->getInc()->dump();
                if (forexpr->getCond()
                   && rhsExprCheck(forexpr->getCond(), lvalelem)
                   && std::next(stmtit) != body->body_end())
                    return *std::next(stmtit);
                if (forexpr->getBody())
                {
                    if (auto forbody = dyn_cast<CompoundStmt>(forexpr->getBody()))
                    {
                        result = scopeCheck(sm, forbody, sourcelval);
                        if (result) return result;
                    } else {
                        // Skip This
                        //if (rhsExprCheck(forexpr->getBody(), lvalelem)) return true;
                    }
                }
            } else if (auto whilestmt = dyn_cast<WhileStmt>(*stmtit)) {
                if (whilestmt->getCond()
                   && rhsExprCheck(whilestmt->getCond(), lvalelem)
                   && std::next(stmtit) != body->body_end())
                    return *std::next(stmtit);
                if (whilestmt->getBody())
                {
                    if (auto whilebody = dyn_cast<CompoundStmt>(whilestmt->getBody()))
                    {
                        result = scopeCheck(sm, whilebody, sourcelval);
                        if (result) return result;
                    }
                }
            } else if (auto ifexpr = dyn_cast<IfStmt>(*stmtit)) {
                if (rhsExprCheck(ifexpr->getCond(), lvalelem)
                   && std::next(stmtit) != body->body_end())
                    return *std::next(stmtit);
                if (ifexpr->getThen())
                {
                    if (auto ifthen = dyn_cast<CompoundStmt>(ifexpr->getThen()))
                    {
                        result = scopeCheck(sm, ifthen, sourcelval);
                        if (result) return result;
                    }
                }
                if (ifexpr->getElse())
                {
                    if (auto ifelse = dyn_cast<CompoundStmt>(ifexpr->getElse()))
                    {
                        result = scopeCheck(sm, ifelse, sourcelval);
                        if (result) return result;
                    }
                }
            } else if (auto swchstmt = dyn_cast<SwitchStmt>(*stmtit)) {
                if (rhsExprCheck(swchstmt->getCond(), lvalelem)
                   && std::next(stmtit) != body->body_end())
                    return *std::next(stmtit);
                // Skip Cases
            } else if (auto expr = dyn_cast<Expr>(*stmtit)) {
                // Other Expressions
                if (rhsExprCheck(expr, lvalelem)
                   && std::next(stmtit) != body->body_end())
                    return *std::next(stmtit);
            } else if (auto retstmt = dyn_cast<ReturnStmt>(*stmtit)) {
                // SKIP Return
            } else {
                std::cerr << "Warning Stmt Unknown\n";
                (*stmtit)->dump();
                //break;
            }
        }

        return nullptr;
    }

    bool paramCheck(const SourceManager &sm, const FunctionDecl *func, const SourceLval *sourcelval)
    {
        // Check locInScope
        if (!locInScope(sm, dyn_cast<CompoundStmt>(func->getBody()), sourcelval))
            return false;

        std::vector<std::string> lvalelem = xtractMembers(sourcelval);
        for (auto paramit = func->param_begin();
                paramit != func->param_end(); paramit++)
        {
            std::string paramname = (*paramit)->getNameAsString();
            // Avoid Pointer Type Params
            if (!(*paramit)->getType()->isPointerType()
                    && paramname == lvalelem[0])
                return true;
        }
        return false;
    }

    virtual void run(const MatchFinder::MatchResult &Result)
    {
        const FunctionDecl *FS = Result.Nodes.getNodeAs<clang::FunctionDecl>("func");
        sm = Result.SourceManager;

        if (sm->isInSystemHeader(FS->getLocStart()))    return;

        const CompoundStmt *body = dyn_cast<CompoundStmt>(FS->getBody());
        if(body == nullptr) return;
        FullSourceLoc fullloc(sm->getExpansionLoc(body->getLocStart()), *sm);
        if (getAbsolutePath(sm->getFilename(fullloc)).compare(0, 12, "/llvm-3.6.2/")
            == 0)
            return;

        for (auto lval : _lvals)
        {
            if (paramCheck(*sm, FS, lval.get()))
            {
                finallvals.insert(lval->id);
                continue;
            }

            auto movstmt = scopeCheck(*sm, body, lval.get());
            if (movstmt)
            {
                auto movloc = GetASTLoc(*sm, movstmt);
                if (lval->loc < movloc)
                {
                    // DUA Siphon Code has Moved Log SourceLval id <> new LavaASTLoc
                    movedlocs[lval->id] = movloc;
                }
                finallvals.insert(lval->id);
            }
        }
    }

private:
    const SourceManager *sm;
};

class TestCallMatcher : public MatchFinder::MatchCallback {
public:
    virtual void run(const MatchFinder::MatchResult &Result)
    {
        const CallExpr *call = Result.Nodes.getNodeAs<CallExpr>("call");
        sm = Result.SourceManager;
        langop = &Result.Context->getLangOpts();
        call->dump();
        call->getDirectCallee()->dump();
        FullSourceLoc fullloc(sm->getExpansionLoc(call->getLocStart()), *sm);
        fullloc.dump();
        call->getLocStart().dump(*sm);
        FullSourceLoc fullloc2(sm->getExpansionLoc(call->getLocEnd()), *sm);
        fullloc2.dump();
        call->getLocEnd().dump(*sm);

        std::cerr << call->getLocStart().isMacroID() << "\n";
        SourceLocation callloc = call->getLocStart();
        if (callloc.isMacroID())
            callloc = sm->getSpellingLoc(callloc);
            //callloc = SourceLocation::getFromRawEncoding(callloc.getRawEncoding());
        callloc.dump(*sm);
        clang::Lexer::findLocationAfterToken(callloc,tok::l_paren, *sm, *langop, true).dump(*sm);
    }

private:
    const SourceManager *sm;
    const LangOptions *langop;
};

}

// Set up the command line options
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::OptionCategory ToolTemplateCategory("tool-template options");

int main(int argc, const char **argv)
{
    CommonOptionsParser OptionsParser(argc, argv, ToolTemplateCategory);

    db.reset(new odb::pgsql::database("postgres", "postgrespostgres",
                BugDB));
    odb::transaction *t = new odb::transaction(db->begin());

    TestMatcher Matcher;
    TestCallMatcher CallMatcher;
    MatchFinder Finder;
    Finder.addMatcher(functionDecl(has(compoundStmt())).bind("func"),
                      &Matcher);
    //Finder.addMatcher(callExpr().bind("call"),
    //        &CallMatcher);

    //std::shared_ptr<SourceLval> _lval(db->load<SourceLval>(1));
    bool flag = true;
#define STRIDE 100000
    for (int rounds = 1; flag; rounds += STRIDE)
    {
        _lvals.clear();
        for (int i = rounds; i < rounds + STRIDE; i++)
        {
            std::shared_ptr<SourceLval> _lval;
            try {
                std::cerr << "SourceLval id " << i << "\n";
                //db->load(i, *_lval);
                _lval.reset(db->load<SourceLval>(i));
            } catch (const odb::object_not_persistent &e) {
                std::cerr << "RESET\n";
                t->reset(db->begin());
                flag = false;
                break;
            }

            _lvals.emplace_back(_lval);
        }
        std::cerr << _lvals.size() << "\n";
        if (!_lvals.size())  continue;

        std::vector<std::string> sourcefiles;
        std::error_code ErrorCode;
        for (recursive_directory_iterator I(SourceDir, ErrorCode), E;
             I != E && !ErrorCode; I.increment(ErrorCode))
        {
            if (filename(I->path())[0] == '.')
            {
              I.no_push();
              continue;
            }
            if (extension(I->path()) == ".c")
                sourcefiles.push_back(I->path());
        }
        for (auto sfile : sourcefiles)
        {
            std::cerr << sfile << "\n";
            ClangTool Tool(OptionsParser.getCompilations(), {sfile});
            Tool.run(newFrontendActionFactory(&Finder).get());
            std::cerr << "Intermediate Result : " << finallvals.size() << "\n";
        }
    }

    std::ofstream outlvals(BugDB+".tmp", std::fstream::out);
    outlvals << "Final Left : " << finallvals.size() << "\n";
    outlvals << "[";
    for (auto lid : finallvals)
        outlvals << lid << ",";
    outlvals << "]\n";
    outlvals.close();

    std::ofstream outmap(BugDB+".idmap", std::fstream::out);
    for (auto mit : movedlocs)
        outmap << mit.first << ":" << mit.second << "\n";
    outmap.close();

    t->commit();
    return 0;
}
