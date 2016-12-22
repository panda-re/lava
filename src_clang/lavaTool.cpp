extern "C" {
#include <unistd.h>
#include <libgen.h>
}

#include <json/json.h>
#include <odb/pgsql/database.hxx>

#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Driver/Options.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "llvm/Option/OptTable.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <set>
#include <memory>
#include <iterator>

#include "lavaDB.h"
#include "lava.hxx"
#include "lava-odb.hxx"
#include "lexpr.hxx"

#define RV_PFX "kbcieiubweuhc"
#define RV_PFX_LEN 13

#define DEBUG 0
#define MATCHER_DEBUG 0

using namespace odb::core;
std::unique_ptr<odb::pgsql::database> db;

char resolved_path[512];
std::string LavaPath;

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::driver;
using namespace clang::tooling;
using namespace llvm;

static cl::OptionCategory
    LavaCategory("LAVA Taint Query and Attack Point Tool Options");
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp(
    "\nTODO: Add descriptive help message.  "
    "Automatic clang stuff is ok for now.\n\n");
enum action { LavaQueries, LavaInjectBugs, LavaInstrumentMain };
static cl::opt<action> LavaAction("action", cl::desc("LAVA Action"),
    cl::values(
        clEnumValN(LavaQueries, "query", "Add taint queries"),
        clEnumValN(LavaInjectBugs, "inject", "Inject bugs"),
        clEnumValN(LavaInstrumentMain, "main", "Insert lava fns into file containing main"),
        clEnumValEnd),
    cl::cat(LavaCategory),
    cl::Required);
static cl::opt<std::string> LavaBugList("bug-list",
    cl::desc("Comma-separated list of bug ids (from the postgres db) to inject into this file"),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<std::string> LavaDB("lava-db",
    cl::desc("Path to LAVA database (custom binary file for source info).  "
        "Created in query mode."),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<std::string> ProjectFile("project-file",
    cl::desc("Path to project.json file."),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<std::string> SourceDir("src-prefix",
    cl::desc("Path to source directory to remove as prefix."),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<std::string> SMainInstrCorrection("main_instr_correction",
    cl::desc("Insertion line correction for post-main instr"),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<bool> KT("kt",
    cl::desc("Inject in Knob-Trigger style"),
    cl::cat(LavaCategory),
    cl::init(false));
static cl::opt<bool> FN_ARG_ATP("fn_arg",
    cl::desc("Inject in function arg style attack point"),
    cl::cat(LavaCategory),
    cl::init(false));
static cl::opt<bool> MEM_WRITE_ATP("mem_write",
    cl::desc("Inject a mem_write sytle attack point"),
    cl::cat(LavaCategory),
    cl::init(false));
static cl::opt<bool> MEM_READ_ATP("mem_read",
    cl::desc("Inject a mem_read style attack point"),
    cl::cat(LavaCategory),
    cl::init(false));


uint32_t MainInstrCorrection;

#define INSERTED_DUA_SIPHON 0x4
#define INSERTED_DUA_USE    0x8
#define INSERTED_MAIN_STUFF 0x16

uint32_t returnCode=0;

uint32_t num_taint_queries = 0;
uint32_t num_atp_queries = 0;

#if DEBUG
auto &debug = llvm::errs();
#else
llvm::raw_null_ostream null_ostream;
auto &debug = null_ostream;
#endif

/*
static cl::opt<std::string> LavaBugBuildDir("bug-build-dir",
    cl::desc("Path to build dir for bug-inj src"
        "Used only in inject mode."),
    cl::cat(LavaCategory),
    cl::init("XXX"));
*/

Loc::Loc(const FullSourceLoc &full_loc)
    : line(full_loc.getExpansionLineNumber()),
    column(full_loc.getExpansionColumnNumber()) {}

static std::vector<const Bug*> bugs;

std::stringstream new_start_of_file_src;

// Map of adjusted locations to siphon-able lvals there.
// Only filled in in LavaInjectBugs. Replaces old gatherDuas func.
std::map<LavaASTLoc, std::set<std::string>> lval_name_location_map;

#define MAX_STRNLEN 64
///////////////// HELPER FUNCTIONS BEGIN ////////////////////
template<typename K, typename V>
V get_or_construct(const std::map<K, V> &map, K key) {
    auto it = map.find(key);
    if (it != map.end()) {
        return it->second;
    } else {
        return V();
    }
}

std::set<uint32_t> parse_ints(std::string ints) {
    std::stringstream ss(ints);
    std::set<uint32_t> result;
    uint32_t i;
    while (ss >> i) {
        result.insert(i);
        assert(ss.peek() == ',');
        ss.ignore();
    }
    return result;
}

// struct fields known to cause trouble
bool InFieldBlackList(std::string field_name) {
    return ((field_name == "__st_ino" ) || (field_name.size() == 0));
}

// is this lvalname / line / filename, etc a bug inj point?
// if so, return the vector of bugs that are injectable at this point
std::vector<const Bug*> AtBug(std::string lvalname, LavaASTLoc loc, bool atAttackPoint,
                    SourceLval::Timing insertion_point) {
    // debug << "atbug : lvalname=" << lvalname << " filename=" << filename << " line=" << line << " atAttackPoint=" << atAttackPoint << " insertion_point=" << insertion_point<< " \n";
    std::vector<const Bug*> injectable_bugs;
    for ( const Bug *bug : bugs ) {
        //                        debug << bug->str() << "\n";
        bool atbug = false;
        if (atAttackPoint) {
            // this is where we'll use the dua.  only need to match the file and line
            assert (insertion_point == -1);
            atbug = (loc == bug->atp->loc.adjust_line(MainInstrCorrection));
        } else {
            // this is the dua siphon -- need to match most every part of dua
            // if dua is a retval, the one in the db wont match this one but verify prefix
            atbug = (loc == bug->dua->lval->loc.adjust_line(MainInstrCorrection)
                    && lvalname == bug->dua->lval->ast_name
                    && insertion_point == bug->dua->lval->timing);
        }
        if (atbug) {
            //                debug << "found injectable bug @ line " << line << "\n";
            injectable_bugs.push_back(bug);
        }
    }
    //                debug << "Not at bug\n";
    return injectable_bugs;
}

std::string StripPfx(std::string filename, std::string pfx) {
    size_t pos = filename.find(pfx, 0);
    if (pos == std::string::npos
        || pos != 0) {
        // its not a prefix
        return std::string("");
    }
    size_t filename_len = filename.length();
    size_t pfx_len = pfx.length();
    if (filename[pfx_len] == '/') {
        pfx_len++;
    }
    std::string suff = filename.substr(pfx_len, filename_len - pfx_len);
    return suff;
}

// returns true if this call expr has a retval we need to catch
bool CallExprHasRetVal(QualType &rqt) {
    if (rqt.getTypePtrOrNull() != NULL ) {
        if (! rqt.getTypePtr()->isVoidType()) {
            // this call has a return value (which may be being ignored
            return true;
        }
    }
    return false;
}

bool QueriableType(const Type *lval_type) {
    if ((lval_type->isIncompleteType())
        || (lval_type->isIncompleteArrayType())
        || (lval_type->isVoidType())
        || (lval_type->isNullPtrType())
        ) {
        return false;
    }
    if (lval_type->isPointerType()) {
        const Type *pt = lval_type->getPointeeType().getTypePtr();
        return QueriableType(pt);
    }
    return true;
}

bool IsArgAttackable(const Expr *arg) {
    //        debug << "IsArgAttackable \n";
    //        arg->dump();
    const Type *t = arg->IgnoreParenImpCasts()->getType().getTypePtr();
    if (dyn_cast<OpaqueValueExpr>(arg) || t->isStructureType() || t->isEnumeralType() || t->isIncompleteType()) {
        return false;
    }
    if (QueriableType(t)) {
        //            debug << "is of queriable type\n";
        if (t->isPointerType()) {
            //                debug << "is a pointer type\n";
            const Type *pt = t->getPointeeType().getTypePtr();
            // its a pointer to a non-void
            if ( ! (pt->isVoidType() ) ) {
                //                    debug << "is not a void type -- ATTACKABLE\n";
                return true;
            }
        }
        if ((t->isIntegerType() || t->isCharType()) && (!t->isEnumeralType())) {
            //                debug << "is integer or char and not enum -- ATTACKABLE\n";
            return true;
        }
    }
    //        debug << "not ATTACKABLE\n";
    return false;
}

bool IsAttackPoint(const CallExpr *e) {
    for ( auto it = e->arg_begin(); it != e->arg_end(); ++it) {
        const Stmt *stmt = dyn_cast<Stmt>(*it);
        if (stmt) {
            const Expr *arg = dyn_cast<Expr>(*it);
            // can't fail, right?
            assert (arg);
            if (IsArgAttackable(arg)) return true;
        }
    }
    return false;
}

///////////////// HELPER FUNCTIONS END ////////////////////

/* create code that siphons dua bytes into a global
   this is how, given a byte in a dua we'll grab it and insert into a global
   o = 3; // byte # in dua (0 is lsb)
   i = 0; // byte # in global
   lava_set(BUG_ID, ((unsigned char *)&dua))[o] << (i*8) | ...);
*/
LExpr ComposeDuaSiphoning(const std::string &lval_name,
        std::vector<const Bug*> &injectable_bugs, std::string filename) {
    // only insert one dua siphon if single bug
    // if > 1 bug we are living dangerously.
    // FIXME: understand this. is it just garbage?
    if (bugs.size() == 1 && (returnCode & INSERTED_DUA_SIPHON))
        return LStr("");

    returnCode |= INSERTED_DUA_SIPHON;

    std::vector<LExpr> siphons;
    for (const Bug *bug : injectable_bugs) {
        const std::vector<uint32_t> &offsets = bug->selected_bytes;

        std::vector<LExpr> or_args;
        for (auto it = offsets.cbegin(); it != offsets.cend(); it++) {
            LExpr shift = LDecimal((it - offsets.cbegin()) * 8);
            or_args.push_back(
                    LIndex(LCast("unsigned char *", LStr(lval_name)), *it) << shift);
        }
        siphons.push_back(LavaSet(bug, LBinop("|", or_args)));
    }

    return LIf(lval_name, siphons);
}

/*******************************
 * Matcher Handlers
 *******************************/
class LavaMatchHandler : public MatchFinder::MatchCallback {
public:
    LavaMatchHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
        rewriter(rewriter), StringIDs(StringIDs) {}

    std::string FullPath(FullSourceLoc &loc) {
        SourceManager &sm = rewriter.getSourceMgr();
        char curdir[260] = {};
        char *ret = getcwd(curdir, 260);
        std::string name = sm.getFilename(loc).str();
        if (name != "") {
            std::stringstream s;
            s << curdir << "/" << name;
            return s.str();
        }
        else {
            return "";
        }
    }

    std::string ExprStr(const Stmt *e) {
        const clang::LangOptions &LangOpts = rewriter.getLangOpts();
        clang::PrintingPolicy Policy(LangOpts);
        std::string TypeS;
        llvm::raw_string_ostream s(TypeS);
        e->printPretty(s, 0, Policy);
        return s.str();
    }
    uint32_t GetStringID(std::string s) {
        if (StringIDs.find(s) == StringIDs.end()) {
            StringIDs[s] = StringIDs.size();
        }
        return StringIDs[s];
    }

    bool InMainFile(const Stmt *s){
        SourceManager &sm = rewriter.getSourceMgr();
        FullSourceLoc fullLoc(s->getLocStart(), sm);
        std::string src_filename = FullPath(fullLoc);
        return src_filename != "" && sm.isInMainFile(s->getLocStart());
    }

    LavaASTLoc GetASTLoc(const Stmt *s){
        SourceManager &sm = rewriter.getSourceMgr();
        FullSourceLoc fullLocStart(s->getLocStart(), sm);
        FullSourceLoc fullLocEnd(s->getLocEnd(), sm);
        std::string src_filename;
        if (LavaAction == LavaInjectBugs) {
            // we want to strip the build path so that
            // we can actually compare bug in and query files for
            // same source which will be in different directories
            src_filename = StripPfx(FullPath(fullLocStart), SourceDir);
        }
        else {
            src_filename = FullPath(fullLocStart);
        }
        return LavaASTLoc(src_filename, fullLocStart, fullLocEnd);
    }

    LExpr LavaAtpQuery(LavaASTLoc ast_loc, AttackPoint::Type atpType) {
        return LBlock({
                LFunc("vm_lava_attack_point2",
                    { LDecimal(GetStringID(ast_loc)), LDecimal(0), LDecimal(atpType) }),
                LDecimal(0) });
    }

    void AttackExpression(const Expr *toAttack, const Expr *parent,
            LavaASTLoc ast_loc, AttackPoint::Type atpType) {
        //        debug << "in AttackExpressionDuaUse\n";
        std::string after;
        debug << "AttackExpression\n";
        if (LavaAction == LavaInjectBugs) {
            std::vector<const Bug*> injectable_bugs =
                AtBug("", ast_loc, true, SourceLval::NULL_TIMING);

            // Nothing to do if we're not at an attack point
            if (injectable_bugs.empty()) {
                return;
            } else {
                debug << "AtBug returned nonempty!";
            }

            // if > 1 bug we live dangerously and may have multiple attack points
            // TODO: is this still necessary?
            if (bugs.size() == 1 && (returnCode & INSERTED_DUA_USE)) return;
            returnCode |= INSERTED_DUA_USE;

            std::vector<LExpr> addends;
            std::transform(injectable_bugs.cbegin(), injectable_bugs.cend(),
                    std::back_inserter(addends), KT ? knobTriggerAttack : traditionalAttack);
            after = " + " + LBinop("+", std::move(addends)).render();
        } else if (LavaAction == LavaQueries) {
            // call attack point hypercall and return 0
            after = " + " + LavaAtpQuery(ast_loc, atpType).render();
            num_atp_queries++;
        }

        // we will get here if not attack was inject in knobTriggerAttack
        // or traditionalAttack
        if (!after.empty()) {
            if (parent) {
                debug << " Injected MemoryReadWriteBug into " << ExprStr(parent) << "\n";
            } else {
                debug << " Injected expression attack for " << ExprStr(toAttack) << "\n";
            }
            debug << "    " << after << "\n";
        }
        // Insert the new addition expression, and if parent expression is
        // already paren expression, do not add parens
        rewriter.InsertTextAfterToken(toAttack->getLocEnd(), after);
        if (parent && !isa<ParenExpr>(parent) && !isa<ArraySubscriptExpr>(parent)){
            rewriter.InsertTextBefore(toAttack->getLocStart(), "(");
            rewriter.InsertTextAfterToken(parent->getLocEnd(), ")");
        }
    }

protected:
    std::map<std::string,uint32_t> &StringIDs;
    Rewriter &rewriter;
};

class MatcherDebugHandler : public LavaMatchHandler {
public:
    MatcherDebugHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
        LavaMatchHandler(rewriter, StringIDs) {}

    virtual void run(const MatchFinder::MatchResult &Result) {
        debug << "====== Found Match =====\n";
        //for (auto n : Result.Nodes.IDToNodeMap){
        //toSiphon = Result.Nodes.getNodeAs<Stmt>("stmt");
        const Stmt *stmt;
        for (BoundNodes::IDToNodeMap::const_iterator n = Result.Nodes.getMap().begin();
                                                     n != Result.Nodes.getMap().end(); ++n){
            if ((stmt = n->second.get<Stmt>())){
                debug << n->first << ": " << ExprStr(stmt) << "\n";
            }
        }
        return;
    }
};

class PriQueryPointSimpleHandler : public LavaMatchHandler {
public:
    PriQueryPointSimpleHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
        LavaMatchHandler(rewriter, StringIDs)  {}

    virtual void run(const MatchFinder::MatchResult &Result) {
        const Stmt *toSiphon;
        toSiphon = Result.Nodes.getNodeAs<Stmt>("stmt");
        LavaASTLoc p = GetASTLoc(toSiphon);
        if (!InMainFile(toSiphon)) return;
        debug << "Have a pri SIMPLE query point!\n";

        std::string before;
        if (LavaAction == LavaQueries) {
            before = "; " + LFunc("vm_lava_pri_query_point", {
                LDecimal(GetStringID(p)),
                LDecimal(p.begin.line),
                LDecimal(SourceLval::BEFORE_OCCURRENCE)}).render() + ";";

            num_taint_queries += 1;
        } else if (LavaAction == LavaInjectBugs) {
            std::set<std::string> lval_names =
                get_or_construct(lval_name_location_map, p);
            std::stringstream before_ss;
            for (auto lval_name : lval_names) {
                //an llval is { lvalname, pointer_tst, lvallen, lval_type, is_ptr };
                assert(lval_name.length() > 0);
                std::vector<const Bug*> injectable_bugs =
                    AtBug(lval_name, p, /*atAttackPoint=*/false,
                          SourceLval::BEFORE_OCCURRENCE);
                // NOTE: if injecting multiple bugs the same dua will need to
                // be instrumented more than once
                if (!injectable_bugs.empty()) {
                    debug << "PriQueryHandler: injecting a dua siphon for "
                        << injectable_bugs.size() << " bugs " << p << " : "
                        << lval_name << "\n";
                } else {
                    debug << "PriQueryHandlerSimple: No bugs for this dua. Something went wrong . . .\n";
                }
                before_ss << ComposeDuaSiphoning(lval_name, injectable_bugs, p);
            }
            before = before_ss.str();
        }
        debug << " Injecting dua siphon at " << ExprStr(toSiphon) << "\n";
        debug << "    Text: " << before << "\n";
        rewriter.InsertTextBefore(toSiphon->getLocStart(), before);
    }
};

class ArgAtpPointHandler : public LavaMatchHandler {
public:
    ArgAtpPointHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
        LavaMatchHandler(rewriter, StringIDs) {}

    virtual void run(const MatchFinder::MatchResult &Result) {
        const CallExpr *ce = Result.Nodes.getNodeAs<CallExpr>("ce");
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("arg");
#if DEBUG
        debug << "Have a vulnerable arg: " << ExprStr(ce) << " -> " << ExprStr(toAttack) << "\n";
        toAttack->dump();
        debug << "Arg has type ";
        toAttack->getType().dump();
#endif
        debug << "\n";
        if (!InMainFile(ce)) return;
        LavaASTLoc p = GetASTLoc(toAttack);

        if (FN_ARG_ATP)
            AttackExpression(toAttack, NULL, p, AttackPoint::ATP_FUNCTION_CALL);
    }
};

class AtpPointerQueryPointHandler : public LavaMatchHandler {
public:
    AtpPointerQueryPointHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
        LavaMatchHandler(rewriter, StringIDs) {}

    /* TODO: add description of what type of attacks we are doing here */

    virtual void run(const MatchFinder::MatchResult &Result) {
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("innerExpr");
        const Expr *parent = Result.Nodes.getNodeAs<Expr>("innerExprParent");
        bool memWrite = false;
        // memwrite style attack points will have assign_expr bound to a node
        if (Result.Nodes.getMap().find("assign_expr") != Result.Nodes.getMap().end()){
             memWrite = true;
        }
        if (!InMainFile(toAttack)) return;
        LavaASTLoc p = GetASTLoc(toAttack);
        //debug << "Have a atp pointer query point" << " at " << p.first << " " << p.second <<  "\n";
        bool memRead = !memWrite;
        if ((memWrite && MEM_WRITE_ATP) || (memRead && MEM_READ_ATP)) {
            AttackExpression(toAttack, parent, p, AttackPoint::ATP_POINTER_RW);
        }
    }
};

namespace clang {
    namespace ast_matchers {
        AST_MATCHER(CallExpr, isAttackPointMatcher){
            const CallExpr *ce = &Node;
            return IsAttackPoint(ce);
        }
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

/*******************************************************************************
 * LavaTaintQueryASTConsumer
 ******************************************************************************/

class LavaTaintQueryASTConsumer : public ASTConsumer {
public:
    LavaTaintQueryASTConsumer(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
        HandlerMatcherDebug(rewriter, StringIDs),
        //HandlerForAtpQueryPoint(rewriter, StringIDs),
        //HandlerForPriQueryPoint(rewriter, StringIDs),
        HandlerForArgAtpPoint(rewriter, StringIDs),
        HandlerForAtpPointerQueryPoint(rewriter, StringIDs),
        HandlerForPriQueryPointSimple(rewriter, StringIDs)
    {
        StatementMatcher memoryAccessMatcher =
            allOf(
                anyOf(
                    arraySubscriptExpr(
                        hasIndex(ignoringParenImpCasts(
                            expr(hasParent(expr().bind("innerExprParent"))).bind("innerExpr")))).bind("lhs"),
                    unaryOperator(hasOperatorName("*"),
                        hasUnaryOperand(ignoringParenImpCasts(
                            expr(hasParent(expr().bind("innerExprParent"))).bind("innerExpr")))).bind("lhs")),
                hasAncestor(functionDecl()), // makes sure that we are't in a global variable declaration
                unless(hasAncestor(varDecl(isStaticLocalDeclMatcher())))); //makes sure that we aren't in an initializer of a static local variable which must be constant

        StatementMatcher memWriteMatcher =
            expr(allOf(
                    memoryAccessMatcher,
                    expr(hasParent(binaryOperator(hasOperatorName("=")).bind("assign_expr"))).bind("lhs")));

        StatementMatcher memReadMatcher =
            allOf(
                unless(memWriteMatcher),
                memoryAccessMatcher);

#if MATCHER_DEBUG == 1
#define IFNOTDEBUG(matcher) HandlerMatcherDebug
#else
#define IFNOTDEBUG(matcher) (matcher)
#endif

        Matcher.addMatcher(
                stmt(hasParent(compoundStmt())).bind("stmt"),
                &IFNOTDEBUG(HandlerForPriQueryPointSimple)
                );

        Matcher.addMatcher(
                callExpr(
                    forEachArgMatcher(expr(isAttackableMatcher()).bind("arg"))).bind("ce"),
                &IFNOTDEBUG(HandlerForArgAtpPoint)
);

        // an array subscript expression is composed of base[index]
        // matches all nodes of: *innerExprParent(innerExpr) = ...
        // and matches all nodes of: base[innerExprParent(innerExpr)] = ...
        Matcher.addMatcher(
                memWriteMatcher,
                &IFNOTDEBUG(HandlerForAtpPointerQueryPoint)
                );

        //// matches all nodes of: ... *innerExprParent(innerExpr) ...
        //// and matches all nodes of: ... base[innerExprParent(innerExpr)] ...
        Matcher.addMatcher(
                memReadMatcher,
                &IFNOTDEBUG(HandlerForAtpPointerQueryPoint)
                );

        }
#undef IFNOTDEBUG

    void HandleTranslationUnit(ASTContext &Context) override {
        // Run the matchers when we have the whole TU parsed.
        Matcher.matchAST(Context);
    }

private:
    std::vector< VarDecl* > globalVars;
    //AtpQueryPointHandler HandlerForAtpQueryPoint;
    //PriQueryPointHandler HandlerForPriQueryPoint;
    ArgAtpPointHandler HandlerForArgAtpPoint;
    AtpPointerQueryPointHandler HandlerForAtpPointerQueryPoint;
    PriQueryPointSimpleHandler HandlerForPriQueryPointSimple;
    MatcherDebugHandler HandlerMatcherDebug;
    MatchFinder Matcher;
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
class LavaTaintQueryFrontendAction : public ASTFrontendAction {
public:
    std::string startoffile_ins;

    LavaTaintQueryFrontendAction() {}

    void EndSourceFileAction() override {
        SourceManager &sm = rewriter.getSourceMgr();
        debug << "*** EndSourceFileAction for: "
                     << sm.getFileEntryForID(sm.getMainFileID())->getName()
                     << "\n";
        // Last thing: include the right file
        // Now using our separate LAVA version
        if (LavaAction == LavaQueries) {
            new_start_of_file_src << "#include \"pirate_mark_lava.h\"\n";
        }

        // add lava_get lava_set defs if this is a file with main () in it
        if (LavaAction == LavaInstrumentMain) {
            // This is the file with main! insert lava_[gs]et and whatever.
            std::string lava_funcs_path(LavaPath + "/src_clang/lava_set.c");
            std::ifstream lava_funcs_file(lava_funcs_path);
            std::stringbuf temp;
            lava_funcs_file.get(temp, '\0');
            debug << "Inserting stuff from" << lava_funcs_path << ":\n";
            debug << temp.str();
            new_start_of_file_src << temp.str();
            returnCode |= INSERTED_MAIN_STUFF;
        }

        if (LavaAction == LavaInjectBugs && MainInstrCorrection == 0) {
            new_start_of_file_src
                << "void lava_set(unsigned int bn, unsigned int val);\n"
                << "extern unsigned int lava_get(unsigned int);\n";
        }

        auto startLoc = sm.getLocForStartOfFile(sm.getMainFileID());
        startLoc.dump(sm);

        rewriter.InsertText(startLoc, new_start_of_file_src.str(), true, true);
#if !MATCHER_DEBUG
        bool ret = rewriter.overwriteChangedFiles();
#endif
        // save the strings db
        if (LavaAction == LavaQueries){
            if (LavaDB != "XXX")
                SaveDB(StringIDs, LavaDB);
        }
    }

    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                     StringRef file) override {
        rewriter.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
        debug << "** Creating AST consumer for: " << file << "\n";
        if (LavaDB != "XXX")
            StringIDs = LoadDB(LavaDB);

        return make_unique<LavaTaintQueryASTConsumer>(rewriter,StringIDs);
    }

private:
    std::map<std::string,uint32_t> StringIDs;
    Rewriter rewriter;
};

std::vector<const Bug*> loadBugs(const std::set<uint32_t> &bug_ids) {
    std::vector<const Bug*> result;
    for (uint32_t bug_id : bug_ids) {
        result.push_back(db->load<Bug>(bug_id));
    }
    return result;
}

int main(int argc, const char **argv) {
    CommonOptionsParser op(argc, argv, LavaCategory);
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());
    if (!(FN_ARG_ATP || MEM_READ_ATP || MEM_WRITE_ATP)) {
        FN_ARG_ATP = true;
        MEM_WRITE_ATP = true;
        MEM_READ_ATP = true;
    }

    LavaPath = std::string(dirname(dirname(dirname(realpath(argv[0], NULL)))));

    debug << "main instr correction = " << SMainInstrCorrection.c_str() << "\n";
    MainInstrCorrection = atoi(SMainInstrCorrection.c_str());

    std::ifstream json_file(ProjectFile);
    Json::Value root;
    if (ProjectFile == "XXX") {
        if (LavaAction == LavaInjectBugs) {
            debug << "Error: Specify a json file with \"-project-file\".  Exiting . . .\n";
        }
    }
    else {
        json_file >> root;
    }

    odb::transaction *t = nullptr;
    if (LavaAction == LavaInjectBugs) {
        db.reset(new odb::pgsql::database("postgres", "postgrespostgres",
                    root["db"].asString()));
        t = new odb::transaction(db->begin());

        // get bug info for the injections we are supposed to be doing.
        debug << "LavaBugList: [" << LavaBugList << "]\n";

        std::set<uint32_t> bug_ids = parse_ints(LavaBugList);
        printf ("%d bug_ids\n", bug_ids.size());
        bugs = loadBugs(bug_ids);
        for (const Bug *bug : bugs) {
            LavaASTLoc dua_loc = bug->dua->lval->loc.adjust_line(MainInstrCorrection);
            lval_name_location_map[dua_loc].insert(bug->dua->lval->ast_name);
        }
    }
    debug << "about to call Tool.run \n";

    int r = Tool.run(newFrontendActionFactory<LavaTaintQueryFrontendAction>().get());
    debug << "back from calling Tool.run \n";
    debug << "num taint queries added " << num_taint_queries << "\n";
    debug << "num atp queries added " << num_atp_queries << "\n";

    if (t) {
        t->commit();
        delete t;
    }

    return (r | returnCode);
}
