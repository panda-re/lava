#include <cassert>
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
#include "clang/Lex/Lexer.h"
#include "lavaDB.h"
#include "lava.hxx"
#include "lava-odb.hxx"
#include "lexpr.hxx"
#include "vector_set.hxx"

// This makes sure assertions actually occur.
#ifdef NDEBUG
#undef NDEBUG
#endif

#define RV_PFX "kbcieiubweuhc"
#define RV_PFX_LEN 13

#define DEBUG 1
#define MATCHER_DEBUG 0
#define OVERWRITE 1

using namespace odb::core;
std::unique_ptr<odb::pgsql::database> db;

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
    cl::init(""));
static cl::opt<std::string> SMainInstrCorrection("main_instr_correction",
    cl::desc("Insertion line correction for post-main instr"),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<bool> KnobTrigger("kt",
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

Loc::Loc(const FullSourceLoc &full_loc)
    : line(full_loc.getExpansionLineNumber()),
    column(full_loc.getExpansionColumnNumber()) {}

static std::vector<const Bug*> bugs;

std::stringstream new_start_of_file_src;

// These two maps replace AtBug.
// Map of bugs with attack points at a given loc.
std::map<LavaASTLoc, std::vector<const Bug *>> bugs_with_atp_at;
// Map of bugs with siphon of a given  lval name at a given loc.
std::map<LavaASTLoc, vector_set<const DuaBytes *>> siphons_at;

#define MAX_STRNLEN 64
///////////////// HELPER FUNCTIONS BEGIN ////////////////////
template<typename K, typename V>
const V &map_get_default(const std::map<K, V> &map, K key) {
    static const V default_val;
    auto it = map.find(key);
    if (it != map.end()) {
        return it->second;
    } else {
        return default_val;
    }
}

std::set<uint32_t> parse_ints(std::string ints) {
    std::istringstream ss(ints);
    std::set<uint32_t> result;
    uint32_t i;
    while (ss.good()) {
        ss >> i;
        result.insert(i);
        assert(ss.eof() || ss.peek() == ',');
        ss.ignore();
    }
    return result;
}

std::string StripPrefix(std::string filename, std::string prefix) {
    size_t prefix_len = prefix.length();
    if (filename.compare(0, prefix_len, prefix) != 0) {
        printf("Not a prefix!\n");
        assert(false);
    }
    while (filename[prefix_len] == '/') prefix_len++;
    return filename.substr(prefix_len);
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
    debug << "IsArgAttackable \n";
#if MATCHER_DEBUG
    arg->dump();
#endif
    const Type *t = arg->IgnoreParenImpCasts()->getType().getTypePtr();
    if (dyn_cast<OpaqueValueExpr>(arg) || t->isStructureType() || t->isEnumeralType() || t->isIncompleteType()) {
        return false;
    }
    if (QueriableType(t)) {
        debug << "is of queriable type\n";
        if (t->isPointerType()) {
            debug << "is a pointer type\n";
            const Type *pt = t->getPointeeType().getTypePtr();
            // its a pointer to a non-void
            if ( ! (pt->isVoidType() ) ) {
                debug << "is not a void type -- ATTACKABLE\n";
                return true;
            }
        }
        if ((t->isIntegerType() || t->isCharType()) && (!t->isEnumeralType())) {
            debug << "is integer or char and not enum -- ATTACKABLE\n";
            return true;
        }
    }
    debug << "not ATTACKABLE\n";
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

LExpr traditionalAttack(const Bug *bug) {
    return LavaGet(bug) * MagicTest(bug->magic(), LavaGet(bug));
}

LExpr knobTriggerAttack(const Bug *bug) {
    LExpr lava_get_lower = LavaGet(bug) & LHex(0x0000ffff);
    //LExpr lava_get_upper = (LavaGet(bug) >> LDecimal(16)) & LHex(0xffff);
    LExpr lava_get_upper = (LavaGet(bug) & LHex(0xffff0000)) >> LDecimal(16);
    // this is the magic value that will trigger the bug
    // we already know that magic_kt returns uint16_t so we don't have
    // to mask it
    uint16_t magic_value = bug->magic_kt();

    return (lava_get_lower * MagicTest(magic_value, lava_get_upper))
        + (lava_get_upper * MagicTest(magic_value, lava_get_lower));
}

/*******************************
 * Matcher Handlers
 *******************************/
struct LavaMatchHandler : public MatchFinder::MatchCallback {
    LavaMatchHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
        rewriter(rewriter), StringIDs(StringIDs) {}

    std::string FullPath(FullSourceLoc &loc) {
        SourceManager &sm = rewriter.getSourceMgr();
        char curdir[PATH_MAX] = {};
        char *ret = getcwd(curdir, PATH_MAX);
        std::string name = sm.getFilename(loc).str();
        assert(!name.empty());
        return std::string(curdir) + "/" + name;
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
        std::map<std::string, uint32_t>::iterator it;
        // This does nothing if s is already in StringIDs.
        std::tie(it, std::ignore) =
            StringIDs.insert(std::make_pair(s, StringIDs.size()));
        return it->second;
    }

    bool InMainFile(const Stmt *s) {
        SourceManager &sm = rewriter.getSourceMgr();
        SourceLocation loc = s->getLocStart();
        return !sm.getFilename(loc).empty() && sm.isInMainFile(loc);
    }

    LavaASTLoc GetASTLoc(const Stmt *s) {
        assert(!SourceDir.empty());
        SourceManager &sm = rewriter.getSourceMgr();
        FullSourceLoc fullLocStart(s->getLocStart(), sm);
        FullSourceLoc fullLocEnd(s->getLocEnd(), sm);
        std::string src_filename = StripPrefix(FullPath(fullLocStart), SourceDir);
        return LavaASTLoc(src_filename, fullLocStart, fullLocEnd);
    }

    LExpr LavaAtpQuery(LavaASTLoc ast_loc, AttackPoint::Type atpType) {
        return LBlock({
                LFunc("vm_lava_attack_point2",
                    { LDecimal(GetStringID(ast_loc)), LDecimal(0), LDecimal(atpType) }),
                LDecimal(0) });
    }

    void AttackExpression(const Expr *toAttack, const Expr *parent,
            const Expr *writeValue, AttackPoint::Type atpType) {
        LavaASTLoc ast_loc = GetASTLoc(toAttack);
        std::vector<LExpr> pointerAddends;
        std::vector<LExpr> valueAddends;

        debug << "Inserting expression attack (AttackExpression).\n";
        if (LavaAction == LavaInjectBugs) {
            const std::vector<const Bug*> &injectable_bugs =
                map_get_default(bugs_with_atp_at, ast_loc);

            // Nothing to do if we're not at an attack point
            if (injectable_bugs.empty()) return;

            returnCode |= INSERTED_DUA_USE;

            // this should be a function bug -> LExpr to add.
            auto pointerAttack = KnobTrigger ? knobTriggerAttack : traditionalAttack;
            for (const Bug *bug : injectable_bugs) {
                assert(bug->atp->type == atpType);
                if (bug->type == Bug::PTR_ADD) {
                    pointerAddends.push_back(pointerAttack(bug));
                } else if (bug->type == Bug::REL_WRITE) {
                    pointerAddends.push_back(
                            MagicTest(bug) * LavaGet(bug->extra_duas[0]));
                    valueAddends.push_back(
                            MagicTest(bug) * LavaGet(bug->extra_duas[1]));
                }
            }
        } else if (LavaAction == LavaQueries) {
            // call attack point hypercall and return 0
            pointerAddends.push_back(LavaAtpQuery(ast_loc, atpType));
            num_atp_queries++;
        }

        // Insert the new addition expression, and if parent expression is
        // already paren expression, do not add parens
        // NB: InsertText... returns false on success.
        if (!pointerAddends.empty()) {
            LExpr addToPointer = LBinop("+", std::move(pointerAddends));
            bool ret = rewriter.InsertTextAfterToken(toAttack->getLocEnd(),
                    " + " + addToPointer.render());
            assert(!ret);
            if (parent &&
                    !isa<ParenExpr>(parent) && !isa<ArraySubscriptExpr>(parent)) {
                rewriter.InsertTextBefore(toAttack->getLocStart(), "(");
                rewriter.InsertTextAfterToken(parent->getLocEnd(), ")");
            }
        }

        if (!valueAddends.empty()) {
            assert(writeValue);
            LExpr addToValue = LBinop("+", std::move(valueAddends));
            bool ret = rewriter.InsertTextBefore(writeValue->getLocStart(), "(");
            assert(!ret);
            ret = rewriter.InsertTextAfterToken(writeValue->getLocEnd(),
                    " + " + addToValue.render() + ")");
            assert(!ret);
        }
    }

protected:
    std::map<std::string,uint32_t> &StringIDs;
    Rewriter &rewriter;
};

struct MatcherDebugHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void run(const MatchFinder::MatchResult &Result) {
        debug << "====== Found Match =====\n";
        //for (auto n : Result.Nodes.IDToNodeMap){
        //toSiphon = Result.Nodes.getNodeAs<Stmt>("stmt");
        const Stmt *stmt;
        for (BoundNodes::IDToNodeMap::const_iterator n = Result.Nodes.getMap().begin();
                                                     n != Result.Nodes.getMap().end(); ++n){
            if ((stmt = n->second.get<Stmt>())){
                debug << n->first << ": " << ExprStr(stmt) << " ";
                stmt->getLocStart().dump(rewriter.getSourceMgr());
                debug << "\n";
            }
        }
        return;
    }
};

struct PriQueryPointSimpleHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    /* create code that siphons dua bytes into a global
    this is how, given a byte in a dua we'll grab it and insert into a global
    o = 3; // byte # in dua (0 is lsb)
    i = 0; // byte # in global
    lava_set(BUG_ID, ((unsigned char *)&dua))[o] << (i*8) | ...);
    */
    // Each lval gets an if clause containing one siphon
    std::string SiphonsForLocation(LavaASTLoc ast_loc) {
        std::stringstream result_ss;
        for (const DuaBytes *dua_bytes : map_get_default(siphons_at, ast_loc)) {
            returnCode |= INSERTED_DUA_SIPHON;
            result_ss << LIf(dua_bytes->dua->lval->ast_name, LavaSet(dua_bytes));
        }

        std::string result = result_ss.str();
        if (!result.empty()) {
            debug << " Injecting dua siphon at " << ast_loc << "\n";
            debug << "    Text: " << result << "\n";
        }
        siphons_at.erase(ast_loc); // Only inject once.
        return result;
    }

    std::string AttackRetBuffer(LavaASTLoc ast_loc) {
        std::stringstream result_ss;
        for (const Bug *bug : map_get_default(bugs_with_atp_at, ast_loc)) {
            if (bug->type == Bug::RET_BUFFER) {
                const DuaBytes *buffer = db->load<DuaBytes>(bug->extra_duas[0]);
                result_ss << LIf(MagicTest(bug).render(), {
                        LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) +
                                LDecimal(buffer->selected.low), },
                                { "movl %0, %%esp", "ret" })});
            }
        }
        bugs_with_atp_at.erase(ast_loc); // Only inject once.
        return result_ss.str();
    }

    virtual void run(const MatchFinder::MatchResult &Result) {
        const Stmt *toSiphon = Result.Nodes.getNodeAs<Stmt>("stmt");
        if (!InMainFile(toSiphon)) return;

        LavaASTLoc ast_loc = GetASTLoc(toSiphon);
        debug << "Have a query point @ " << ast_loc << "!\n";

        std::string before;
        if (LavaAction == LavaQueries) {
            before = "; " + LFunc("vm_lava_pri_query_point", {
                LDecimal(GetStringID(ast_loc)),
                LDecimal(ast_loc.begin.line),
                LDecimal(SourceLval::BEFORE_OCCURRENCE)}).render() + "; ";

            num_taint_queries += 1;
        } else if (LavaAction == LavaInjectBugs) {
            before = SiphonsForLocation(ast_loc) + AttackRetBuffer(ast_loc);
        }
        rewriter.InsertText(toSiphon->getLocStart(), before,
                /* InsertAfter = */ false, /* indentNewLine = */ true);
    }
};

struct FunctionArgAtpHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void run(const MatchFinder::MatchResult &Result) {
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("arg");
        if (!InMainFile(toAttack)) return;

        debug << "FunctionArgAtpHandler @ " << GetASTLoc(toAttack) << "\n";

        if (FN_ARG_ATP) {
            AttackExpression(toAttack, nullptr, nullptr, AttackPoint::FUNCTION_ARG);
        }
    }
};

struct ReadDisclosureHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.
    virtual void run(const MatchFinder::MatchResult &Result) {
        const CallExpr *callExpr = Result.Nodes.getNodeAs<CallExpr>("call_expression");
        if (!InMainFile(callExpr)) return;

        LExpr addend = LDecimal(0);
        // iterate through all the arguments in the call expression
        for ( auto it = callExpr->arg_begin(); it != callExpr->arg_end(); ++it) {
            const Expr *arg = dyn_cast<Expr>(*it);
            if (arg) {
                if (arg->getType()->isIntegerType()) {
                    if (LavaAction == LavaQueries)  {
                        addend = LavaAtpQuery(GetASTLoc(arg), AttackPoint::PRINTF_LEAK);
                        rewriter.InsertTextAfterToken(arg->getLocEnd(), " + " + addend.render());
                    } else if (LavaAction == LavaInjectBugs) {
                        const std::vector<const Bug*> &injectable_bugs =
                            map_get_default(bugs_with_atp_at, GetASTLoc(arg));
                        for (const Bug* bug : injectable_bugs) {
                            if (bug->type != Bug::PRINTF_LEAK) {
                                continue;
                            }
                            SourceManager &SM = rewriter.getSourceMgr();
                            SourceRange range = arg->getSourceRange();
			    Rewriter::RewriteOptions rangeOpts;
			    rangeOpts.IncludeInsertsAtBeginOfRange = false;
			    unsigned int offset = rewriter.getRangeSize(range, rangeOpts);
			    
			    range.setEnd(range.getEnd().getLocWithOffset(offset));
                    
                            llvm::StringRef ref = Lexer::getSourceText(CharSourceRange::getCharRange(range), SM, LangOptions());

                            rewriter.InsertTextBefore(arg->getLocStart(), MagicTest(bug).render() + "? &(" + ref.str() + ") : ");
                        }
                    }

                }
	    }
        }
    }
};

struct PointerAtpHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    /* TODO: add description of what type of attacks we are doing here */

    virtual void run(const MatchFinder::MatchResult &Result) {
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("innerExpr");
        const Expr *parent = Result.Nodes.getNodeAs<Expr>("innerExprParent");
        LavaASTLoc ast_loc = GetASTLoc(toAttack);
        debug << "PointerAtpHandler @ " << ast_loc << "\n";

        const Expr *writeValue = nullptr;
        AttackPoint::Type atpType = AttackPoint::POINTER_READ;

        // memwrite style attack points will have rhs bound to a node
        auto it = Result.Nodes.getMap().find("rhs");
        if (it != Result.Nodes.getMap().end()){
            atpType = AttackPoint::POINTER_WRITE;
            writeValue = it->second.get<Expr>();
            assert(writeValue);
        }
        if (!InMainFile(toAttack)) return;

        if ((MEM_WRITE_ATP && atpType == AttackPoint::POINTER_WRITE)
                || (MEM_READ_ATP && atpType == AttackPoint::POINTER_READ)) {
            AttackExpression(toAttack, parent, writeValue, atpType);
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
        HandlerForFunctionArgAtp(rewriter, StringIDs),
        HandlerForPointerAtp(rewriter, StringIDs),
        HandlerForReadDisclosure(rewriter, StringIDs),
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
                    expr(hasAncestor(binaryOperator(allOf(
                                    hasOperatorName("="),
                                    hasRHS(expr().bind("rhs")))))).bind("lhs")));

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
                &IFNOTDEBUG(HandlerForFunctionArgAtp)
                );

        // an array subscript expression is composed of base[index]
        // matches all nodes of: *innerExprParent(innerExpr) = ...
        // and matches all nodes of: base[innerExprParent(innerExpr)] = ...
        Matcher.addMatcher(
                memWriteMatcher,
                &IFNOTDEBUG(HandlerForPointerAtp)
                );

        //// matches all nodes of: ... *innerExprParent(innerExpr) ...
        //// and matches all nodes of: ... base[innerExprParent(innerExpr)] ...
        Matcher.addMatcher(
                memReadMatcher,
                &IFNOTDEBUG(HandlerForPointerAtp)
                );

	///////////////////////////////////////////////////////
	// andy's matcher
        Matcher.addMatcher(
			   callExpr(callee(functionDecl(hasName("::printf"))), unless(argumentCountIs(1))).bind("call_expression"),
                &HandlerForReadDisclosure
                );
        }
#undef IFNOTDEBUG

    void HandleTranslationUnit(ASTContext &Context) override {
        if (LavaAction != LavaInstrumentMain) {
            // Run the matchers when we have the whole TU parsed.
            Matcher.matchAST(Context);
        }
    }

private:
    std::vector< VarDecl* > globalVars;
    FunctionArgAtpHandler HandlerForFunctionArgAtp;
    PointerAtpHandler HandlerForPointerAtp;
    PriQueryPointSimpleHandler HandlerForPriQueryPointSimple;
    MatcherDebugHandler HandlerMatcherDebug;
    ReadDisclosureHandler HandlerForReadDisclosure;
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
        startLoc.print(debug, sm);

        rewriter.InsertText(startLoc, new_start_of_file_src.str(), true, true);
#if OVERWRITE
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
        // for each bug_id, load that bug from DB and insert into bugs vector.
        std::transform(bug_ids.begin(), bug_ids.end(), std::back_inserter(bugs),
                [&](uint32_t bug_id) { return db->load<Bug>(bug_id); });

        for (const Bug *bug : bugs) {
            LavaASTLoc atp_loc = bug->atp->loc.adjust_line(MainInstrCorrection);
            bugs_with_atp_at[atp_loc].push_back(bug);

            LavaASTLoc dua_loc = bug->trigger_lval->loc.adjust_line(MainInstrCorrection);
            siphons_at[dua_loc].insert(bug->trigger);

            for (uint64_t dua_id : bug->extra_duas) {
                const DuaBytes *dua_bytes = db->load<DuaBytes>(dua_id);
                LavaASTLoc extra_loc = dua_bytes->dua->lval->loc.adjust_line(MainInstrCorrection);
                siphons_at[extra_loc].insert(dua_bytes);
            }
        }
    }
    debug << "about to call Tool.run \n";

    int r = Tool.run(newFrontendActionFactory<LavaTaintQueryFrontendAction>().get());
    debug << "back from calling Tool.run \n";
    if (LavaAction == LavaQueries) {
        debug << "num taint queries added " << num_taint_queries << "\n";
        debug << "num atp queries added " << num_atp_queries << "\n";
    }

    if (t) {
        t->commit();
        delete t;
    }

    return (r | returnCode);
}
