// This makes sure assertions actually occur.
#ifdef NDEBUG
#undef NDEBUG
#endif

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
#include "clang/Driver/Options.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/Lexer.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/ReplacementsYaml.h"
#include "clang/Tooling/Tooling.h"
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

#define DEBUG 0
#define MATCHER_DEBUG 0

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
static cl::opt<std::string> MainFileList("main-files",
    cl::desc("Main files"),
    cl::cat(LavaCategory),
    cl::init(""));
static cl::opt<bool> KnobTrigger("kt",
    cl::desc("Inject in Knob-Trigger style"),
    cl::cat(LavaCategory),
    cl::init(false));

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
static std::set<std::string> main_files;

static std::map<std::string, uint32_t> StringIDs;

// Map of bugs with attack points at a given loc.
std::map<std::pair<LavaASTLoc, AttackPoint::Type>, std::vector<const Bug *>>
    bugs_with_atp_at;
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

std::set<std::string> parse_commas_strings(std::string list) {
    std::istringstream ss(list);
    std::set<std::string> result;
    std::string i;
    while(std::getline(ss, i, ',')) {
        result.insert(i);
    }
    return result;
}

template<typename Elem>
std::set<Elem> parse_commas(std::string list) {
    std::istringstream ss(list);
    std::set<Elem> result;
    Elem i;
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
#if MATCHER_DEBUG
    debug << "IsArgAttackable \n";
    arg->dump();
#endif
    const Type *t = arg->IgnoreParenImpCasts()->getType().getTypePtr();
    if (dyn_cast<OpaqueValueExpr>(arg) || t->isStructureType() || t->isEnumeralType() || t->isIncompleteType()) {
        return false;
    }
    if (QueriableType(t)) {
        if (t->isPointerType()) {
            const Type *pt = t->getPointeeType().getTypePtr();
            // its a pointer to a non-void
            if ( ! (pt->isVoidType() ) ) {
                return true;
            }
        }
        if ((t->isIntegerType() || t->isCharType()) && (!t->isEnumeralType())) {
            return true;
        }
    }
    return false;
}

///////////////// HELPER FUNCTIONS END ////////////////////

LExpr traditionalAttack(const Bug *bug) {
    // return LavaGet(bug) * MagicTest(bug->magic(), LavaGet(bug));
    return LHex(bug->magic()) * MagicTest(bug->magic(), LavaGet(bug));
}

LExpr knobTriggerAttack(const Bug *bug) {
    LExpr lava_get_lower = LavaGet(bug) & LHex(0x0000ffff);
    //LExpr lava_get_upper = (LavaGet(bug) >> LDecimal(16)) & LHex(0xffff);
    LExpr lava_get_upper = (LavaGet(bug) & LHex(0xffff0000)) >> LDecimal(16);
    // this is the magic value that will trigger the bug
    // we already know that magic_kt returns uint16_t so we don't have
    // to mask it
    uint16_t magic_value = bug->magic_kt();
    // DEBUG
    //debug << "Knob Trigger Attack\nbug magic "<< bug->magic_kt() << "\nbug id "<< bug->id<<"\n";
    printf("Knob Attack\nbug magic %8x\nbug id %llu\n", bug->magic_kt() , bug->id);
    return (lava_get_lower * MagicTest<uint16_t>(magic_value, lava_get_upper))
        + (lava_get_upper * MagicTest<uint16_t>(magic_value, lava_get_lower));
}

/*
 * Keeps track of a list of insertions and makes sure conflicts are resolved.
 */
class Insertions {
private:
    std::map<SourceLocation, std::string> impl;

public:
    void clear() { impl.clear(); }

    void InsertAfter(SourceLocation loc, std::string str) {
        if (!str.empty()) impl[loc].append(str);
    }

    void InsertBefore(SourceLocation loc, std::string str) {
        if (!str.empty()) {
            str.append(impl[loc]);
            impl[loc] = str;
        }
    }

    void render(const SourceManager &sm, std::vector<Replacement> &out) {
        out.reserve(impl.size() + out.size());
        for (const auto &keyvalue : impl) {
            out.emplace_back(sm, keyvalue.first, 0, keyvalue.second);
        }
    }
};

/*
 * Contains all the machinery necessary to insert and tries to create some
 * high-level constructs around insertion.
 * Fluent interface to make usage easier. Use Modifier::Change to point at a
 * specific clang expression and the insertion methods to make changes there.
 */
class Modifier {
private:
    Insertions &Insert;
    const LangOptions *LangOpts = nullptr;
    const SourceManager *sm = nullptr;
    const Stmt *stmt = nullptr;

public:
    Modifier(Insertions &Insert) : Insert(Insert) {}

    void Reset(const LangOptions *LangOpts_, const SourceManager *sm_) {
        LangOpts = LangOpts_;
        sm = sm_;
    }

    std::pair<SourceLocation, SourceLocation> range() const {
        auto startRange = sm->getExpansionRange(stmt->getLocStart());
        auto endRange = sm->getExpansionRange(stmt->getLocEnd());
        return std::make_pair(startRange.first, endRange.second);
    }

    SourceLocation before() const {
        return range().first;
    }

    SourceLocation after() const {
        // clang stores ranges as start of first token -> start of last token.
        // so to get character range for replacement, we need to add start of
        // last token.
        SourceLocation end = range().second;
        unsigned lastTokenSize = Lexer::MeasureTokenLength(end, *sm, *LangOpts);
        return end.getLocWithOffset(lastTokenSize);
    }

    const Modifier &InsertBefore(std::string str) const {
        Insert.InsertBefore(before(), str);
        return *this;
    }

    const Modifier &InsertAfter(std::string str) const {
        Insert.InsertAfter(after(), str);
        return *this;
    }

    const Modifier &Change(const Stmt *stmt_) {
        stmt = stmt_;
        return *this;
    }

    const Modifier &Parenthesize() const {
        return InsertBefore("(").InsertAfter(")");
    }

    const Modifier &Operate(std::string op, const LExpr &addend, const Stmt *parent) const {
        InsertAfter(" " + op + " " + addend.render());
        if (parent && !isa<ArraySubscriptExpr>(parent)
                && !isa<ParenExpr>(parent)) {
            Parenthesize();
        }
        return *this;
    }

    const Modifier &Add(const LExpr &addend, const Stmt *parent) const {
        // If inner stmt has lower precedence than addition, add parens.
        const BinaryOperator *binop = dyn_cast<BinaryOperator>(stmt);
        if (isa<AbstractConditionalOperator>(stmt)
                || (binop && !binop->isMultiplicativeOp()
                    && !binop->isAdditiveOp())) {
            Parenthesize();
        }
        return Operate("+", addend, parent);
    }
};

/*******************************
 * Matcher Handlers
 *******************************/
struct LavaMatchHandler : public MatchFinder::MatchCallback {
    LavaMatchHandler(Modifier &Mod) : Mod(Mod) {}

    std::string ExprStr(const Stmt *e) {
        clang::PrintingPolicy Policy(*LangOpts);
        std::string TypeS;
        llvm::raw_string_ostream s(TypeS);
        e->printPretty(s, 0, Policy);
        return s.str();
    }

    LavaASTLoc GetASTLoc(const SourceManager &sm, const Stmt *s) {
        assert(!SourceDir.empty());
        FullSourceLoc fullLocStart(sm.getExpansionLoc(s->getLocStart()), sm);
        FullSourceLoc fullLocEnd(sm.getExpansionLoc(s->getLocEnd()), sm);
        std::string src_filename = StripPrefix(
                getAbsolutePath(sm.getFilename(fullLocStart)), SourceDir);
        return LavaASTLoc(src_filename, fullLocStart, fullLocEnd);
    }

    LExpr LavaAtpQuery(LavaASTLoc ast_loc, AttackPoint::Type atpType) {
        return LBlock({
                LFunc("vm_lava_attack_point2",
                    { LDecimal(GetStringID(StringIDs, ast_loc)), LDecimal(0),
                        LDecimal(atpType) }),
                LDecimal(0) });
    }

    void AttackExpression(const SourceManager &sm, const Expr *toAttack,
            const Expr *parent, const Expr *rhs, AttackPoint::Type atpType) {
        LavaASTLoc ast_loc = GetASTLoc(sm, toAttack);
        std::vector<LExpr> pointerAddends;
        std::vector<LExpr> valueAddends;

        debug << "Inserting expression attack (AttackExpression).\n";
        if (LavaAction == LavaInjectBugs) {
            const std::vector<const Bug*> &injectable_bugs =
                map_get_default(bugs_with_atp_at,
                        std::make_pair(ast_loc, atpType));

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
            bugs_with_atp_at.erase(std::make_pair(ast_loc, atpType));
        } else if (LavaAction == LavaQueries) {
            // call attack point hypercall and return 0
            pointerAddends.push_back(LavaAtpQuery(ast_loc, atpType));
            num_atp_queries++;
        }

        if (!pointerAddends.empty()) {
            LExpr addToPointer = LBinop("+", std::move(pointerAddends));
            Mod.Change(toAttack).Add(addToPointer, parent);
        }

        if (!valueAddends.empty()) {
            assert(rhs);
            LExpr addToValue = LBinop("+", std::move(valueAddends));
            Mod.Change(rhs).Add(addToValue, nullptr);
        }
    }

    virtual void handle(const MatchFinder::MatchResult &Result) = 0;
    virtual ~LavaMatchHandler() = default;

    virtual void run(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;
        auto nodesMap = Result.Nodes.getMap();

#if MATCHER_DEBUG
        debug << "====== Found Match =====\n";
#endif
        for (auto &keyValue : nodesMap) {
            const Stmt *stmt = keyValue.second.get<Stmt>();
            SourceLocation start = stmt->getLocStart();
            if (stmt) {
                if (!sm.getFilename(start).empty() && sm.isInMainFile(start)
                        && !sm.isMacroArgExpansion(start)) {
#if MATCHER_DEBUG
                    debug << keyValue.first << ": " << ExprStr(stmt) << " ";
                    stmt->getLocStart().print(debug, sm);
                    debug << "\n";
#endif
                } else return;
            }
        }
        handle(Result);
    }

    const LangOptions *LangOpts = nullptr;

protected:
    Modifier &Mod;
};

struct PriQueryPointHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    // create code that siphons dua bytes into a global
    // for dua x, offset o, generates:
    // lava_set(slot, *(const unsigned int *)(((const unsigned char *)x)+o)
    // Each lval gets an if clause containing one siphon
    std::string SiphonsForLocation(LavaASTLoc ast_loc) {
        std::stringstream result_ss;
        for (const DuaBytes *dua_bytes : map_get_default(siphons_at, ast_loc)) {
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
        auto key = std::make_pair(ast_loc, AttackPoint::QUERY_POINT);
        for (const Bug *bug : map_get_default(bugs_with_atp_at, key)) {
            if (bug->type == Bug::RET_BUFFER) {
                const DuaBytes *buffer = db->load<DuaBytes>(bug->extra_duas[0]);
                result_ss << LIf(MagicTest(bug).render(), {
                            LIfDef("__x86_64__", {
                                LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) +
                                    LDecimal(buffer->selected.low), },
                                    { "movq %0, %%rsp", "ret" }),
                                LAsm({ UCharCast(LStr(buffer->dua->lval->ast_name)) +
                                    LDecimal(buffer->selected.low), },
                                    { "movl %0, %%esp", "ret" })})});
            }
        }
        bugs_with_atp_at.erase(key); // Only inject once.
        return result_ss.str();
    }

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        const Stmt *toSiphon = Result.Nodes.getNodeAs<Stmt>("stmt");
        const SourceManager &sm = *Result.SourceManager;

        LavaASTLoc ast_loc = GetASTLoc(sm, toSiphon);
        debug << "Have a query point @ " << ast_loc << "!\n";

        std::string before;
        if (LavaAction == LavaQueries) {
            before = "; " + LFunc("vm_lava_pri_query_point", {
                LDecimal(GetStringID(StringIDs, ast_loc)),
                LDecimal(ast_loc.begin.line),
                LDecimal(0)}).render() + "; ";

            num_taint_queries += 1;
        } else if (LavaAction == LavaInjectBugs) {
            before = SiphonsForLocation(ast_loc) + AttackRetBuffer(ast_loc);
        }
        Mod.Change(toSiphon).InsertBefore(before);
    }
};

struct FunctionArgHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("arg");
        const SourceManager &sm = *Result.SourceManager;

        debug << "FunctionArgHandler @ " << GetASTLoc(sm, toAttack) << "\n";

        AttackExpression(sm, toAttack, nullptr, nullptr, AttackPoint::FUNCTION_ARG);
    }
};

struct ReadDisclosureHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;
        const CallExpr *callExpr = Result.Nodes.getNodeAs<CallExpr>("call_expression");

        LExpr addend = LDecimal(0);
        // iterate through all the arguments in the call expression
        for (auto it = callExpr->arg_begin(); it != callExpr->arg_end(); ++it) {
            const Expr *arg = dyn_cast<Expr>(*it);
            if (arg) {
                if (arg->getType()->isIntegerType()) {
                    LavaASTLoc ast_loc = GetASTLoc(sm, arg);
                    Mod.Change(arg);
                    if (LavaAction == LavaQueries)  {
                        addend = LavaAtpQuery(GetASTLoc(sm, arg),
                                AttackPoint::PRINTF_LEAK);
                        Mod.Add(addend, nullptr);
                    } else if (LavaAction == LavaInjectBugs) {
                        const std::vector<const Bug*> &injectable_bugs =
                            map_get_default(bugs_with_atp_at,
                                    std::make_pair(ast_loc, AttackPoint::PRINTF_LEAK));
                        for (const Bug *bug : injectable_bugs) {
                            Mod.Parenthesize()
                                .InsertBefore(MagicTest(bug).render() +
                                        " ? &(" + ExprStr(arg) + ") : ");
                        }
                    }

                }
            }
        }
    }
};

struct MemoryAccessHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("innerExpr");
        const Expr *parent = Result.Nodes.getNodeAs<Expr>("lhs");
        const SourceManager &sm = *Result.SourceManager;
        LavaASTLoc ast_loc = GetASTLoc(sm, toAttack);
        debug << "PointerAtpHandler @ " << ast_loc << "\n";

        const Expr *rhs = nullptr;
        AttackPoint::Type atpType = AttackPoint::POINTER_READ;

        // memwrite style attack points will have rhs bound to a node
        auto it = Result.Nodes.getMap().find("rhs");
        if (it != Result.Nodes.getMap().end()){
            atpType = AttackPoint::POINTER_WRITE;
            rhs = it->second.get<Expr>();
            assert(rhs);
        }

        AttackExpression(sm, toAttack, parent, rhs, atpType);
    }
};

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
                                    hasLHS(hasDescendant(expr(
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

        debug << "*** handleBeginSource for: " << Filename << "\n";

        std::string insert_at_top;
        if (LavaAction == LavaQueries) {
            insert_at_top = "#include \"pirate_mark_lava.h\"\n";
        } else if (LavaAction == LavaInjectBugs) {
            if (main_files.count(getAbsolutePath(Filename)) > 0) {
                // This is the file with main! insert lava_[gs]et and whatever.
                std::ifstream lava_funcs_file(LavaPath + "/src_clang/lava_set.c");
                insert_at_top.assign(
                        std::istreambuf_iterator<char>(lava_funcs_file),
                        std::istreambuf_iterator<char>());
            } else {
                insert_at_top =
                    "void lava_set(unsigned int bn, unsigned int val);\n"
                    "extern unsigned int lava_get(unsigned int, unsigned int, unsigned int);\n";
            }
        }

        debug << "Inserting at top of file: \n" << insert_at_top;
        TUReplace.Replacements.emplace_back(Filename, 0, 0, insert_at_top);

        for (auto it = MatchHandlers.begin();
                it != MatchHandlers.end(); it++) {
            (*it)->LangOpts = &CI.getLangOpts();
        }

        return true;
    }

    virtual void handleEndSource() override {
        debug << "*** handleEndSource\n";

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

int main(int argc, const char **argv) {
    CommonOptionsParser op(argc, argv, LavaCategory);
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());

    LavaPath = std::string(dirname(dirname(dirname(realpath(argv[0], NULL)))));

    std::ifstream json_file(ProjectFile);
    Json::Value root;
    if (ProjectFile == "XXX") {
        if (LavaAction == LavaInjectBugs) {
            debug << "Error: Specify a json file with \"-project-file\".  Exiting . . .\n";
            exit(1);
        }
    } else {
        json_file >> root;
    }

    if (LavaDB != "XXX") StringIDs = LoadDB(LavaDB);

    odb::transaction *t = nullptr;
    if (LavaAction == LavaInjectBugs) {
        db.reset(new odb::pgsql::database("postgres", "postgrespostgres",
                    root["db"].asString()));
        t = new odb::transaction(db->begin());

        main_files = parse_commas_strings(MainFileList);

        // get bug info for the injections we are supposed to be doing.
        debug << "LavaBugList: [" << LavaBugList << "]\n";

        std::set<uint32_t> bug_ids = parse_commas<uint32_t>(LavaBugList);
        // for each bug_id, load that bug from DB and insert into bugs vector.
        std::transform(bug_ids.begin(), bug_ids.end(), std::back_inserter(bugs),
                [&](uint32_t bug_id) { return db->load<Bug>(bug_id); });

        for (const Bug *bug : bugs) {
            LavaASTLoc atp_loc = bug->atp->loc;
            auto key = std::make_pair(atp_loc, bug->atp->type);
            bugs_with_atp_at[key].push_back(bug);

            LavaASTLoc dua_loc = bug->trigger_lval->loc;
            siphons_at[dua_loc].insert(bug->trigger);

            if (bug->type != Bug::RET_BUFFER) {
                for (uint64_t dua_id : bug->extra_duas) {
                    const DuaBytes *dua_bytes = db->load<DuaBytes>(dua_id);
                    LavaASTLoc extra_loc = dua_bytes->dua->lval->loc;
                    siphons_at[extra_loc].insert(dua_bytes);
                }
            }
        }
    }

    debug << "about to call Tool.run \n";
    LavaMatchFinder Matcher;
    Tool.run(newFrontendActionFactory(&Matcher, &Matcher).get());
    debug << "back from calling Tool.run \n";

    if (LavaAction == LavaQueries) {
        std::cout << "num taint queries added " << num_taint_queries << "\n";
        std::cout << "num atp queries added " << num_atp_queries << "\n";

        if (LavaDB != "XXX") SaveDB(StringIDs, LavaDB);
    } else if (LavaAction == LavaInjectBugs) {
        if (!bugs_with_atp_at.empty()) {
            std::cout << "Warning: Failed to inject attacks for bugs:\n";
            for (const auto &keyvalue : bugs_with_atp_at) {
                std::cout << "    At " << keyvalue.first.first << "\n";
                for (const Bug *bug : keyvalue.second) {
                    std::cout << "        " << *bug << "\n";
                }
            }
        }
        if (!siphons_at.empty()) {
            std::cout << "Warning: Failed to inject siphons:\n";
            for (const auto &keyvalue : siphons_at) {
                std::cout << "    At " << keyvalue.first << "\n";
                for (const DuaBytes *dua_bytes : keyvalue.second) {
                    std::cout << "        " << *dua_bytes << "\n";
                }
            }
        }
    }

    if (t) {
        t->commit();
        delete t;
    }

    return 0;
}
