/**
 * @file duasan.cpp
 * @brief Filter DUA candidates and adjust siphon trace positions using Clang ASTs.
 *
 * @par Paper connection
 * Zhenghao Hu, Yu Hu, and Brendan Dolan-Gavitt, "Chaff Bugs: Deterring Attackers
 * by Making Software Buggier," 2018, arXiv:1808.00659, sections IV-A1 and V-B3.
 * IV-A1 requires initialized DUA bytes at the siphon (the inserted copy into
 * global storage). V-B3 explains why observing initialization in one execution
 * is insufficient: a conditional initializer may not execute on another input.
 * Its strategy requires a reference in the same or an enclosing scope before
 * siphoning. This tool implements a syntactic approximation of that strategy.
 * @see https://arxiv.org/html/1808.00659v1#S4.SS1.SSS1
 * @see https://arxiv.org/html/1808.00659v1#S5.SS2.SSS3
 *
 * @par From recorded DUA to source expression
 * A DUA is dead, uncomplicated, available input. Discovery/taint tracking happens
 * earlier in the pipeline, not here. main() loads existing Dua rows into _duas;
 * dua->lval supplies the recorded filename, line/column range and AST spelling.
 * ClangTool parses the source into an AST (abstract syntax tree). MatchFinder
 * selects function definitions and invokes TestMatcher::run() for each one.
 * A CompoundStmt is a brace-delimited block; Expr nodes represent expressions.
 * dyn_cast<T>() asks whether a node has shape T and returns nullptr otherwise.
 *
 * @par Checks and database result
 * run() uses locInScope() to find functions containing the recorded source range.
 * paramCheck() accepts matching non-pointer, non-reference parameters. Otherwise
 * scopeCheck() scans statements in containing blocks; rhsExprCheck() compares
 * expression name components against xtractMembers(). A reference is evidence
 * of an existing use, not proof that a declaration initializes every byte.
 * For a later selected position, run() requires a SourceTrace row for the same
 * input and coordinates at or after the original trace index; it updates only
 * Dua::trace_index, not SourceLval::loc. Missing evidence marks the DUA fake.
 *
 * @par Small example (recorded candidate: p at the first semicolon)
 * @code{.cpp}
 * void consume(int);
 * void subject(int *p) {
 *     ;             // Original recorded DUA point; p is not accepted as a parameter.
 *     consume(*p);  // CallExpr -> UnaryOperator -> DeclRefExpr named p.
 *     ;             // scopeCheck selects this next statement as the new point.
 * }
 * @endcode
 * Relocation needs a matching dynamic trace entry for the last semicolon. A read
 * inside an unrelated sibling/conditional block is not evidence for this scope.
 * Taking &p alone also does not read p's value (see addressExprCheck()).
 *
 * @par Limits and persistence
 * Source ranges and names do not establish declaration identity, definite
 * initialization, object lifetime, alias relationships, or array-element identity.
 * This file does not implement the runtime string/pointer bounds checks discussed
 * separately in V-B3, nor does it prove the paper's non-exploitability guarantees.
 * Normal runs commit DUA updates before removeBugsUsingFakeDuas() deletes
 * eligible dependent bugs. Unmatched candidates fail before commit unless an
 * intentional partial run opts into --allow-unmatched-duas; this coverage audit
 * detects missing matches, not every possible coordinate drift. Dry runs roll
 * back and skip deletion. Existing
 * build/run references protect bugs.
 */

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include <iostream>
#include <fstream>
#include <set>
#include <stdexcept>

#include <odb/pgsql/database.hxx>
#include "lava-odb.hxx"
#include "lava.hxx"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
using namespace llvm;
using namespace llvm::sys::fs;
using namespace llvm::sys::path;

using namespace odb::core;
/// Database connection shared by AST callbacks; main() owns transaction boundaries.
std::unique_ptr<odb::pgsql::database> db;

/// DUA objects loaded for the current batch in increasing ID order.
std::vector<std::shared_ptr<Dua>> _duas;
/// Unique candidate IDs examined and rejected across all parsed translation units.
std::set<uint64_t> checked_duas, rejected_duas;

static cl::opt<bool> DryRun("dry-run",
    cl::desc("Report DUA rejection decisions without updating or deleting database rows"),
    cl::init(false));
static cl::opt<bool> AllowUnmatchedDuas("allow-unmatched-duas",
    cl::desc("Allow unchecked DUAs for an intentional partial-source run (disables coverage failure)"),
    cl::init(false));
static cl::opt<std::string> SourceDir("src-prefix",
    cl::desc("Preprocessed source file directory"),
    cl::init(""));
static cl::opt<std::string> BugDB("db",
    cl::desc("Database Name"),
    cl::init(""));
static cl::opt<std::string> DBHost("host",
    cl::desc("Remote Host"),
    cl::init("database"));
static cl::opt<int> DBPort("port",
    cl::desc("Remote Port"),
    cl::init(5432));

/**
 * @brief Store macro expansion line and column coordinates.
 * @param full_loc Valid Clang location associated with its source manager.
 */
Loc::Loc(const FullSourceLoc &full_loc)
    : line(full_loc.getExpansionLineNumber()),
    column(full_loc.getExpansionColumnNumber()) {}

namespace {

/**
 * @brief Remove the configured source prefix and following slash characters.
 * @param filename Absolute source filename.
 * @param prefix Source directory prefix, matched at a path-component boundary.
 * @return Remaining filename, or an empty string when the prefix does not match.
 */
std::string StripPrefix(std::string filename, std::string prefix) {
    size_t prefix_len = prefix.length();
    if (filename.compare(0, prefix_len, prefix) != 0) {
        // Outside -src-prefix (system headers): no DUA lives there. Return a name that matches
        // nothing (the old printf + assert(false) printed millions of lines; assert is off in Release).
        return std::string();
    }
    if (prefix_len != 0 && prefix[prefix_len - 1] != '/'
            && filename.size() > prefix_len && filename[prefix_len] != '/') {
        return std::string();
    }
    while (prefix_len < filename.size() && filename[prefix_len] == '/') {
        prefix_len++;
    }
    return filename.substr(prefix_len);
}

/**
 * @brief Translate a statement's expansion range into database coordinates.
 *
 * Removes SourceDir and collapses embedded parent-directory segments using the
 * existing textual normalization. This does not resolve filesystem symlinks.
 * @param sm Source manager for the statement's translation unit.
 * @param s Non-null statement with valid source locations.
 * @return Prefix-relative filename and inclusive begin/end source coordinates.
 */
ASTLoc GetASTLoc(const SourceManager &sm, const Stmt *s) {
    FullSourceLoc fullLocStart(sm.getExpansionLoc(s->getBeginLoc()), sm);
    FullSourceLoc fullLocEnd(sm.getExpansionLoc(s->getEndLoc()), sm);
    std::string src_filename = StripPrefix(getAbsolutePath(sm.getFilename(fullLocStart)), SourceDir);
    size_t findhint = 0;
    while (src_filename.find("/../", findhint) != std::string::npos) {
        std::string::size_type matchindex = src_filename.find("/../", findhint);
        if (matchindex >= 2 && src_filename[matchindex-1] == '.' && src_filename[matchindex-2] == '.') {
            findhint = matchindex + 4;
            continue;
        }
        std::string::size_type pos0 = src_filename.rfind('/', matchindex - 1);
        if (pos0 != std::string::npos) {
            src_filename.erase(pos0, matchindex + 3 - pos0);
        }
        else {
            src_filename.erase(0, matchindex + 4);
        }
    }
    return ASTLoc(src_filename, fullLocStart, fullLocEnd);
}

/**
 * @brief Test inclusive source-range containment within a compound statement.
 * @param sm Source manager used to normalize the body's coordinates.
 * @param body Non-null compound statement to compare.
 * @param locdua Recorded candidate range in the same coordinate convention.
 * @return True when filenames match and both endpoints are within the body.
 * @note Implements the block-containment part of the V-B3 scope strategy:
 * a read in a sibling block must not justify a siphon outside that block.
 * This compares source coordinates, not C++ declaration bindings. GetASTLoc()
 * uses macro expansion locations so both sides must use that same convention.
 */
bool locInScope(const SourceManager &sm, const CompoundStmt *body, const ASTLoc &locdua) {
    ASTLoc loccomp = GetASTLoc(sm, body);
    return loccomp.filename == locdua.filename
        && (!(locdua.begin < loccomp.begin))
        && (!(loccomp.end < locdua.end));
}

/**
 * @brief Extract ordered name components from the stored lvalue spelling.
 *
 * Skips leading parentheses, dereference and address-of characters, then splits
 * at closing parentheses and skips separating dots. This handles the stored
 * spelling convention rather than parsing arbitrary C/C++ expressions.
 * For example, "((object).field)" becomes {"object", "field"}; "&(array)"
 * becomes {"array"}. Stripping address/dereference wrappers loses pointer-versus-pointee identity;
 * callers must not interpret this name match as full alias or type analysis.
 * @param sourcelval Non-null source lvalue containing the AST name.
 * @return Components used for exact name matching, possibly empty.
 */
std::vector<std::string> xtractMembers(const SourceLval *sourcelval) {
    std::string astname = sourcelval->ast_name;
    std::vector<std::string> result;
    std::string::iterator it = std::find_if_not(astname.begin(), astname.end(), [&](const char c) { return c == '(' || c == '*' || c == '&'; });
    while (it != astname.end()) {
        std::string::iterator previt = it;
        it = std::find_if(previt, astname.end(), [&](const char c) { return c == ')'; });
        result.push_back(std::string(previt, it));
        it = std::find_if_not(it, astname.end(), [&](const char c) { return c == '.' || c == ')'; });
    }
    return result;
}

/**
 * @brief Analyze function definitions against the current batch of DUAs.
 *
 * Matching uses names and source ranges, without alias analysis or a control-flow
 * graph. Rejected candidates and trace-index adjustments are persisted unless
 * DryRun is set. An active database transaction must surround callback execution.
 */
class TestMatcher : public MatchFinder::MatchCallback {
public :
    /**
     * @brief Search supported expression shapes for an exact lvalue-name chain.
     *
     * Ignores parentheses/casts. Address-taking inspects only the reads needed
     * to compute the address, not the addressed object's value. Assignments
     * inspect only their RHS; other binary operators inspect both operands.
     * Conditional expressions inspect value arms; calls inspect arguments and
     * indirect callees. The condition itself is currently not searched.
     * Subscripts inspect both base and index; initializer lists inspect their
     * elements. Member chains must match in full, avoiding a match between a
     * whole object and one field.
     * @param expr Expression to inspect recursively; nullptr does not match.
     * @param lvalelem Ordered components of the candidate lvalue.
     * @return True on a supported syntactic match; unknown shapes emit diagnostics.
     * @par Examples and relation to V-B3
     * consume(x) supplies a syntactic reference to x; consume(&x) only forms its
     * address and does not. Reading object.field must not qualify object.other
     * or the complete object: another field may still be uninitialized.
     * @note This does not resolve callee side effects or follow aliases. Array
     * element reads are matched to their base name, not to individual elements.
     * Name extraction also strips dereference wrappers, so pointer and pointee
     * availability cannot be distinguished reliably by these components alone.
     */
    bool rhsExprCheck(const Expr *expr, const std::vector<std::string> &lvalelem) {
        if (!expr || lvalelem.empty()) {
            return false;
        }
        bool isvalid = false;
        const Expr *cur_expr = expr->IgnoreParenCasts();
        std::vector<std::string> cmpelem;
        while(true) {
            if (const DeclRefExpr *declref = dyn_cast<DeclRefExpr>(cur_expr)) {
                cmpelem.insert(cmpelem.begin(), declref->getFoundDecl()->getNameAsString());
                break;
            } else if (const MemberExpr *member = dyn_cast<MemberExpr>(cur_expr)) {
                cmpelem.insert(cmpelem.begin(), member->getMemberDecl()->getNameAsString());
                cur_expr = member->getBase()->IgnoreParenCasts();
            } else if (const BinaryOperator *binop = dyn_cast<BinaryOperator>(cur_expr)) {
                if (binop->isAssignmentOp()) {
                    return rhsExprCheck(binop->getRHS(), lvalelem);
                } else {
                    return rhsExprCheck(binop->getRHS(), lvalelem)
                        || rhsExprCheck(binop->getLHS(), lvalelem);
                }
            } else if (const ConditionalOperator *condop = dyn_cast<ConditionalOperator>(cur_expr)) {
                if (condop->getRHS()) {
                    isvalid = rhsExprCheck(condop->getRHS(), lvalelem);
                }
                if (condop->getLHS()) {
                    isvalid = isvalid || rhsExprCheck(condop->getLHS(), lvalelem);
                }
                return isvalid;
            } else if (const UnaryOperator *uniop = dyn_cast<UnaryOperator>(cur_expr)) {
                if (uniop->getOpcode() == UO_AddrOf) {
                    return addressExprCheck(uniop->getSubExpr(), lvalelem);
                }
                cur_expr = uniop->getSubExpr()->IgnoreParenCasts();
                // Reading *&object reads object, rather than only its address.
                if (uniop->getOpcode() == UO_Deref) {
                    const UnaryOperator *address = dyn_cast<UnaryOperator>(cur_expr);
                    if (address && address->getOpcode() == UO_AddrOf) {
                        cur_expr = address->getSubExpr()->IgnoreParenCasts();
                    }
                }
            } else if (const InitListExpr *list = dyn_cast<InitListExpr>(cur_expr)) {
                for (unsigned i = 0; i < list->getNumInits(); i++) {
                    isvalid = isvalid || rhsExprCheck(list->getInit(i), lvalelem);
                }
                return isvalid;
            } else if (const CallExpr *call = dyn_cast<CallExpr>(cur_expr)) {
                if (!call->getDirectCallee() && rhsExprCheck(call->getCallee(), lvalelem)) {
                    return true;
                }
                for (unsigned i = 0; i < call->getNumArgs(); i++) {
                    isvalid = isvalid || rhsExprCheck(call->getArg(i), lvalelem);
                }
                return isvalid;
            } else if (const ArraySubscriptExpr *array = dyn_cast<ArraySubscriptExpr>(cur_expr)) {
                if (rhsExprCheck(array->getIdx(), lvalelem)) {
                    return true;
                }
                cur_expr = array->getBase()->IgnoreParenCasts();
            } else if (const IntegerLiteral *intlit = dyn_cast<IntegerLiteral>(cur_expr)) {
                break;
            } else {
                std::cerr << "Warning Member Type Unknown\n";
                cur_expr->dump();
                break;
            }
        }

        if (cmpelem.size() == 0) {
            return false;
        }
        // Fix for nginx partially initialized dua: strict node matching
        if (lvalelem.size() != cmpelem.size()) {
            return false;
        }

        for (size_t i = 0; i < std::min(lvalelem.size(), cmpelem.size()); i++) {
            if (lvalelem[i] != cmpelem[i]) {
                return false;
            }
        }
        return true;
    }


    /**
     * @brief Find value reads required to compute an lvalue's address.
     *
     * &object and &object.field do not read object bytes. &pointer[index] reads
     * the pointer and index, whereas &array[index] reads only the index when the
     * base is an actual array. &*pointer reads the pointer. No callee effects or
     * alias relationships are inferred.
     * @param expr Non-null addressed expression.
     * @param lvalelem Candidate name components.
     * @return True when address computation reads the candidate.
     */
    bool addressExprCheck(const Expr *expr, const std::vector<std::string> &lvalelem) {
        expr = expr->IgnoreParenCasts();
        if (const ArraySubscriptExpr *array = dyn_cast<ArraySubscriptExpr>(expr)) {
            const Expr *base = array->getBase()->IgnoreParenImpCasts();
            return rhsExprCheck(array->getIdx(), lvalelem)
                || (base->getType()->isArrayType()
                    ? addressExprCheck(base, lvalelem)
                    : rhsExprCheck(base, lvalelem));
        }
        if (const MemberExpr *member = dyn_cast<MemberExpr>(expr)) {
            return member->isArrow() ? rhsExprCheck(member->getBase(), lvalelem)
                                     : addressExprCheck(member->getBase(), lvalelem);
        }
        if (const UnaryOperator *unary = dyn_cast<UnaryOperator>(expr)) {
            return unary->getOpcode() == UO_Deref
                && rhsExprCheck(unary->getSubExpr(), lvalelem);
        }
        return false;
    }

    /**
     * @brief Search a compound statement for a candidate siphon position.
     *
     * Visits statements in source order and recurses into supported compound
     * bodies. A matching initializer returns its declaration; matching ordinary
     * expressions and control conditions return the next sibling when present.
     * A declaration with the candidate's root name stops this scope's search.
     * Return statements, switch cases and unbraced control bodies are not searched.
     * @param sm Source manager forwarded through recursive searches.
     * @param body Non-null compound statement to scan.
     * @param dua Non-null candidate whose lvalue is to be matched.
     * @param reason Optional diagnostic for a declaration barrier. A failed
     * search is missing syntactic evidence, not proof of uninitialized bytes
     * (paper IV-A1 and V-B3); callee writes such as fread are not inferred.
     * @return Selected statement, or nullptr for an empty name, an unrelated
     * compound statement, or when no usable position is found.
     * @par Scope rule and corrected comment drift
     * V-B3 motivates looking for references in the DUA's block or an enclosing
     * block. The old nested-block comment claimed that recursive scopeCheck()
     * already checked locInScope(), but no such check existed in this function;
     * only run() checked the function body. The entry guard below now applies
     * containment on every recursive call. test_scope_search covers sibling
     * blocks, conditional-only reads, and reads within the containing block.
     * @note A declaration is not automatically proof of initialization: seeing
     * the candidate's own root declaration stops this search, even with an
     * initializer. A different variable's initializer that reads the candidate
     * is evidence of use and returns that DeclStmt. Other matches return the next
     * sibling statement. These are placement rules, not a control-flow proof.
     */
    const Stmt *scopeCheck(const SourceManager &sm, const CompoundStmt *body, const Dua *dua,
                          std::string *reason = nullptr) {
        const SourceLval *sourcelval = dua->lval;
        const Stmt *result = nullptr;

        std::vector<std::string> lvalelem = xtractMembers(sourcelval);
        if (lvalelem.empty() || !locInScope(sm, body, sourcelval->loc)) {
            return nullptr;
        }
        for (CompoundStmt::const_body_iterator stmtit = body->body_begin(); stmtit != body->body_end(); stmtit++) {
            // Start Testing Code
            if (const DeclStmt *declstmt = dyn_cast<DeclStmt>(*stmtit)) {
                for (DeclStmt::const_decl_iterator sdeclit = declstmt->decl_begin();
                        sdeclit != declstmt->decl_end();
                        sdeclit++) {
                    const VarDecl *vardecl = dyn_cast<VarDecl>(*sdeclit);
                    if (!vardecl) {
                        continue;
                    }
                    if (vardecl->getNameAsString() == lvalelem[0]) {
                        if (reason) {
                            *reason = "declaration-barrier: search stopped at candidate root declaration; "
                                "later initialization and callee writes are not analyzed";
                        }
                        return nullptr;
                    }
                    if (const Expr *initexpr = vardecl->getAnyInitializer()) {
                        if (rhsExprCheck(initexpr, lvalelem)) {
                            return declstmt;
                        }
                    }
                }
            } else if (const CompoundStmt *nestedcomp = dyn_cast<CompoundStmt>(*stmtit)) {
                // Recurse only into compound statements containing this DUA;
                // sibling blocks may contain unrelated objects with the same name.
                result = scopeCheck(sm, nestedcomp, dua, reason);
                if (result) {
                    return result;
                }
                // Dont RETURN since we need to continue our check afterward
            } else if (const ForStmt *forexpr = dyn_cast<ForStmt>(*stmtit)) {
                //forexpr->getInit()->dump();
                //forexpr->getInc()->dump();
                if (forexpr->getCond()
                   && rhsExprCheck(forexpr->getCond(), lvalelem)
                   && std::next(stmtit) != body->body_end()) {
                        return *std::next(stmtit);
                }
                if (forexpr->getBody()) {
                    if (const CompoundStmt *forbody = dyn_cast<CompoundStmt>(forexpr->getBody())) {
                        result = scopeCheck(sm, forbody, dua, reason);
                        if (result) {
                            return result;
                        }
                    } else {
                        // Skip This
                        //if (rhsExprCheck(forexpr->getBody(), lvalelem)) return true;
                    }
                }
            } else if (const WhileStmt *whilestmt = dyn_cast<WhileStmt>(*stmtit)) {
                if (whilestmt->getCond()
                   && rhsExprCheck(whilestmt->getCond(), lvalelem)
                   && std::next(stmtit) != body->body_end()) {
                   return *std::next(stmtit);
                }
                if (whilestmt->getBody()) {
                    if (const CompoundStmt *whilebody = dyn_cast<CompoundStmt>(whilestmt->getBody())) {
                        result = scopeCheck(sm, whilebody, dua, reason);
                        if (result) {
                            return result;
                        }
                    }
                }
            } else if (const IfStmt *ifexpr = dyn_cast<IfStmt>(*stmtit)) {
                if (rhsExprCheck(ifexpr->getCond(), lvalelem)
                   && std::next(stmtit) != body->body_end()) {
                   return *std::next(stmtit);
                }
                if (ifexpr->getThen()) {
                    if (const CompoundStmt *ifthen = dyn_cast<CompoundStmt>(ifexpr->getThen())) {
                        result = scopeCheck(sm, ifthen, dua, reason);
                        if (result) return result;
                    }
                }
                if (ifexpr->getElse()) {
                    if (const CompoundStmt *ifelse = dyn_cast<CompoundStmt>(ifexpr->getElse())) {
                        result = scopeCheck(sm, ifelse, dua, reason);
                        if (result) {
                            return result;
                        }
                    }
                }
            } else if (const SwitchStmt *swchstmt = dyn_cast<SwitchStmt>(*stmtit)) {
                if (rhsExprCheck(swchstmt->getCond(), lvalelem)
                   && std::next(stmtit) != body->body_end()) {
                   return *std::next(stmtit);
                }
                // Skip Cases
            } else if (const Expr *expr = dyn_cast<Expr>(*stmtit)) {
                // Other Expressions
                if (rhsExprCheck(expr, lvalelem)
                   && std::next(stmtit) != body->body_end()) {
                    return *std::next(stmtit);
                }
            } else if (const ReturnStmt *retstmt = dyn_cast<ReturnStmt>(*stmtit)) {
                // SKIP Return
            } else {
                std::cerr << "Warning Stmt Unknown\n";
                (*stmtit)->dump();
                //break;
            }
        }
        return nullptr;
    }

    /**
     * @brief Recognize candidate roots that name parameters passed by value.
     * @param sm Source manager retained in the interface; currently unused.
     * @param func Non-null function whose parameters are inspected.
     * @param sourcelval Non-null lvalue to match; empty component lists are rejected.
     * @return True for a matching parameter of neither pointer nor reference type.
     * @note Passing a pointer/reference does not establish pointee initialization.
     */
    bool paramCheck(const SourceManager &sm, const FunctionDecl *func, const SourceLval *sourcelval) {
        std::vector<std::string> lvalelem = xtractMembers(sourcelval);
        if (lvalelem.empty()) {
            return false;
        }
        for (FunctionDecl::param_const_iterator paramit = func->param_begin();
                paramit != func->param_end(); paramit++) {
            std::string paramname = (*paramit)->getNameAsString();
            // Pointer/reference arguments do not initialize the referenced bytes.
            if (!(*paramit)->getType()->isPointerType()
                    && !(*paramit)->getType()->isReferenceType()
                    && paramname == lvalelem[0]) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Process a matched function, rejecting or relocating contained DUAs.
     * @param Result Match containing "func" and its source manager.
     *
     * Skips system code and accepts matching parameters passed by value directly.
     * For other candidates, a later siphon needs a trace entry for the same input
     * at or after the original trace index. Missing positions mark the DUA fake.
     * DryRun changes only in-memory candidate objects and rejection counters.
     * @par Relating AST results to the execution trace
     * The AST supplies a source position, not an execution event. SourceTrace
     * links that position to the seed input's recorded execution. The query picks
     * the lowest matching index >= the old index. If the selected source point
     * is not later than the recorded DUA point, the existing trace index is kept.
     * No new source code or taint trace is generated by this callback.
     */
    virtual void run(const MatchFinder::MatchResult &Result) {
        const FunctionDecl *FS = Result.Nodes.getNodeAs<clang::FunctionDecl>("func");
        sm = Result.SourceManager;

        if (sm->isInSystemHeader(FS->getBeginLoc())) {
            return;
        }
        const CompoundStmt *body = dyn_cast<CompoundStmt>(FS->getBody());

        if(body == nullptr) {
            return;
        }
        FullSourceLoc fullloc(sm->getExpansionLoc(body->getBeginLoc()), *sm);
        // Native API check for system headers and internal compiler macros
        if (fullloc.isInSystemHeader() || sm->isInSystemMacro(fullloc)) {
            return;
        }

        // Fallback check to catch any package-installed /usr/ path
        // Before it checked for LLVM only, we now generalize this
        std::string absPath = getAbsolutePath(sm->getFilename(fullloc));
        if (absPath.compare(0, 9, "/usr/lib/") == 0 || absPath.compare(0, 13, "/usr/include/") == 0) {
            return;
        }

        for (std::shared_ptr<Dua> &dua : _duas) {
            // Check locInScope, keep things going if not in the scope
            if (!locInScope(*sm,
                        dyn_cast<CompoundStmt>(FS->getBody()),
                        dua->lval->loc)) {
                continue;
            }

            checked_duas.insert(dua->id);
            if (paramCheck(*sm, FS, dua->lval)) {
                continue;
            }

            std::string reason = "no-supported-reference: no usable siphon statement found "
                "in a containing block";
            const Stmt *newloc = scopeCheck(*sm, body, dua.get(), &reason);
            if (!newloc) {  // Discard unusable DUA - mark dua as `fake_dua`
                logRejection(*dua, reason);
                dua->fake_dua = true;
                rejected_duas.insert(dua->id);
                if (!DryRun) {
                    db->update(*dua);
                }
            } else {
                ASTLoc movloc = GetASTLoc(*sm, newloc);
                // DUA Siphon Code has Moved
                uint64_t trace_index = dua->trace_index;

                if (movloc.filename == dua->lval->loc.filename &&
                  !(dua->lval->loc.begin < movloc.begin)) {
                    continue;
                }
                using Query = odb::query<SourceTrace>;
                odb::result<SourceTrace> trres(db->query<SourceTrace>(
                            (Query::file_taint == dua->inputfile->id &&
                             Query::loc.filename == movloc.filename &&
                             Query::loc.begin.line == movloc.begin.line &&
                             Query::loc.begin.column == movloc.begin.column &&
                             Query::index >= trace_index) +
                            " ORDER BY " + Query::index + " LIMIT 1"));
                if (!trres.empty()) {
                    dua->trace_index = trres.begin()->index;
                } else {
                    logRejection(*dua, "missing-source-trace: selected siphon has no matching "
                        "execution for this input at or after the original trace index", &movloc);
                    dua->fake_dua = true;
                    rejected_duas.insert(dua->id);
                }
                if (!DryRun) {
                    db->update(*dua);
                }
            }
        }
    }

private:
    /**
     * @brief Explain each rejection without claiming definite uninitialization.
     * IV-A1 motivates initialized bytes; V-B3 motivates the reference/scope
     * heuristic. Missing SourceTrace evidence is a separate execution check.
     * Dry runs emit the same reasons without persisting their decisions.
     */
    void logRejection(const Dua &dua, const std::string &reason,
                      const ASTLoc *selected = nullptr) const {
        const ASTLoc &loc = dua.lval->loc;
        std::cerr << "DUASan reject DUA " << dua.id << " name=" << dua.lval->ast_name
                  << " at " << loc.filename << ':' << loc.begin.line << ':' << loc.begin.column
                  << " length=" << dua.length << " trace_index=" << dua.trace_index
                  << " reason=" << reason;
        if (selected) {
            std::cerr << " selected=" << selected->filename << ':' << selected->begin.line
                      << ':' << selected->begin.column;
        }
        std::cerr << " (paper IV-A1/V-B3; heuristic rejection, not proof of uninitialized bytes)\n";
    }

    const SourceManager *sm;
};

/**
 * @brief Load the next ordered batch of at most 100,000 DUAs into _duas.
 *
 * Uses ID pagination rather than numeric windows: missing IDs cannot end the
 * scan prematurely. Must run within the caller's active database transaction.
 * @param database Connection used to query and load the candidate objects.
 * @param last_id Exclusive lower bound, advanced to the last loaded ID on success.
 * @return True when candidates were loaded; false when _duas is empty.
 */
bool loadDuaBatch(odb::pgsql::database &database, uint64_t &last_id) {
    const size_t batch_size = 100000;
    _duas.clear();
    odb::result<Dua> candidates(database.query<Dua>(
        (odb::query<Dua>::id > last_id) + " ORDER BY "
        + odb::query<Dua>::id + " LIMIT " + std::to_string(batch_size)));
    for (odb::result<Dua>::iterator candidate = candidates.begin();
            candidate != candidates.end(); ++candidate) {
        _duas.emplace_back(candidate.load());
    }
    if (_duas.empty()) {
        return false;
    }
    last_id = _duas.back()->id;
    return true;
}

/**
 * @brief Audit whether every DUA in the current batch reached a function callback.
 *
 * A candidate enters checked_duas only after its recorded filename and range
 * match a parsed function. Previously unmatched rows silently survived, making
 * source-coordinate drift or omitted translation units look like a successful
 * sanitization. Report up to five concrete examples and return the full missing
 * count. main() rolls back on any missing candidate unless the caller explicitly
 * opts into a partial run with --allow-unmatched-duas.
 *
 * This is a runtime check, not assert(): Release builds must enforce it too.
 * Missing coverage is not proof of drift; excluded files and unsupported scopes
 * can also cause it. Conversely, drift that still lands inside another function
 * can pass this audit. Source provenance checks are still needed when changing
 * preprocessing (-E), macro/location conventions, or the query pass.
 * @return Number of loaded candidate IDs absent from checked_duas.
 */
size_t reportUnmatchedDuas() {
    size_t unmatched = 0;
    for (const std::shared_ptr<Dua> &dua : _duas) {
        if (checked_duas.count(dua->id) != 0) {
            continue;
        }
        if (unmatched < 5) {
            std::cerr << "Unchecked DUA " << dua->id << " at " << dua->lval->loc
                      << " (" << dua->lval->ast_name << ")\n";
        }
        ++unmatched;
    }
    if (unmatched != 0) {
        std::cerr << "DUASan coverage mismatch: " << unmatched << " of " << _duas.size()
                  << " DUAs in this batch did not match a parsed function. "
                  << "Possible source-coordinate drift, omitted source files, or unsupported scopes.\n";
    }
    return unmatched;
}

/**
 * @brief Fail-safe cleanup of unbuilt/unrun bugs that depend on fake DUA bytes.
 *
 * DUASan may run after Phase II has already created Bug rows, or against an
 * existing database during a rerun. Marking a Dua fake does not remove those
 * rows. This final safeguard deletes bugs with fake trigger bytes and bugs
 * with fake extra bytes, except CHAFF_STACK_UNUSED's extras, which are exempt.
 * Bugs referenced by build_bugs or run are retained to preserve their history
 * and foreign keys. No DUA, build, or run rows are deleted.
 *
 * If sanitization is eventually enforced between Phase I and Phase II, with
 * Phase II honoring rejection results, a fresh database needs no such cleanup.
 * Existing bug rows can still need it. This is database hygiene, not a proof
 * that retained bugs are safe to inject or that their DUAs are initialized.
 *
 * @par Transaction and performance
 * Owns a separate transaction: the caller must commit DUA updates and leave no
 * active transaction before calling. Exceptions roll back this cleanup through
 * the local transaction's destructor; previously committed DUA results survive.
 * A temporary, analyzed table identifies fake DuaBytes without loading millions
 * of Bug objects. SET LOCAL disables nested-loop plans only for this transaction;
 * stale planner statistics previously caused hours-long scans on large databases.
 * The temporary table is dropped on commit. Dry runs must not call this function.
 * @param database Connection containing the committed sanitization results.
 */
void removeBugsUsingFakeDuas(odb::pgsql::database &database) {
    std::cerr << "Finished cleaning up DUA, now updating Bugs\n";

    odb::transaction transaction(database.begin());
    database.execute("SET LOCAL enable_nestloop = off");
    database.execute("CREATE TEMP TABLE fake_duabytes ON COMMIT DROP AS"
                " SELECT db.id FROM duabytes db JOIN dua d ON d.id = db.dua WHERE d.fake_dua");
    database.execute("ANALYZE fake_duabytes");
    const std::string unused =
        " AND NOT EXISTS (SELECT 1 FROM build_bugs bb WHERE bb.value = bug.id)"
        " AND NOT EXISTS (SELECT 1 FROM run r WHERE r.fuzzed = bug.id)";
    unsigned long long erased = database.execute(
        "DELETE FROM bug USING fake_duabytes f WHERE bug.trigger = f.id" + unused);
    erased += database.execute(
        "DELETE FROM bug WHERE bug.id IN ("
        "  SELECT b.id FROM bug b CROSS JOIN LATERAL unnest(b.extra_duas) AS e(id)"
        "  JOIN fake_duabytes f ON f.id = e.id"
        "  WHERE b.type <> " + std::to_string((int)Bug::CHAFF_STACK_UNUSED) + ")" + unused);
    std::cerr << "Erased " << erased << " bugs that use fake DUAs\n";
    transaction.commit();
}

} // namespace

// Set up the command line options
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::OptionCategory ToolTemplateCategory("tool-template options");

/**
 * @brief Run AST-based DUA filtering, then remove eligible dependent bugs.
 *
 * Uses Clang's compilation database and source-path arguments. PostgreSQL
 * credentials come from POSTGRES_USER and POSTGRES_PASSWORD; connection and
 * source-prefix options are declared above. Each batch loads up to 100,000 DUAs
 * ordered by ID, continuing after the last loaded ID so gaps cannot end the scan.
 *
 * Parsing failure or incomplete DUA coverage rolls back candidate updates and
 * skips deletion. --allow-unmatched-duas explicitly permits partial coverage;
 * use it only when omitted candidates are intentional. DryRun also
 * rolls back and reports unique checked/rejected IDs. Otherwise candidate updates
 * commit first, followed by a separate cleanup transaction. Cleanup preserves
 * bugs referenced by builds or runs, and exempts CHAFF_STACK_UNUSED extra DUAs.
 * Parsing/coverage failures throw std::runtime_error. The transaction is owned
 * by a unique_ptr so unwinding rolls back before the function-level handler
 * reports the exception and returns failure. Python does not receive a C++
 * exception: subprocess.run(check=True) converts the nonzero process exit into
 * CalledProcessError. The pipeline's default run_local() path then exits too.
 * This remains active with NDEBUG and with Python assertions disabled.
 * @param argc Number of command-line arguments.
 * @param argv Command-line arguments, including the executable name.
 * @return Zero on normal completion or dry run; one for option, credential,
 * parsing, coverage or caught standard-exception failures.
 */
int main(int argc, const char **argv) try {
    llvm::Expected<CommonOptionsParser> ExpectedParser = CommonOptionsParser::create(argc, argv, ToolTemplateCategory);
    if (!ExpectedParser) {
        // Print the error message from LLVM
        llvm::errs() << ExpectedParser.takeError();
        return 1;
    }
    CommonOptionsParser &op = ExpectedParser.get();

    const char* pgpass = std::getenv("POSTGRES_PASSWORD");
    const char* pguser = std::getenv("POSTGRES_USER");
    if (pgpass) {
        std::cout << "POSTGRES_PASSWORD IS SET" << std::endl;
    } else {
        std::cout << "POSTGRES_PASSWORD is not set" << std::endl;
        exit(1);
    }

    if (pguser) {
        std::cout << "POSTGRES_USER IS SET: " << pguser << std::endl;
    } else {
        std::cout << "POSTGRES_USER is not set" << std::endl;
        exit(1);
    }

    db.reset(new odb::pgsql::database(pguser, pgpass,
                BugDB, DBHost, DBPort));
    std::unique_ptr<odb::transaction> t(new odb::transaction(db->begin()));

    TestMatcher Matcher;
    MatchFinder Finder;
    Finder.addMatcher(
            functionDecl(has(compoundStmt())).bind("func"),
            &Matcher);

    std::vector<std::string> sourcefiles = op.getSourcePathList();
    uint64_t last_id = 0;
    size_t loaded_duas = 0;
    size_t unmatched_duas = 0;
    while (loadDuaBatch(*db, last_id)) {
        ClangTool Tool(op.getCompilations(), sourcefiles);
        if (Tool.run(newFrontendActionFactory(&Finder).get()) != 0) {
            throw std::runtime_error(
                "DUASan parsing failed; rolling back DUA changes without deleting bugs");
        }
        loaded_duas += _duas.size();
        const size_t unmatched = reportUnmatchedDuas();
        unmatched_duas += unmatched;
        if (unmatched != 0 && !AllowUnmatchedDuas) {
            throw std::runtime_error(
                "DUASan refuses incomplete coverage; rolling back DUA changes "
                "without deleting bugs. Use --allow-unmatched-duas only for "
                "intentional partial-source runs.");
        }
    }
    std::cerr << "DUASan coverage: checked " << checked_duas.size() << " of "
              << loaded_duas << " loaded DUAs; unmatched " << unmatched_duas << "\n";

    if (DryRun) {
        std::cerr << "DUASan dry run: checked " << checked_duas.size()
                  << " DUAs; rejected " << rejected_duas.size()
                  << "; no database changes\n";
        t->rollback();
        return 0;
    }

    // Commit the DUA updates first: the bug cleanup below is slow on big DBs, and losing it must
    // not lose these (the whole run used to be one transaction).
    t->commit();
    t.reset();
    removeBugsUsingFakeDuas(*db);
    return 0;
} catch (const std::exception &error) {
    std::cerr << "DUASan failed: " << error.what() << "\n";
    return 1;
}
