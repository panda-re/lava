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

#include "lavaDB.h"
#include "lava.hxx"
#include "lava-odb.hxx"

#define RV_PFX "kbcieiubweuhc"
#define RV_PFX_LEN 13

#define DEBUG 0

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

struct Llval {
    std::string name;         // name of constructed lval
    std::string pointer_tst;  // name of base ptr for null test
    std::string len;          // string repr of computation of lval length
    const Type *typ;          // type of lval
    bool is_ptr;              // true if name represents ptr to what we are supposed to trace taint on (so no need to use '&').

    bool operator<(const Llval &other) const {
        return std::tie(name, pointer_tst, len, typ, is_ptr) <
            std::tie(other.name, other.pointer_tst, other.len, other.typ,
                    other.is_ptr);
    }
};

struct Insertions {
    std::string top_of_file;  // stuff to insert at top of file
    std::string before_part;  // stuff to insert right before thing under inspection
    std::string after_part;   // stuff to insert right after the thing under inspection
};

Loc::Loc(const FullSourceLoc &full_loc)
    : line(full_loc.getExpansionLineNumber()),
    column(full_loc.getExpansionColumnNumber()) {}

std::set<std::string> lava_get_proto;
std::set<std::string> lava_set_proto;

static std::set<const Bug*> bugs;

std::stringstream new_start_of_file_src;

#define MAX_STRNLEN 64
///////////////// HELPER FUNCTIONS BEGIN ////////////////////
std::string hex_str(uint32_t x) {
    std::stringstream ss;
    ss << "0x" << std::hex << x;
    return ss.str();
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

void SpitLlval(Llval &llval) {
    debug << "name=" << llval.name <<
        " pointer_tst=" << llval.pointer_tst <<
        " len=" << llval.len <<
        " is_ptr=" << llval.is_ptr;
#if DEBUG
    llval.typ->dump();
#endif
}
// struct fields known to cause trouble
bool InFieldBlackList(std::string field_name) {
    return ((field_name == "__st_ino" ) || (field_name.size() == 0));
}
// is this lvalname / line / filename, etc a bug inj point?
// if so, return the vector of bugs that are injectable at this point
std::set<const Bug*> AtBug(std::string lvalname, LavaASTLoc loc, bool atAttackPoint,
                    SourceLval::Timing insertion_point, bool is_retval ) {
    //                debug << "atbug : lvalname=" << lvalname << " filename=" << filename << " line=" << line << " atAttackPoint=" << atAttackPoint << " insertion_point=" << insertion_point<< " \n";
    std::set<const Bug*> injectable_bugs;
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
                    && ((is_retval
                            && (0 == strncmp(lvalname.c_str(), bug->dua->lval->ast_name.c_str(), RV_PFX_LEN)))
                        || lvalname == bug->dua->lval->ast_name)
                    && insertion_point == bug->dua->lval->timing);
        }
        if (atbug) {
            //                debug << "found injectable bug @ line " << line << "\n";
            injectable_bugs.insert(bug);
        }
    }
    //                debug << "Not at bug\n";
    //if (injectable_bugs.size() > 1) {
        //debug << (injectable_bugs.size()) << " injectable bugs at this source loc\n";
        //for (auto bug : injectable_bugs) {
            //debug << bug->str() << " \n";
        //}
    //}
    return injectable_bugs;
}


std::set<std::string> gatherDuas(LavaASTLoc loc) {
    std::set<std::string> duas;
    for ( const Bug *bug : bugs ) {
        //                        debug << bug->str() << "\n";
        // this is the dua siphon -- gather all unique dua names at this `loc`
        if (loc == bug->dua->lval->loc.adjust_line(MainInstrCorrection)) {
            //                debug << "found injectable bug @ line " << line << "\n";
            duas.insert(bug->dua->lval->ast_name);
        }
    }
    return duas;
}
std::pair<bool, Llval> ConstructLlval(std::string lvalname, std::string pointer_tst, const Type *lval_type) {
    std::string lvalderef;
    std::string lvallen;
    bool success = true;
    bool is_ptr = false;
    if (lval_type->isPointerType()) {
        is_ptr = true;
        const Type *pt = lval_type->getPointeeType().getTypePtr();
        //            lvalderef = "(" + lvalname + ")";
        if (pt->isCharType()) {
            // lval is a string
            lvallen = "(size_t) -1";  // strnlen(" + lvalname + "," + std::to_string(MAX_STRNLEN) + ")";
        }
        else {
            if ( pt->isVoidType() )
                success = false;
            // lval is a pointer, but not a string
            lvallen = "sizeof(*(" + lvalname + "))";
        }
    }
    else {
        // lval not a pointer
        if ( lval_type->isVoidType() )
            success = false;
        //            lvalderef = "(" + lvalname + ")";
        lvallen = "sizeof(" + lvalname + ")";
    }
    //        assert (lvalderef.length() != 0);
    assert (lvallen.length() != 0);
    // t is not a pointer
    Llval llval = { lvalname, pointer_tst, lvallen, lval_type, is_ptr };
    return std::make_pair(success,llval);
}


std::string RandVarName() {
    std::stringstream rvs;
    rvs << RV_PFX;
    rvs << rand();
    return rvs.str();
}

std::string RandTargetValue() {
    std::stringstream tv;
    tv << "0x12345678";
    return tv.str();
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
    //std::string fn_name = fd->getDirectCallee()->getNameInfo().getName().getAsString();
    //return
        //((fn_name.find("memcpy") != std::string::npos)
         //|| (fn_name.find("malloc") != std::string::npos)
         //|| (fn_name.find("memmove") != std::string::npos)
         //|| (fn_name.find("bcopy") != std::string::npos)
         //|| (fn_name.find("strcpy") != std::string::npos)
         //|| (fn_name.find("strncpy") != std::string::npos)
         //|| (fn_name.find("strcat") != std::string::npos)
         //|| (fn_name.find("strncat") != std::string::npos)
         //|| (fn_name.find("exec") != std::string::npos)
         //|| (fn_name.find("popen") != std::string::npos));
}
// insertions are like parentheses.  they have to match
// as in:
// before_outer before_inner thing after_inner after_outer
Insertions ComposeInsertions(Insertions &inss_outer, Insertions &inss_inner) {
    Insertions inss;
    inss.top_of_file = inss_outer.top_of_file + inss_inner.top_of_file;
    inss.before_part = inss_outer.before_part + inss_inner.before_part;
    inss.after_part = inss_inner.after_part + inss_outer.after_part;
    return inss;
}

bool EmptyInsertions(Insertions &inss) {
    return  (inss.top_of_file == "" && inss.before_part == "" && inss.after_part == "");
}

// ignore top of file stuff
bool EmptyInsertions2(Insertions &inss) {
    return  ( inss.before_part == "" && inss.after_part == "");
}

void SpitInsertions(Insertions &inss) {
    debug << "top_of_file=[" << inss.top_of_file << "]\n";
    debug << "before_part=[" << inss.before_part << "]\n";
    debug << "after_part=[" << inss.after_part << "]\n";
}
// compose a lava global for this bug id
std::string LavaGlobal(uint32_t id) {
    std::stringstream ss;
    ss << "lava_" << id;
    return ss.str();
}

/* create code that siphons dua bytes into a global
   this is how, given a byte in a dua we'll grab it and insert into a global
   o = 3; // byte # in dua (0 is lsb)
   i = 0; // byte # in global
   lava_1 |=  (((unsigned char *) &dua))[o] << (i*8) ;
*/
Insertions ComposeDuaSiphoning(Llval &llval, std::set<const Bug*> &injectable_bugs, std::string filename) {
    Insertions inss;
    // only insert one dua siphon if single bug
    // if > 1 bug we are living dangerously.
    if (bugs.size() == 1 && (returnCode & INSERTED_DUA_SIPHON)) return inss;
    returnCode |= INSERTED_DUA_SIPHON;
    std::string lval_name = llval.name;
    //        debug << "ComposeDuaSiphoning\n";
    std::stringstream siphon;
    if ((!(llval.pointer_tst == ""))  || llval.is_ptr)
        siphon << "if (";
    if (!(llval.pointer_tst == ""))  {
        siphon << "(" << llval.pointer_tst << ")";
        if (llval.is_ptr)
            siphon << " && ";
    }
    if (llval.is_ptr)
        siphon << "(" << llval.name << ")";
    if ((!(llval.pointer_tst == ""))  || llval.is_ptr)
        siphon << ")  {";
    for ( const Bug *bug : injectable_bugs) {
        uint32_t i = 0;
        std::string gn = LavaGlobal(bug->id);
        siphon << "int " << gn << " = 0;\n";
        std::string lval_base;
        if (llval.is_ptr)
            lval_base = llval.name;
        else
            lval_base = "&(" + llval.name + ")";
        for ( uint32_t offset : bug->selected_bytes ) {
            siphon << LavaGlobal(bug->id)
                   << " |= ((unsigned char *) "
                   << lval_base << ")[" << offset << "] << (" << i << "*8);";
            i ++;
            // we don't need more than 4 bytes of dua
        }
        siphon << "lava_set(" << (std::to_string(bug->id)) << "," << gn << ");\n";
    }
    if ((!(llval.pointer_tst == ""))  || llval.is_ptr)
        siphon << "}";

    inss.after_part = siphon.str();
    // this is prototype for setter
    if (lava_set_proto.count(filename) == 0) {
        inss.top_of_file = "void lava_set(unsigned int bn, unsigned int val);\n";
        lava_set_proto.insert(filename);
    }
    return inss;
}
///////////////// HELPER FUNCTIONS END ////////////////////
/*******************************
 * Matcher Handlers
 *******************************/
class LavaMatchHandler : public MatchFinder::MatchCallback {
public:
  LavaMatchHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
      rewriter(rewriter), StringIDs(StringIDs)   {}
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

private:
  std::map<std::string,uint32_t> &StringIDs;
  Rewriter &rewriter;
};
class MatcherDebugHandler : public LavaMatchHandler {
public:
    MatcherDebugHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
      rewriter(rewriter), StringIDs(StringIDs), LavaMatchHandler(rewriter, StringIDs)  {}

    virtual void run(const MatchFinder::MatchResult &Result) {
        debug << "====== Found Match =====\n";
        //for (auto n : Result.Nodes.IDToNodeMap){
        //toSiphon = Result.Nodes.getNodeAs<Stmt>("stmt");
        const Stmt *stmt;
        for (BoundNodes::IDToNodeMap::const_iterator n = Result.Nodes.getMap().begin();
                                                     n != Result.Nodes.getMap().end(); ++n){
            if (stmt = n->second.get<Stmt>()){
                debug << n->first << ": " << LavaMatchHandler::ExprStr(stmt) << "\n";
            }
        }
        return;
    }

private:
  std::map<std::string,uint32_t> &StringIDs;
  Rewriter &rewriter;
};

class PriQueryPointSimpleHandler : public LavaMatchHandler {
public:
  PriQueryPointSimpleHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
      rewriter(rewriter), StringIDs(StringIDs), LavaMatchHandler(rewriter, StringIDs)  {}

    Insertions ComposePriDuaQuery(const Stmt *stmt, LavaASTLoc ast_loc) {
        Insertions inss;
        std::stringstream before, after;
        before << "; vm_lava_pri_query_point(" << LavaMatchHandler::GetStringID(ast_loc);
        before << ", " << ast_loc.begin.line << ", " << SourceLval::BEFORE_OCCURRENCE << "); ";


        inss.before_part = before.str();
        inss.after_part = after.str();
        return inss;
    }
    virtual void run(const MatchFinder::MatchResult &Result) {
        const Stmt *toSiphon;
        toSiphon = Result.Nodes.getNodeAs<Stmt>("stmt");
        LavaASTLoc p = LavaMatchHandler::GetASTLoc(toSiphon);
        if (!LavaMatchHandler::InMainFile(toSiphon)) return;
        debug << "Have a pri SIMPLE query point!\n";

        Insertions inss;
        std::string top_of_file;
        if (LavaAction == LavaQueries) {
            inss = ComposePriDuaQuery(toSiphon, p);
            if (inss.before_part != "" || inss.after_part != "")
                num_taint_queries += 1;
            top_of_file = inss.top_of_file;
        }
        else if (LavaAction == LavaInjectBugs){
            std::set<std::string> duas = gatherDuas(p);
            std::stringstream dua_src_before;
            std::stringstream dua_src_after;
            for ( auto dua : duas ) {
                //an llval is { lvalname, pointer_tst, lvallen, lval_type, is_ptr };
                Llval llval = { dua, "", "", NULL, true };
                assert (llval.name.length() > 0);
                std::set<const Bug*> injectable_bugs = 
                    AtBug(llval.name, p, /*atAttackPoint=*/false,
                          SourceLval::BEFORE_OCCURRENCE, /*is_retval=*/ false);
                // NOTE: if injecting multiple bugs the same dua will need to be instrumented more than once        
                if (!injectable_bugs.empty()) {
                    debug << "PriQueryHandler: injecting a dua siphon for " << 
                        injectable_bugs.size() << " bugs " << p << " : " << llval.name << "\n"; 
                }
                else {
                    debug << "PriQueryHandlerSimple: No bugs for this dua. Something went wrong . . .\n";
                }
                // for dua siphoning, we want to insert *either* before or after.
                // based on the bug
                inss = ComposeDuaSiphoning(llval, injectable_bugs, p);
                top_of_file = inss.top_of_file != "" ?
                              inss.top_of_file : top_of_file;
                dua_src_before << inss.after_part;
                injectable_bugs =  AtBug(llval.name, p,false,
                        SourceLval::AFTER_OCCURRENCE, false);
                inss = ComposeDuaSiphoning(llval, injectable_bugs, p);
                top_of_file = inss.top_of_file != "" ?
                              inss.top_of_file : top_of_file;
                dua_src_after << inss.after_part;
            }
            inss.before_part = dua_src_before.str();
            inss.after_part = dua_src_after.str();
        }
        if (inss.before_part != "" ||
            inss.after_part != "" || 
            top_of_file != "") {
            debug << " Injecting dua siphon at " << LavaMatchHandler::ExprStr(toSiphon) << "\n";
            SpitInsertions(inss);
            //rewriter.InsertText(toSiphon->getLocStart(), inss.before_part);
            rewriter.InsertTextBefore(toSiphon->getLocStart(), inss.before_part);
            //if (!dyn_cast<ReturnStmt>(toSiphon))
                //rewriter.InsertTextAfterToken(toSiphon->getLocEnd(), inss.after_part);
            new_start_of_file_src << top_of_file;
        }
    }

private:
  std::map<std::string,uint32_t> &StringIDs;
  Rewriter &rewriter;
};

Insertions traditionalAttack(std::set<const Bug*> &injectable_bugs, bool malloc_style_attack){
    Insertions inss;
    bool first_attack = false;
    int j = 0;
    for (const Bug *bug : injectable_bugs) {
        debug << "attacking expr with bug " << j << " -- bugid=" << bug->id << "\n";
        std::string gn = "(lava_get(" + (std::to_string(bug->id)) + "))";
        // this is the magic value that will trigger the bug
        uint32_t magic_value = 0x6c617661;
        //                        if (bugs->size() > 1) {
            // with lots of bugs we need magic value to be distinct per bug
            magic_value -=  bug->id;
            //                        }
            //                        else {
            //                        }
        std::string magic_value_s = hex_str(magic_value);
        // byte-swapped version of magic value
        uint32_t magic_value_bs = __bswap_32(magic_value);
        std::string magic_value_bs_s = hex_str(magic_value_bs);
        // evaluates to 1 iff dua is the magic value
        std::string magic_test = "(" + magic_value_s + "==" + gn + "||" + magic_value_bs_s + "==" + gn + ")";
        //if (fn_name.find("malloc") != std::string::npos) {
        if (malloc_style_attack) {
            // nasty heuristic. for malloc, we want the lava switch 
            // to undersize the malloc to a few bytes and hope for
            // an overflow
            // ... oh dear how do we compose multiple attacks on malloc? 
            //                assert (first_attack);
            if (first_attack) {
                first_attack = false;
                //                                new_expr << magic_test << " ? 1 : " << orig_expr;
                inss.before_part = magic_test + " ? 1 : ";
            }
            break;
        }
        else {
            // for everything else we add lava_get() to the expr and hope to break things
            // also we test if its equal to magic value 
            std::string plus_op = "+";
            /*
            if (first_attack) {
                first_attack = false;
                new_expr << orig_expr; 
            }
            */
            inss.after_part += " " + plus_op + gn + "*" + magic_test;
        }
        j++;
    }
    return inss;
}

Insertions knobTriggerAttack(std::set<const Bug*> &injectable_bugs, bool malloc_style_attack){
    Insertions inss;
    bool first_attack = false;
    int j = 0;
    for (const Bug *bug : injectable_bugs) {
        debug << "attacking expr with knob-trigger bug " << j << " -- bugid=" << bug->id << "\n";
        std::string gn_lower = " (lava_get(" + (std::to_string(bug->id)) + ") & 0x0000ffff)";
        std::string gn_upper = "((lava_get(" + (std::to_string(bug->id)) + ") & 0xffff0000) >> 16)";
        // this is the magic value that will trigger the bug
        uint32_t magic_value = 0x6c617661 & 0xffff;
        //                        if (bugs->size() > 1) {
            // with lots of bugs we need magic value to be distinct per bug
            magic_value = (magic_value - bug->id) % 0x10000;
            //                        }
            //                        else {
            //                        }
        std::string magic_value_s = hex_str(magic_value);
        // byte-swapped version of magic value
        uint32_t magic_value_bs = __bswap_32(magic_value) >> 16;
        std::string magic_value_bs_s = hex_str(magic_value_bs);
        // evaluates to 1 iff dua is the magic value
        std::string magic_test_lower = "((" + magic_value_s + "==" + gn_lower + ")||(" + magic_value_bs_s + "==" + gn_lower + "))";
        std::string magic_test_upper = "((" + magic_value_s + "==" + gn_upper + ")||(" + magic_value_bs_s + "==" + gn_upper + "))";
        // for everything else we add lava_get() to the expr and hope to break things
        // also we test if its equal to magic value 
        std::string plus_op = "+";

        inss.after_part += " " + plus_op + "(" + gn_lower + "*" + magic_test_upper + ")" +
                           " " + plus_op + "(" + gn_upper + "*" + magic_test_lower + ")";
        j++;
    }
    return inss;
}

Insertions rangeStyleAttack(std::set<const Bug*> &injectable_bugs, uint32_t num_bits, bool malloc_style_attack){
    assert(bugs.size() == 1);
    assert(num_bits >= 0 && num_bits <= 7);
    uint32_t mask = ((uint32_t) 0xffffffff) >> num_bits;
    std::string mask_bit = hex_str(mask) + "&";
    Insertions inss;
    bool first_attack = false;
    int j = 0;
    for (const Bug *bug : injectable_bugs) {
        debug << "attacking expr with bug " << j << " -- bugid=" << bug->id << "\n";
        std::string gn = "(" + mask_bit + "lava_get(" + (std::to_string(bug->id)) + "))";
        // this is the magic value that will trigger the bug
        uint32_t magic_value = 0x6c617661;
        if (bugs.size() > 1) {
            // with lots of bugs we need magic value to be distinct per bug
            magic_value -=  bug->id;
        }
            //                        }
            //                        else {
            //                        }
        std::string magic_value_s = mask_bit + hex_str(magic_value);
        // byte-swapped version of magic value
        uint32_t magic_value_bs = __bswap_32(magic_value);
        std::string magic_value_bs_s = hex_str(magic_value_bs);
        // evaluates to 1 iff dua is the magic value
        std::string magic_test = "(" + magic_value_s + "==" + gn + "||" +
                                       magic_value_bs_s + "==" + gn + ")";
        //if (fn_name.find("malloc") != std::string::npos) {
        if (malloc_style_attack) {
            // nasty heuristic. for malloc, we want the lava switch 
            // to undersize the malloc to a few bytes and hope for
            // an overflow
            // ... oh dear how do we compose multiple attacks on malloc? 
            //                assert (first_attack);
            if (first_attack) {
                first_attack = false;
                //                                new_expr << magic_test << " ? 1 : " << orig_expr;
                inss.before_part = magic_test + " ? 1 : ";
            }
            break;
        }
        else {
            // for everything else we add lava_get() to the expr and hope to break things
            // also we test if its equal to magic value 
            std::string plus_op = "+";
            /*
            if (first_attack) {
                first_attack = false;
                new_expr << orig_expr; 
            }
            */
            inss.after_part += " " + plus_op + gn + "*" + magic_test;
        }
        j++;
    }
    return inss;
}


class ArgAtpPointHandler : public LavaMatchHandler {
public:
  ArgAtpPointHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
      rewriter(rewriter), StringIDs(StringIDs), LavaMatchHandler(rewriter, StringIDs)  {}

    /*
      Add code to call expr corresponding to use of dua that will trigger a bug here.
      Note that we may be injecting code that triggers more than one bug here. 
      NB: we dont actually know how to *change* code.
      so we instead just add another copy of the call with one
      of the arg perturbed by global.  :)
    */
    Insertions AttackArgInsertion(const Expr *arg, std::set<const Bug*> &injectable_bugs, LavaASTLoc ast_loc) {
        //        debug << "in ComposeAtpDuaUse\n";
        Insertions inss;
        // NB: only insert one dua use if single bug.
        // if > 1 bug we live dangerously and may have multiple attack points
        if (bugs.size() == 1 && (returnCode & INSERTED_DUA_USE)) return inss;
            // really, this cast can't fail, right?
        assert(arg);
        std::stringstream new_arg;
        std::string orig_arg = ExprStr(arg);
        uint32_t j = 0;
        //TODO figure out how to deal with this
        bool malloc_style_attack = false;
        bool first_attack = true;
        Insertions arg_ins;

        if (LavaAction == LavaInjectBugs) {
            // Nothing to do if we're not at an attack point
            if (injectable_bugs.empty())
                return inss;
            returnCode |= INSERTED_DUA_USE;
            if (lava_get_proto.count(ast_loc.filename) == 0) {
                inss.top_of_file = "extern unsigned int lava_get(unsigned int) ;\n";
                lava_get_proto.insert(ast_loc.filename);
            }
            Insertions attack_inss;
            if (KT)
                attack_inss = knobTriggerAttack(injectable_bugs, false /*malloc_style_attack*/);
            else
                attack_inss = traditionalAttack(injectable_bugs, false);
            arg_ins.before_part = attack_inss.before_part;
            arg_ins.after_part = attack_inss.after_part;
        }
        else if (LavaAction == LavaQueries) {
            if (!FN_ARG_ATP)
                return inss;
            std::stringstream corruption;
            // call attack point hypercall and return 0
            corruption << " + ({vm_lava_attack_point2(" << LavaMatchHandler::GetStringID(ast_loc) << ", ";
            corruption << 0 << ", " << AttackPoint::ATP_FUNCTION_CALL << "); 0;;})";
            arg_ins.after_part = corruption.str();
            num_atp_queries++;
        }
        //rewriter.InsertText(arg->getLocStart(), "(char *)(");
        //rewriter.InsertTextAfterToken(arg->getLocEnd(), ")" + arg_ins.after_part);
        rewriter.InsertTextAfterToken(arg->getLocEnd(), arg_ins.after_part);
        //        SourceRange sr = SourceRange(call_expr->getLocStart(),call_expr->getLocEnd());
        //        rewriter.ReplaceText(sr, new_call.str());
        return inss;
    }



    virtual void run(const MatchFinder::MatchResult &Result) {
        const CallExpr *ce = Result.Nodes.getNodeAs<CallExpr>("ce");
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("arg");
        debug << "Have a vulnerable arg: " << ExprStr(ce) << " -> " << ExprStr(toAttack) << "\n";
#if DEBUG
        toAttack->dump();
#endif
        debug << "Arg has type ";
#if DEBUG
        toAttack->getType().dump();
#endif
        debug << "\n";
        if (!LavaMatchHandler::InMainFile(ce)) return;
        LavaASTLoc p = LavaMatchHandler::GetASTLoc(toAttack);
        Insertions inss;
        std::set<const Bug*> bugs = AtBug("", p, true, SourceLval::NULL_TIMING, false);
        inss = AttackArgInsertion(toAttack, bugs, p);
        if (inss.before_part != "" || inss.after_part != "" || inss.top_of_file != "") {
            debug << " Injected FunctionArgBug into " << LavaMatchHandler::ExprStr(ce) << "\n";
            SpitInsertions(inss);
            //rewriter.InsertText(toAttack->getLocStart(), inss.before_part);
            //rewriter.InsertTextAfterToken(toAttack->getLocEnd(), inss.after_part);
            new_start_of_file_src << inss.top_of_file;
        }
        return;
    }

private:
  std::map<std::string,uint32_t> &StringIDs;
  Rewriter &rewriter;
};


class AtpPointerQueryPointHandler : public LavaMatchHandler {
public:
  AtpPointerQueryPointHandler(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
      rewriter(rewriter), StringIDs(StringIDs), LavaMatchHandler(rewriter, StringIDs)  {}

    /*
TODO: add description of what type of attacks we are doing here
    */
    Insertions AttackExpressionInsertion(const Expr *toAttack, const Expr *parent, bool memWrite,
            std::set<const Bug*> &injectable_bugs, LavaASTLoc ast_loc) {
        //        debug << "in AttackExpressionDuaUse\n";
        Insertions inss;
        std::stringstream new_source, corruption;
        new_source << LavaMatchHandler::ExprStr(toAttack);
        if (LavaAction == LavaInjectBugs) {
            if (bugs.size() == 1 && (returnCode & INSERTED_DUA_USE)) return inss;
            if (injectable_bugs.empty()) return inss;
            returnCode |= INSERTED_DUA_USE;
            // if > 1 bug we live dangerously and may have multiple attack points
            // NB: only insert one dua use if single bug.
            if (lava_get_proto.count(ast_loc) == 0) {
                inss.top_of_file = "extern unsigned int lava_get(unsigned int) ;\n";
                lava_get_proto.insert(ast_loc);
            }
            debug << new_source.str() << "is being attacked\n";
            Insertions attack_inss;
            if (KT)
                attack_inss = knobTriggerAttack(injectable_bugs, false /*malloc_style_attack*/);
            else
                attack_inss = traditionalAttack(injectable_bugs, false);
            corruption << attack_inss.after_part;
        }
        else if (LavaAction == LavaQueries) {
            bool memRead = !memWrite;
            if ((memWrite && MEM_WRITE_ATP) ||
                (memRead && MEM_READ_ATP)) {
                // call attack point hypercall and return 0
                corruption << "+ ({vm_lava_attack_point2(" << LavaMatchHandler::GetStringID(ast_loc) << ", ";
                corruption << 0 << ", " << AttackPoint::ATP_POINTER_RW << "); 0;})";
                new_source << corruption.str();
                num_atp_queries++;
            }
        }

        // we will get here if not attack was inject in knobTriggerAttack
        // or traditionalAttack
        if (corruption.str() == "")
            return inss;
        // Insert the new addition expression, and if parent expression is
        // already paren expression, do not add parens
        //if (dyn_cast<ParenExpr>(parent)) {
        if (dyn_cast<ParenExpr>(parent) || dyn_cast<ArraySubscriptExpr>(parent)){
            rewriter.InsertTextAfterToken(toAttack->getLocEnd(), " " + corruption.str());
            //SourceRange sr = SourceRange(toAttack->getLocStart(),toAttack->getLocEnd());
            //rewriter.ReplaceText(sr, "(" + new_source.str() + ")");

        }
        else {
            rewriter.InsertTextBefore(toAttack->getLocStart(), "(");
            rewriter.InsertTextAfterToken(toAttack->getLocEnd(), " " + corruption.str());
            rewriter.InsertTextAfterToken(parent->getLocEnd(), ")");
            //rewriter.InsertTextBefore(toAttack->getLocEnd(), ")");
            //SourceRange sr = SourceRange(toAttack->getLocStart(),toAttack->getLocEnd());
            //rewriter.ReplaceText(sr, "(" + new_source.str() + ")");
        }
        return inss;
    }

    virtual void run(const MatchFinder::MatchResult &Result) {
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("innerExpr");
        const Expr *parent = Result.Nodes.getNodeAs<Expr>("innerExprParent");
        bool memWrite = false;
        // memwrite style attack points will have assign_expr bound to a node
        if (Result.Nodes.getMap().find("assign_expr") != Result.Nodes.getMap().end()){
             memWrite = true;
        }
        if (!LavaMatchHandler::InMainFile(toAttack)) return;
        LavaASTLoc p = LavaMatchHandler::GetASTLoc(toAttack);
        //debug << "Have a atp pointer query point" << " at " << p.first << " " << p.second <<  "\n";
        //parent->dump();
        Insertions inss;
        std::set<const Bug*> bugs = AtBug("", p, true, SourceLval::NULL_TIMING, false);
        inss = AttackExpressionInsertion(toAttack, parent, memWrite, bugs, p);
        if (inss.before_part != "" || inss.after_part != "" || inss.top_of_file != "") {
            debug << " Injected MemoryReadWriteBug into " << LavaMatchHandler::ExprStr(parent) << "\n";
            SpitInsertions(inss);
            //rewriter.InsertText(toAttack->getLocStart(), inss.before_part);
            //rewriter.InsertTextAfterToken(toAttack->getLocEnd(), inss.after_part);
            new_start_of_file_src << inss.top_of_file;
        }
    }

private:
  std::map<std::string,uint32_t> &StringIDs;
  Rewriter &rewriter;
};

namespace clang {
namespace ast_matchers{
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


        Matcher.addMatcher(
                stmt(hasParent(compoundStmt())).bind("stmt"),
#if DEBUG == 1
                &HandlerMatcherDebug
#else
                &HandlerForPriQueryPointSimple
#endif
                );

        Matcher.addMatcher(
                callExpr(
                    forEachArgMatcher(expr(isAttackableMatcher()).bind("arg"))).bind("ce"),
#if DEBUG == 1
                &HandlerMatcherDebug
#else
                &HandlerForArgAtpPoint
#endif
);

        // an array subscript expression is composed of base[index]
        // matches all nodes of: *innerExprParent(innerExpr) = ...
        // and matches all nodes of: base[innerExprParent(innerExpr)] = ...
        Matcher.addMatcher(
                memWriteMatcher,
#if DEBUG == 1
                &HandlerMatcherDebug
#else
                &HandlerForAtpPointerQueryPoint
#endif
                );

        //// matches all nodes of: ... *innerExprParent(innerExpr) ...
        //// and matches all nodes of: ... base[innerExprParent(innerExpr)] ...
        Matcher.addMatcher(
                memReadMatcher,
#if DEBUG == 1
                &HandlerMatcherDebug
#else
                &HandlerForAtpPointerQueryPoint
#endif
                );

        }

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

        std::string start_of_file_str = std::string(new_start_of_file_src.str());
        auto y = sm.getMainFileID();
        //        y.dump();
        auto x = sm.getLocForStartOfFile(y);
        x.dump(sm);

        rewriter.InsertText(x, // sm.getLocForStartOfFile(sm.getMainFileID()),
                            //                            new_start_of_file_src.str(),
                            start_of_file_str,
                            true, true);
#if !DEBUG
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

std::set<const Bug*> loadBugs(const std::set<uint32_t> &bug_ids) {
    std::set<const Bug*> result;
    for (uint32_t bug_id : bug_ids) {
        result.insert(db->load<Bug>(bug_id));
    }
    return result;
}

int main(int argc, const char **argv) {
    CommonOptionsParser op(argc, argv, LavaCategory);
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());
    if (LavaAction == LavaQueries) {
        if (!(FN_ARG_ATP || MEM_READ_ATP || MEM_WRITE_ATP)) {
            FN_ARG_ATP = true;
            MEM_WRITE_ATP = true;
            MEM_READ_ATP = true;
        }
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
