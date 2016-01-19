
extern "C" {
#include <stdlib.h>
#include <libgen.h>
}

#include <json/json.h>

#include <set>
#include "includes.h"
#include "lavaDB.h"

#include "../include/lava_bugs.h"

#define RV_PFX "kbcieiubweuhc"
#define RV_PFX_LEN 13


std::string BuildPath; 
char resolved_path[512];
std::string LavaPath;

using namespace clang;
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

static cl::opt<std::string> SMainInstrCorrection("main_instr_correction",
    cl::desc("Insertion line correction for post-main instr"), 
    cl::cat(LavaCategory),
    cl::init("XXX"));
                    
         
uint32_t MainInstrCorrection;

#define INSERTED_DUA_SIPHON 0x4
#define INSERTED_DUA_USE    0x8
#define INSERTED_MAIN_STUFF 0x16
 
uint32_t returnCode=0;

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
    const Type *typ;                // type of lval
    bool is_ptr;              // true if name represents ptr to what we are supposed to trace taint on (so no need to use '&').

    bool operator<(const Llval &other) const {
        if (name < other.name) return true;
        if (name > other.name) return false;
        if (pointer_tst < other.pointer_tst) return true;
        if (pointer_tst > other.pointer_tst) return false;
        if (len < other.len) return true;
        if (len > other.len) return false;
        if (typ < other.typ) return true;
        if (typ > other.typ) return false;
        return is_ptr < other.is_ptr;
    }      
};



struct Insertions {
    std::string top_of_file;  // stuff to insert at top of file
    std::string before_part;  // stuff to insert right before thing under inspection
    std::string after_part;   // stuff to insert right after the thing under inspection
};


std::set<std::string> lava_get_proto;
std::set<std::string> lava_set_proto;


std::map<Ptr, std::set<uint32_t>> ptr_to_set;

static std::set<Bug> bugs;


std::stringstream new_start_of_file_src;


#define MAX_STRNLEN 64


std::string hex_str(uint32_t x) {
    std::stringstream ss; 
    ss << "0x" << std::hex << x;
    return ss.str();
}

/*******************************************************************************
 * LavaTaintQuery
 ******************************************************************************/

class LavaTaintQueryASTVisitor :
    public RecursiveASTVisitor<LavaTaintQueryASTVisitor> {
public:
    LavaTaintQueryASTVisitor(Rewriter &rewriter,
        std::vector< VarDecl* > &globalVars, std::map<std::string,uint32_t> &StringIDs) :
            rewriter(rewriter), globalVars(globalVars), StringIDs(StringIDs)  {}

    
    void SpitLlval(Llval &llval) {
        errs() << "name=" << llval.name << 
            " pointer_tst=" << llval.pointer_tst << 
            " len=" << llval.len << 
            " is_ptr=" << llval.is_ptr;
        llval.typ->dump();
        
    }            


    uint32_t GetStringID(std::string s) {
        if (StringIDs.find(s) == StringIDs.end()) {
            StringIDs[s] = StringIDs.size();
        }
        return StringIDs[s];
    }

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

    bool TraverseDecl(Decl *d) {
        if (!d) return true;

        SourceManager &sm = rewriter.getSourceMgr();
        if (sm.isInMainFile(d->getLocation()))
            return RecursiveASTVisitor<LavaTaintQueryASTVisitor>::TraverseDecl(d);
        
        return true;
    }

    // give me an expr and i'll return the string repr from original source
    std::string ExprStr(Expr *e) {
        const clang::LangOptions &LangOpts = rewriter.getLangOpts();
        clang::PrintingPolicy Policy(LangOpts);
        std::string TypeS;
        raw_string_ostream s(TypeS);
        e->printPretty(s, 0, Policy);
        return s.str();
    }


    // struct fields known to cause trouble
    bool InFieldBlackList(std::string field_name) {
        return ((field_name == "__st_ino" ) || (field_name.size() == 0));
    }

    
    
    /*
      llval is lval we want to query for taint.
      note that we insert extra code if lval needs guarding b/c it might 
      otherwise try to deref a null pointer.
     */
    std::string ComposeDuaTaintQuery(Llval &llval, uint32_t filename_id, uint32_t line, uint32_t insertion_point) {
        Insertions inss;
        std::stringstream query;

        if ((!(llval.pointer_tst == ""))  || llval.is_ptr) 
            query << "if (";

        if (!(llval.pointer_tst == ""))  {
            query << "(" << llval.pointer_tst << ")";
            if (llval.is_ptr) 
                query << " && ";
        }

        if (llval.is_ptr) 
            query << "(" << llval.name << ")";
        
        if ((!(llval.pointer_tst == ""))  || llval.is_ptr) 
            query << ")  {";
        
            
        query << "vm_lava_query_buffer(";
        if (llval.is_ptr) 
            query << "(" << llval.name << "), " ;
        else 
            query << "&(" << llval.name << "), " ;
        query << llval.len << ", "
              << filename_id << ", "
              << GetStringID(llval.name) << ", "
              << line << ", "
              << insertion_point << ");\n";

        if ((!(llval.pointer_tst == ""))  || llval.is_ptr) 
            query << "}";
        
        return query.str();
    }

    /*
      recurse to determine if this statement contains any declarations 
      if expr is a fn arg this would mean any lvals for those decls wouldn't be in scope before
      the fn call
    */
    bool ContainsDecl(Stmt *s) {
        if (s) {
            //            s->dump();
            DeclStmt *ds = dyn_cast<DeclStmt>(s);
            if (ds) {
                //                errs() << "is a decl\n";
                return true;  // found decl
            }
            if (s->child_begin() == s->child_end()) {
                // leaf node
                //                errs() << "leaf\n";
                return false;
            }
            else {
                //                errs() << "nonleaf\n";
                // s not a leaf -- has children
                int i = 0;
                for ( auto &child : s->children() ) {
                    i ++;
                    //                    errs() << "child " << i << "\n";
                    if  (ContainsDecl(child)) return true;
                }
            }
        }
        return false;
    }


    void CollectLvalsStmt(Stmt *s, std::set<Expr *> &lvals) {
        if (s) {
            if (s->child_begin() == s->child_end()) {
                // s is a leaf node -- it must be an expression?
                Expr *e = dyn_cast<Expr>(s);
                if (e) {
                    if (! ((e->getType().getTypePtr())->isNullPtrType()) ) {
                        Expr *eic = e->IgnoreCasts(); 
                        if (eic->isLValue()) {
                            StringLiteral *sl = dyn_cast<StringLiteral>(eic);
                            if (!sl) {
                                // e is an lval and NOT a string literl
                                if (CanGetSizeOf(eic)) {
                                    // make sure its not a register
                                    lvals.insert(eic->IgnoreCasts());
                                }
                            }
                        }
                    }
                }
            }
            else {
                // s has children -- recurse
                for ( auto &child : s->children() ) {             
                    CollectLvalsStmt(child, lvals);
                }
            }
        }
    }        

    // Find lvals buried in e. new lvals get added to lvals set
    void CollectLvals(Expr *e, std::set<Expr *> &lvals) {
        Stmt *s = dyn_cast<Stmt>(e);
        if (s) {
            CollectLvalsStmt(s, lvals);
        }
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


    // based on type, determine if this lval is queriable
    // which means can we get an addr out of it in ways we'll need to
    // and determine its size
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
    
    /*
      lv_name is base for a struct.  Might be a pointer.
      Use rd to iterate over slots in that struct and collect llvals.  
      pointer indicates if lv_name is a pointer (and thus needs a null test)
    */
    void CollectLlvalsStruct1stLevel(std::string lv_name, RecordDecl *rd, 
                                     bool pointer, std::set<Llval> &llvals) {
        for (auto field : rd->fields()) {
            if ( (!(field->getType()->isIncompleteType()))
                 && (!(field->getType()->isIncompleteArrayType()))
                 && (!(field->isBitField())) 
                 && (!(InFieldBlackList(field->getName().str())))) {
                std::string accessor =
                    (pointer ? (std::string("->")) : (std::string(".")));                    
                std::string lval_ss = 
                    lv_name + accessor + field->getName().str();
                std::string pointer_tst = (pointer ? lv_name : "");                
                QualType qt = field->getType();
                // discard a->b when it is a pointer.  
                // why?  because what if a is non-null but doesnt point to valid memory? 
                // a->b is a deref that will seg fault.  
                const Type *lval_type = qt.getTypePtr();
                if (!lval_type->isPointerType()) {
                    std::pair<bool, Llval> res = ConstructLlval(lval_ss, pointer_tst, lval_type);
                    bool success = res.first;
                    if (success) {
                        Llval llval = res.second;                
                        llvals.insert(llval); 
                    }
                }
            }
        }
    }

    // check if lval is a struct or a ptr-to-a-struct,
    // if so, then collect lvals (as strings) that are 1st level struct slots
    void CollectLlvalsStruct(Expr *lval, std::set<Llval> &llvals) {
        if (!CanGetSizeOf(lval)) 
            return;
        QualType qt = lval->getType();
        const Type *t = qt.getTypePtr();
        std::string lv_name = "(" + ExprStr(lval) + ")";
        if (t->isPointerType()) {
            if (t->getPointeeType()->isRecordType()) {
                // we have a ptr to a struct 
                const RecordType *rt = t->getPointeeType()->getAsStructureType();
                if (rt) {
                    CollectLlvalsStruct1stLevel(lv_name, rt->getDecl(), /* pointer = */ true, llvals);
                }
            }
        }
        else {
            if (t->isRecordType()) {
                // we have a struct
                const RecordType *rt = t->getAsStructureType();
                if (rt) {
                    CollectLlvalsStruct1stLevel(lv_name, rt->getDecl(), /* pointer = */ false, llvals);
                }
            }
        }
    }


    bool CanGetSizeOf(Expr *e) {
        assert (e->isLValue());
        DeclRefExpr *d = dyn_cast<DeclRefExpr>(e);
        if (d) {
            const Type *t = e->getType().getTypePtr();
            VarDecl *vd = dyn_cast<VarDecl>(d->getDecl());
            if (vd) {
                if (vd->getStorageClass() == SC_Register) return false;
                if (t->isPointerType() && !t->isNullPtrType() && t->getPointeeType()->isIncompleteType()) return false;
                if (t->isIncompleteType()) return false;
                return true;
            }
            else {
                return false;
            }
        }
        else {
            Stmt *s = dyn_cast<Stmt>(e);
            if (s) {
                for ( auto &child : s->children() ) {
                    Expr *ce = dyn_cast<Expr>(child)->IgnoreCasts();
                    if (ce) {
                        if (!CanGetSizeOf(ce)) return false;
                    }
                }
                // Made it through all children and they passed
                return true;
            }
            else {
                // Not a DeclRefExpr and no children. Ignore it.
                return false;
            }
        }
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

    bool IsArgAttackable(Expr *arg) {
        //        errs() << "IsArgAttackable \n";
        //        arg->dump();
        const Type *t = arg->getType().getTypePtr();
        if (t->isStructureType() || t->isEnumeralType() || t->isIncompleteType()) {
            return false;
        }
        if (QueriableType(t)) {
            //            errs() << "is of queriable type\n";
            if (t->isPointerType()) {
                //                errs() << "is a pointer type\n";
                const Type *pt = t->getPointeeType().getTypePtr();
                // its a pointer to a non-void 
                if ( ! (pt->isVoidType() ) ) {
                    //                    errs() << "is not a void type -- ATTACKABLE\n";
                    return true;
                }
            }
            if ((t->isIntegerType() || t->isCharType()) && (!t->isEnumeralType())) {
                //                errs() << "is integer or char and not enum -- ATTACKABLE\n";
                return true;
            }
        }
        //        errs() << "not ATTACKABLE\n";
        return false;
    }

    bool IsAttackPoint(CallExpr *e) {
        for ( auto it = e->arg_begin(); it != e->arg_end(); ++it) {
            Stmt *stmt = dyn_cast<Stmt>(*it);
            if (stmt) {
                Expr *arg = dyn_cast<Expr>(*it);
                // can't fail, right? 
                assert (arg);
                if (IsArgAttackable(arg)) return true;
            }
        }
        return false;
        /*
        std::string fn_name = fd->getDirectCallee()->getNameInfo().getName().getAsString();
        return
            ((fn_name.find("memcpy") != std::string::npos) 
             || (fn_name.find("malloc") != std::string::npos)
             || (fn_name.find("memmove") != std::string::npos)
             || (fn_name.find("bcopy") != std::string::npos)
             || (fn_name.find("strcpy") != std::string::npos)
             || (fn_name.find("strncpy") != std::string::npos)
             || (fn_name.find("strcat") != std::string::npos)
             || (fn_name.find("strncat") != std::string::npos)
             || (fn_name.find("exec") != std::string::npos)
             || (fn_name.find("popen") != std::string::npos));
        */
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
        errs() << "top_of_file=[" << inss.top_of_file << "]\n";
        errs() << "before_part=[" << inss.before_part << "]\n";
        errs() << "after_part=[" << inss.after_part << "]\n";
    }

    Insertions ComposeAtpQuery(CallExpr *ce, std::string filename, uint32_t line) {
        std::string fn_name =  ce->getDirectCallee()->getNameInfo().getName().getAsString();
        Insertions inss;
        if (IsAttackPoint(ce)) {                
            /*
              if ((fn_name.find("memcpy") != std::string::npos) 
              || (fn_name.find("malloc") != std::string::npos)
              || (fn_name.find("memmove") != std::string::npos)
              || (fn_name.find("bcopy") != std::string::npos)
              || (fn_name.find("strcpy") != std::string::npos)
              || (fn_name.find("strncpy") != std::string::npos)
              || (fn_name.find("strcat") != std::string::npos)
              || (fn_name.find("strncat") != std::string::npos)
              || (fn_name.find("exec") != std::string::npos)
              || (fn_name.find("popen") != std::string::npos)) {
            */
            // this is an attack point              
            std::stringstream before;
            std::stringstream after;
            //            errs() << "Found attack point at " << filename << ":" << line << "\n";
            before << "({";
            QualType rqt = ce->getCallReturnType();
            bool has_retval = CallExprHasRetVal(rqt);
            std::string retvalname = RandVarName();
            before << "vm_lava_attack_point(" << GetStringID(filename) << ", ";
            before << line << ", " << GetStringID(fn_name) << ");\n";
            if (has_retval) {
                before << (rqt.getAsString()) << " " << retvalname << " = ";
                after << "; " << retvalname << ";";
            }
            after << ";})";
            inss.before_part = before.str();
            inss.after_part = after.str();
        }
        return inss;
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
    Insertions ComposeDuaSiphoning(Llval &llval, std::set<Bug> &injectable_bugs, std::string filename) {
        Insertions inss;
        // only insert one dua siphon if single bug
        // if > 1 bug we are living dangerously. 
        if (bugs.size() == 1 && (returnCode & INSERTED_DUA_SIPHON)) return inss;
        returnCode |= INSERTED_DUA_SIPHON;
        std::string lval_name = llval.name;
        //        errs() << "ComposeDuaSiphoning\n";
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
        for ( auto &bug : injectable_bugs) {
            uint32_t i = 0;
            std::string gn = LavaGlobal(bug.id);
            siphon << "int " << gn << " = 0;\n";
            uint32_t o = 0;
            std::string lval_base;
            if (llval.is_ptr) 
                lval_base = llval.name;
            else 
                lval_base = "&(" + llval.name + ")";
            for ( auto ptr : bug.dua.lval_taint ) {
                // 0 means this offset of the lval is either untainted or not-viable for use by lava
                if (ptr != 0) {
                    siphon << LavaGlobal(bug.id) 
                           << " |= ((unsigned char *) " 
                           << lval_base << ")[" << o << "] << (" << i << "*8);";
                    i ++;
                }
                // we don't need more than 4 bytes of dua
                if (i == 4) break;
                o ++;
            }
            siphon << "lava_set(" << (std::to_string(bug.id)) << "," << gn << ");\n";
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

    /*
      Add code to call expr corresponding to use of dua that will trigger a bug here.
      Note that we may be injecting code that triggers more than one bug here. 
      NB: we dont actually know how to *change* code.
      so we instead just add another copy of the call with one
      of the arg perturbed by global.  :)
    */
    Insertions ComposeAtpDuaUse(CallExpr *call_expr, std::set<Bug> &injectable_bugs, std::string filename) {
        //        errs() << "in ComposeAtpDuaUse\n";
        Insertions inss;        
        // NB: only insert one dua use if single bug.  
        // if > 1 bug we live dangerously and may have multiple attack points
        if (bugs.size() == 1 && (returnCode & INSERTED_DUA_USE)) return inss;
        returnCode |= INSERTED_DUA_USE;
        std::string fn_name = call_expr->getDirectCallee()->getNameInfo().getName().getAsString();
        if (lava_get_proto.count(filename) == 0) {
            inss.top_of_file = "extern unsigned int lava_get(unsigned int) ;\n";
            lava_get_proto.insert(filename);
        }
        uint32_t num_args = call_expr->getNumArgs();
        std::vector<uint32_t> attackable_args;        
        uint32_t i=0;
        // collect inds of attackable args
        for ( auto it = call_expr->arg_begin(); it != call_expr->arg_end(); ++it) {            
            if (IsArgAttackable(dyn_cast<Expr>(*it))) 
                attackable_args.push_back(i);
            i ++;
        }                       
        std::stringstream new_call;
        new_call << fn_name << "(";
        i = 0;        
        uint32_t ii = 0;
        uint32_t j = 0;
        uint32_t num_injectable_bugs = injectable_bugs.size();
        uint32_t num_attackable_args = attackable_args.size();
        for ( auto it = call_expr->arg_begin(); it != call_expr->arg_end(); ++it) {
            errs() << "considering arg " << ii << "\n";
            Expr *arg = dyn_cast<Expr>(*it);
            // really, this cast can't fail, right?
            assert(arg); 
            std::stringstream new_arg;            
            std::string orig_arg = ExprStr(arg);
            bool arg_was_attacked = false;
            if (IsArgAttackable(arg)) {
                errs() << "is attackable\n";
                uint32_t j = 0;
                bool first_attack = true;
                Insertions arg_ins;
                for (auto &bug : injectable_bugs) {
                    errs() << "considering bug " << j << "\n";
                    if ((j % num_attackable_args) == i) {
                        errs() << "attacking arg " << ii << " with bug " << j << " -- bugid=" << bug.id << "\n";
                        std::string gn = "(lava_get(" + (std::to_string(bug.id)) + "))";
                        arg_was_attacked = true;
                        // this is the magic value that will trigger the bug
                        uint32_t magic_value = 0x6c617661;
                        //                        if (bugs.size() > 1) {
                            // with lots of bugs we need magic value to be distinct per bug
                            magic_value -=  bug.id;
                            //                        }
                            //                        else {
                            //                        }
                        std::string magic_value_s = hex_str(magic_value);
                        // byte-swapped version of magic value
                        uint32_t magic_value_bs = __bswap_32(magic_value);                                        
                        std::string magic_value_bs_s = hex_str(magic_value_bs);
                        // evaluates to 1 iff dua is the magic value
                        std::string magic_test = "(" + magic_value_s + "==" + gn + "||" + magic_value_bs_s + "==" + gn + ")";
                        if (fn_name.find("malloc") != std::string::npos) {
                            // nasty heuristic. for malloc, we want the lava switch 
                            // to undersize the malloc to a few bytes and hope for
                            // an overflow
                            // ... oh dear how do we compose multiple attacks on malloc? 
                            //                assert (first_attack);
                            if (first_attack) {
                                first_attack = false;
                                //                                new_arg << magic_test << " ? 1 : " << orig_arg;
                                arg_ins.before_part = magic_test + " ? 1 : "; 
                            }
                        }                                
                        else {
                            // for everything else we add lava_get() to the arg and hope to break things
                            // also we test if its equal to magic value 
                            // ... if arg is an lval we'll += instead
                            std::string plus_op = "+";
                            if (arg->isLValue()) plus_op = "+=";                        
                            /*
                            if (first_attack) {
                                first_attack = false;
                                new_arg << orig_arg; 
                            }
                            new_arg << plus_op << gn << "*" << magic_test;
                            */
                            arg_ins.after_part += plus_op + gn + "*" + magic_test;
                        }
                    }
                    j ++;
                }
                rewriter.InsertTextAfterToken(arg->getLocEnd(), arg_ins.after_part);


                i ++;
            }
            else {
                errs() << "is not attackable\n";
            }
            if (!arg_was_attacked) {
                // arg wasn't attacked -- it gets used in original form
                new_arg << (ExprStr(arg));
            }
            new_call << new_arg.str();
            if (ii < num_args-1) {
                new_call << ",";
            }
            ii ++;
        }
        new_call << ")";        
        //        SourceRange sr = SourceRange(call_expr->getLocStart(),call_expr->getLocEnd());
        //        rewriter.ReplaceText(sr, new_call.str());
        return inss;
    }        


    // is this lvalname / line / filename, etc a bug inj point?  
    // if so, return the vector of bugs that are injectable at this point
    std::set<Bug> AtBug(std::string lvalname, std::string filename, uint32_t line, bool atAttackPoint, 
                        uint32_t insertion_point, bool is_retval ) {
        //                errs() << "atbug : lvalname=" << lvalname << " filename=" << filename << " line=" << line << " atAttackPoint=" << atAttackPoint << " insertion_point=" << insertion_point<< " \n";
        std::set<Bug> injectable_bugs;
        for ( auto bug : bugs ) { 
            //                        errs() << bug.str() << "\n";
            bool atbug = false;
            if (atAttackPoint) {
                // this is where we'll use the dua.  only need to match the file and line
                assert (insertion_point == -1);
                atbug = (filename == bug.atp.filename && line == bug.atp.line + MainInstrCorrection);
            }
            else {
                // this is the dua siphon -- need to match most every part of dua
                // if dua is a retval, the one in the db wont match this one but verify prefix
                atbug = (filename == bug.dua.filename && line == (bug.dua.line + MainInstrCorrection)
                         && ((is_retval && (0 == strncmp(lvalname.c_str(), bug.dua.lvalname.c_str(), RV_PFX_LEN)))
                             || (lvalname == bug.dua.lvalname)) 
                         && insertion_point == bug.dua.insertionpoint);
            }
            if (atbug) {
                //                errs() << "found injectable bug @ line " << line << "\n";
                injectable_bugs.insert(bug);
            }
        }
        //                errs() << "Not at bug\n";
        /*
        if (injectable_bugs.size() > 1) {
            errs() << (injectable_bugs.size()) << " injectable bugs at this source loc\n";
            for (auto bug : injectable_bugs) {
                errs() << bug.str() << " \n";
            }
        }
        */
        return injectable_bugs;
    }
        
    /*
      returns new code called for @ dua: 
      lval taint queries OR siphoning lval off into bug global
      this is called once for every lval found @ source location.
      how to insert this string into source is determined by the caller.
      what is insertion_point?  
      If we are composing taint queries then they can go before or after
      a call site.  We need the taint query to differentiate and transmit that
      info up to hypervisor.  This is needed because bug insertion, later, 
      will need it.  
      insertion_point is just a number that (currently) can be 
      1 = query was before call
      2 = query was after call
    */
    Insertions ComposeDuaNewSrc(Llval &llval, std::string filename, 
                                uint32_t line, uint32_t insertion_point, bool is_retval) {
        Insertions inss;
        //        errs() << "ComposeDuaNewSrc\n";
        //        errs() << llval.name << " : " << line << " : " << filename << " : " << insertion_point << "\n";
        if (LavaAction == LavaQueries) {
            // yes, always pack this into after_part
            inss.after_part = ComposeDuaTaintQuery(llval, GetStringID(filename), 
                                                   line, insertion_point);
        }
        else if (LavaAction == LavaInjectBugs) {
            std::set<Bug> injectable_bugs = 
                AtBug(llval.name, filename, line, /*atAttackPoint=*/false,
                      insertion_point, is_retval);
            // NOTE: if injecting multiple bugs the same dua will need to be instrumented more than once        
            if (!injectable_bugs.empty()) {
                errs() << "ComposeDuaNewSrc: injecting a dua siphon for " << injectable_bugs.size() << " bugs " << filename << " : " << line << " : " << llval.name << "\n"; 
                inss = ComposeDuaSiphoning(llval, injectable_bugs, filename);
            }
        }
        else if (LavaAction == LavaInstrumentMain) {
            // do nothing
        }
        else {
            assert (1==0);
        }
        return inss;
    }
    
    /*     
      returns insertions called for @ attack point:
      attack query OR bug global use
      this is called once for the call expr that is @ the source location
    */
    Insertions ComposeAtpNewSrc( CallExpr *call_expr, std::string filename, uint32_t line) {
        Insertions inss;

        FunctionDecl *f = call_expr->getDirectCallee();
        std::string fn_name = f->getNameInfo().getName().getAsString();       


        //                errs() << "ComposeAtpNewSrc\n";
        if (LavaAction == LavaQueries) {            
            inss = ComposeAtpQuery(call_expr, filename, line);
        }
        else if (LavaAction == LavaInjectBugs) {
            std::set<Bug> injectable_bugs = 
                AtBug("", filename, line, /*atAttackPoint=*/true, 
                      /*insertion_point=*/-1, /*is_retval=*/false);
            // NOTE: if injecting multiple bugs the same atp may need to be instrumented more than once.
            if (!injectable_bugs.empty()) {
                errs() << "ComposeAtpNewSrc: injecting a dua use for " << injectable_bugs.size() << " bugs " << filename << " : " << line << " : " << fn_name << "\n"; 
                inss = ComposeAtpDuaUse(call_expr, injectable_bugs, filename);
            }
        }
        else if (LavaAction == LavaInstrumentMain) {
            // do nothing
        }
        else {
            assert (1==0);
        }
        return inss;
    }

    bool InFnBlackList(std::string fn_name) {
        return
            ((fn_name == "vm_lava_query_buffer")
             || (fn_name.find("va_start") != std::string::npos)
             || (fn_name == "va_arg")
             || (fn_name == "va_end")
             || (fn_name == "va_copy")
             || (fn_name.find("free") != std::string::npos));
    }

    bool VisitCallExpr(CallExpr *e) {
        //        errs() << "VisitCallExpr \n";
        SourceManager &sm = rewriter.getSourceMgr();
        FullSourceLoc fullLoc(e->getLocStart(), sm);
        std::string src_filename;
        if (LavaAction == LavaInjectBugs) {
            // we want to strip the build path so that 
            // we can actually compare bug in and query files for
            // same source which will be in different directories
            src_filename = StripPfx(FullPath(fullLoc), BuildPath);
        }
        else {
            src_filename = FullPath(fullLoc);
        }
        uint32_t src_line = fullLoc.getExpansionLineNumber(); 
        errs() << "VisitCallExpr " << src_filename << " " << src_line << "\n";
        // if we dont know the filename, that indicates unhappy situation.  bail.
        if (src_filename == "") return true;
        FunctionDecl *f = e->getDirectCallee();
        // this is also bad -- bail
        if (!f) return true;
        std::string fn_name = f->getNameInfo().getName().getAsString();       
        //        errs() << "VisitCallExpr " << src_filename << " " << fn_name << " " << src_line << "\n";
        /*
          if this is an attack point, we will either 
          * insert code to say "im at an attack point" 
          * insert code to use lava global modulo bugs list 
        */
        Insertions inssAtp;
        if (IsAttackPoint(e)) {
            inssAtp = ComposeAtpNewSrc(e, src_filename, src_line);
        }
        /*
          Regardless of whether or not this is an attack point there may be 
          duas in CallExpr. Could be buried in expression args. 
          Or could be the return value. 
          Either 
          * add taint query for each discovered lval
          * add code to siphon dua bytes into global. 
        */
        Insertions inssDua;                
        bool any_dua_insertions = false;
        // NB: there are some fns for which we will skip this step. 
        if (!(InFnBlackList(fn_name))) {
            // collect queriable / siphonable lvals for this fn.
            std::set<Llval> llvals;
            QualType rqt = e->getCallReturnType(); 
            bool has_retval = CallExprHasRetVal(rqt);
            std::string retvalname = RandVarName();            
            std::string rv_before;
            std::string rv_after;            
            Llval rv_llval;
            bool queriable_retval = false;
            if (has_retval) {
                //                errs() << "1 has retval\n";
                std::string pointer_tst = (rqt.getTypePtr()->isPointerType() ? retvalname : "");
                if (QueriableType(rqt.getTypePtr())) {
                    //                    errs() << "is queriable type\n";
                    std::pair<bool, Llval> res = ConstructLlval(retvalname, pointer_tst, rqt.getTypePtr());
                    queriable_retval = res.first;
                    if (queriable_retval) {
                        rv_llval = res.second;
                        //                        errs() << "1 rv_llval.length() = " << (rv_llval.name.length()) << "\n";
                        assert (rv_llval.name.length() > 0);
                        //                llvals.insert({retvalname, pointer_tst});
                    }
                }
                rv_before = (rqt.getAsString()) + " " + retvalname + " = ";
                rv_after = retvalname + ";";
            }
            int i = 0;
            for ( auto it = e->arg_begin(); it != e->arg_end(); ++it) {
                i ++;
                Stmt *stmt = dyn_cast<Stmt>(*it);
                if (stmt) {
                    Expr *arg = dyn_cast<Expr>(*it);
                    // can't fail, right? 
                    assert (arg);
                    // if this arg contains a decl, i.e., { int x; ... }, discard
                    bool cd = ContainsDecl(stmt);
                    if (! cd) {
                        // collect all lvals buried in expr (so, 'a' and 'b' for 'a+b')
                        std::set<Expr *> lvals;
                        CollectLvals(arg, lvals);
                        // Now collect lvals as llvals.
                        // And, for lvals that are structs, for all 1st-level fields.  
                        for ( auto lval : lvals ) {
                            std::string lv_name = "(" + ExprStr(lval) + ")";
                            std::string pointer_tst = (lval->getType().getTypePtr()->isPointerType() ? lv_name : "");
                            std::pair<bool, Llval> res = ConstructLlval(lv_name, pointer_tst, lval->getType().getTypePtr());
                            bool success = res.first;
                            if (success) {
                                Llval llval = res.second;
                                assert (lv_name.length() != 0);
                                llvals.insert(llval);
                                CollectLlvalsStruct(lval, llvals);
                            }
                        }
                    }
                }
            }
            // compose and collect dua code: either taint queries or dua siphoning
            std::stringstream dua_src_before;
            std::stringstream dua_src_after;            
            for ( auto llval : llvals ) {
                assert (llval.name.length() > 0);
                if (!(QueriableType(llval.typ))) {
                    continue;
                }
                Insertions inss_before;
                Insertions inss_after; 
                // for taint queries, we want to insert *both* before and after call, potentially
                // for dua siphoning, we want to insert *either* before or after.
                // based on the bug
                inss_before = ComposeDuaNewSrc(llval, src_filename, src_line,
                                               INSERTION_POINT_BEFORE_CALL, /*is_retval=*/ false);
                inss_after = ComposeDuaNewSrc(llval, src_filename, src_line,
                                              INSERTION_POINT_AFTER_CALL, /*is_retval=*/ false);
                inssDua.top_of_file += inss_before.top_of_file;
                inssDua.top_of_file += inss_after.top_of_file;
                // NB: yes, this is correct
                dua_src_before << inss_before.after_part;
                dua_src_after << inss_after.after_part;
            }
            any_dua_insertions = !((dua_src_before.str() == "") && (dua_src_after.str() == ""));
            // check the retval for insertions
            // for both query & dua siphon, only makes sense to insert *after* return value is set.
            Insertions rv_inss;
            if (has_retval && queriable_retval) { 
                rv_inss = ComposeDuaNewSrc(rv_llval, src_filename, src_line, 
                                           INSERTION_POINT_AFTER_CALL, /* is_retval=*/ true);            
            }
            // if injecting, should not have both an arg dua insertion and a retval insertion
            if (LavaAction == LavaInjectBugs) {
                /*
                if (any_dua_insertions) {
                    if (!EmptyInsertions(rv_inss)) {
                        errs() << "We have both dua insertions due to args and dua insertions due to rv?\n";
                        errs() << "due to args:\n";
                        errs() << "before: " << dua_src_before.str() << "\n";
                        errs() << "after: " << dua_src_after.str() << "\n";
                        errs() << "due to rv\n";
                        SpitInsertions(rv_inss);
                    }
                    assert (EmptyInsertions(rv_inss));
                }
                */
            }
            any_dua_insertions |= (!EmptyInsertions(rv_inss));
            if (any_dua_insertions) {
                // some kind of insertion to either query taint on arg or retval or siphon dua for arg or retval.
                // compose it but also do that retval stuff.
                // Note: rv_before is 'rvtype rvname ='
                inssDua.before_part = "({" + dua_src_before.str() + rv_before;
                // the original call will go here
                // Note:  rv_after is just 'rvname ;'
                inssDua.after_part = ";" + dua_src_after.str() + rv_inss.after_part + rv_after + "})";
                inssDua.top_of_file += rv_inss.top_of_file;
            }
        }
        //        errs() << "inssDua\n";
        //        SpitInsertions (inssDua);
        //        errs() << "inssAtp\n";
        //        SpitInsertions (inssAtp);
        

        Insertions inss = ComposeInsertions(inssDua, inssAtp);
        if (!EmptyInsertions(inss)) {
            //            printf ("non-empty insertions\n");
            //            SpitInsertions(inss);
            rewriter.InsertText(e->getLocStart(), inss.before_part, true, true);        
            rewriter.InsertTextAfterToken(e->getLocEnd(), inss.after_part);
            new_start_of_file_src << inss.top_of_file;    
        }
        return true;
        /*
        }
    
        catch (...) {
            errs() << "exception?\n";
        }

    */
    }

private:

    std::map<std::string,uint32_t> &StringIDs;
    std::vector< VarDecl* > &globalVars;
    Rewriter &rewriter;

};


class LavaTaintQueryASTConsumer : public ASTConsumer {
public:
    LavaTaintQueryASTConsumer(Rewriter &rewriter, std::map<std::string,uint32_t> &StringIDs) :
        visitor(rewriter, globalVars, StringIDs) {}

    bool HandleTopLevelDecl(DeclGroupRef DR) override {
    // iterates through decls
        for (DeclGroupRef::iterator b = DR.begin(), e = DR.end(); b != e; ++b) {
            // for debug
            //(*b)->dump();
            VarDecl *vd = dyn_cast<VarDecl>(*b);
            if (vd) {
                if (vd->isFileVarDecl() && vd->hasGlobalStorage())  {
                    globalVars.push_back(vd);
                }  
            }
            else
                visitor.TraverseDecl(*b);
        }
        return true;
    }

private:
    LavaTaintQueryASTVisitor visitor;
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
class LavaTaintQueryFrontendAction : public ASTFrontendAction {
public:
    std::string startoffile_ins;
    
    LavaTaintQueryFrontendAction() {}
    
    void EndSourceFileAction() override {
        SourceManager &sm = rewriter.getSourceMgr();
        errs() << "*** EndSourceFileAction for: "
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
            printf("Inserting stuff from %s:\n", lava_funcs_path.c_str());
            printf("%s", temp.str().c_str());
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
        bool ret = rewriter.overwriteChangedFiles();
        // save the strings db 
        if (LavaAction == LavaQueries)
            SaveDB(StringIDs, LavaDB);
    }

    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                     StringRef file) override {
        rewriter.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
        errs() << "** Creating AST consumer for: " << file << "\n";
        StringIDs = LoadDB(LavaDB);

        SourceManager &sm = rewriter.getSourceMgr();
        auto y = sm.getMainFileID();
        //        y.dump();
        auto x = sm.getLocForStartOfFile(y);
        x.dump(sm);


        return make_unique<LavaTaintQueryASTConsumer>(rewriter,StringIDs);
    }

private:
    std::map<std::string,uint32_t> StringIDs;
    Rewriter rewriter;
};


int main(int argc, const char **argv) {
    CommonOptionsParser op(argc, argv, LavaCategory);
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());

    LavaPath = std::string(dirname(dirname(dirname(realpath(argv[0], NULL)))));

    //    printf ("main instr correction = %s\n", (char *) SMainInstrCorrection.c_str());
    MainInstrCorrection = atoi(SMainInstrCorrection.c_str());

    printf ("main instr correction = %d\n", MainInstrCorrection);

    for (int i=0; i<argc; i++) {
        if (0 == strcmp(argv[i], "-p")) {
            BuildPath = std::string(argv[i+1]);
            errs() << "BuildPath = [" << BuildPath << "]\n";
        }
    }

    std::ifstream json_file(ProjectFile);
    Json::Value root;
    json_file >> root;

    if (LavaAction == LavaInjectBugs) {
        std::string dbhost(root["dbhost"].asString());
        std::string dbname(root["db"].asString());

        PGconn *conn = pg_connect(dbhost, dbname);
        // get bug info for the injections we are supposed to be doing.
        errs() << "LavaBugList: [" << LavaBugList << "]\n";

        std::set<uint32_t> bug_ids = parse_ints(LavaBugList);
        printf ("%d bug_ids\n", bug_ids.size());
        bugs = loadBugs(bug_ids, conn);        

        /*
        // determine if we have any file / src for which BOTH dua siphon and use will be injected on same line
        std::map<std::pair<std::string, uint32_t>, uint32_t> num_dua_siphon;
        std::map<std::pair<std::string, uint32_t>, uint32_t> num_dua_use;
        std::set<std::pair<std::string, uint32_t>> srcloc;
        for ( auto &bug : bugs ) {            
            Dua dua = bug.dua;
            AttackPoint atp = bug.atp;
            std::pair<std::string, uint32_t> dua_siphon_srcloc = std::make_pair(dua.filename, dua.line);
            std::pair<std::string, uint32_t> dua_use_srcloc = std::make_pair(atp.filename, atp.line);
            srcloc.insert(dua_siphon_srcloc);
            srcloc.insert(dua_use_srcloc);
            if (num_dua_siphon.count(dua_siphon_srcloc) == 0) 
                num_dua_siphon[dua_siphon_srcloc] = 1;
            else 
                num_dua_siphon[dua_siphon_srcloc] ++;
            if (num_dua_use.count(dua_use_srcloc) == 0) 
                num_dua_use[dua_use_srcloc] = 1;
            else 
                num_dua_use[dua_use_srcloc] ++;
        }

        for ( auto sl : srcloc ) {
            if (num_dua_siphon.count(sl) > 0 && num_dua_use.count(sl) > 0) {
                errs() << " BOTH dua siphon and use @ " << sl.first << " : " << sl.second << "\n";
            }
        }
        */

        ptr_to_set = loadTaintSets(conn);

        /*
        for ( auto bug : bugs ) {
            errs() << bug.str() << "\n";
        }
        */
    } 
    errs() << "about to call Tool.run \n";
    int r = Tool.run(newFrontendActionFactory<LavaTaintQueryFrontendAction>().get());
    errs() << "back from calling Tool.run \n";
    return (r | returnCode);

}
