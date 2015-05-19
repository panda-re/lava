
extern "C" {
#include <stdlib.h>
}

#include "includes.h"
#include "lavaDB.h"

#include "../include/lava_bugs.h"


char resolved_path[512];

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
enum action { LavaQueries, LavaInjectBugs };
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
static cl::opt<std::string> LavaBugBuildDir("bug-build-dir",
    cl::desc("Path to build dir for bug-inj src" 
        "Used only in inject mode."),
    cl::cat(LavaCategory),
    cl::init("XXX"));


struct Llval {
    std::string name;        // name of constructed lval
    std::string pointer_tst;  // name of base ptr for null test
    
    bool operator<(const Llval &other) const {
        if (name < other.name) return true;
        if (name > other.name) return false;
        return (pointer_tst < other.pointer_tst);
    }      
};



struct Insertions {
    std::string top_of_file;  // stuff to insert at top of file
    std::string before_part;  // stuff to insert right before thing under inspection
    std::string after_part;   // stuff to insert right after the thing under inspection
};



static std::set<Bug> bugs;


std::stringstream new_start_of_file_src;

/*******************************************************************************
 * LavaTaintQuery
 ******************************************************************************/

class LavaTaintQueryASTVisitor :
    public RecursiveASTVisitor<LavaTaintQueryASTVisitor> {
public:
    LavaTaintQueryASTVisitor(Rewriter &rewriter,
        std::vector< VarDecl* > &globalVars, std::map<std::string,uint32_t> &StringIDs) :
            rewriter(rewriter), globalVars(globalVars), StringIDs(StringIDs)  {}

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
        if (!(llval.pointer_tst == "")) {
            query << "if (" << llval.pointer_tst << ")  {";
        }
        query << "vm_lava_query_buffer("
              << "&(" << llval.name << "), " 
              << "sizeof(" << llval.name << "), "
              << filename_id << ", "
              << GetStringID(llval.name) << ", "
              << line << ", "
              << insertion_point << ");\n";
        if (!(llval.pointer_tst == "")) {
            query << "}";
        }
        return query.str();
    }
        

    // Find lvals buried in e. new lvals get added to lvals set
    void CollectLvals(Expr *e, std::set<Expr *> &lvals) {
        Stmt *s = dyn_cast<Stmt>(e);
        if (s) {
            if (s->child_begin() == s->child_end()) {
                // e is a leaf node
                if (e->isLValue()) {
                    StringLiteral *sl = dyn_cast<StringLiteral>(e);
                    if (!sl) {
                        // ok its an lval that isnt a string literl
                        if (CanGetSizeOf(e)) {
                            // make sure its not a register
                            lvals.insert(e);
                        }
                    }
                }
            }
            else {
                // e has children -- recurse
                for ( auto &child : s->children() ) {             
                    Expr *ce = dyn_cast<Expr>(child)->IgnoreCasts();
                    CollectLvals(ce, lvals);
                }
            }
        }
    }

    /*
      lv_name is base for a struct.  Might be a pointer.
      Use rd to iterate over slots in that struct and collect llvals.  
      pointer indicates if lv_name is a pointer (and thus needs a null test)
    */
    void CollectLlvalsStruct1stLevel(std::string lv_name, RecordDecl *rd, bool pointer, std::set<Llval> &llvals) {
        for (auto field : rd->fields()) {
            if (!field->isBitField()) {
                if (! InFieldBlackList(field->getName().str())) {
                    std::string accessor =
                        (pointer ? (std::string("->")) : (std::string(".")));                    
                    std::string lval_ss = 
                        lv_name + accessor + field->getName().str();
                    std::string pointer_tst = (pointer ? lv_name : "");
                    llvals.insert( { lval_ss, pointer_tst } ); 
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
        const Type *t = e->getType().getTypePtr();
        if (d) {
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
        rvs << "kbcieiubweuhc";
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

    bool IsAttackPoint(FunctionDecl *fd) {
        std::string fn_name = fd->getNameInfo().getName().getAsString();
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

    void SpitInsertions(Insertions &inss) {
        errs() << "top_of_file=[" << inss.top_of_file << "]\n";
        errs() << "before_part=[" << inss.before_part << "]\n";
        errs() << "after_part=[" << inss.after_part << "]\n";
    }

    Insertions ComposeAtpQuery(CallExpr *ce, std::string filename, uint32_t line) {
        std::string fn_name =  ce->getDirectCallee()->getNameInfo().getName().getAsString();
        Insertions inss;
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
            // this is an attack point              
            std::stringstream before;
            std::stringstream after;
            errs() << "Found attack point at " << filename << ":" << line << "\n";
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
    Insertions ComposeDuaSiphoning(Bug &bug) {
        errs() << "ComposeDuaSiphoning\n";
        Insertions inss;
        std::stringstream ss;
        uint32_t i = 0;
        std::string gn = LavaGlobal(bug.id);
        ss << gn << " = 0;\n";
        for ( auto o : bug.dua.lval_offsets ) {
            // byte o in lval is dead
            ss << LavaGlobal(bug.id) 
               << " |= (((unsigned char *) &" 
               << bug.dua.lvalname << "))[" << o << "] << (" << i << "*8);";
            i ++;
            // only need 4 bytes
            if (i == 4) break;
        }
        inss.after_part = ss.str();
        inss.top_of_file = "int " + gn + ";\n";
        return inss;
    }

    /*
      Add code to call expr to use the global.
      NB: we dont actually know how to *change* code.
      so we instead just add another copy of the call with one
      of the arg perturbed by global.  :)
    */
    Insertions ComposeAtpGlobalUse(CallExpr *call_expr, Bug &bug) {
        Insertions inss;        
        if (bug.atp.filename != bug.dua.filename) {
            // only needed if dua is in different file from attack point
            inss.top_of_file = "extern int " + LavaGlobal(bug.id) + ";\n";
        }
        std::string fn_name = call_expr->getDirectCallee()->getNameInfo().getName().getAsString();
        uint32_t n = call_expr->getNumArgs();
        //        errs() << "n=" << n << "\n";
        // choose an arg at random to add global to.          
        std::default_random_engine generator;
        std::uniform_int_distribution<int> distribution(0,n-1);
        int arg_num = distribution(generator);  // generates number in the range 1..6 
        //        errs() <<  "adding global to arg " << arg_num << "\n";
        uint32_t i = 0;
        std::stringstream new_call;
        new_call << fn_name << "(";
        for ( auto it = call_expr->arg_begin(); it != call_expr->arg_end(); ++it) {
            //            errs() << "i=" << i << "\n";
            Expr *arg = dyn_cast<Expr>(*it);
            if (i == arg_num) {
                new_call << (ExprStr(arg)) + "+" +  LavaGlobal(bug.id);           
                if (i < n-1) {
                    new_call << ",";
                }
            }
            i++;
        }
        new_call << ")";
        SourceRange sr = SourceRange(call_expr->getLocStart(),call_expr->getLocEnd());
        rewriter.ReplaceText(sr, new_call.str());
        return inss;
    }        


    /*
      NOTE: this is a little borked.
      actually, there can be more than one Bug for a lvalname/filename/line.
      only in the dua when it is in a loop.  lval will be same but it will be tainted
      by different parts of the input
      returns Bug 
    */
    bool AtBug(std::string lvalname, std::string filename, uint32_t line, bool atAttackPoint, Bug *the_bug ) {
        errs() << "\nAtBug? filename=" << filename << " lval=" << lvalname 
               << " line=" << line << " atattackpoint=" << atAttackPoint << "\n";
        for ( auto bug : bugs ) {
            bool atbug = false;
            if (atAttackPoint) {
                errs() << bug.atp.filename << " " << bug.atp.line << "\n";
                if (filename == bug.atp.filename 
                    && line == bug.atp.line) {
                    errs() << "atAttackpoint -- filename and line match -- WE ARE THERE\n";
                    atbug = true;
                }
            }
            else {
                errs() << "M" << bug.dua.filename << " " << bug.dua.line << "\n";
                if (filename == bug.dua.filename
                    && line == bug.dua.line) {
                    errs() << "!atAttackpoint -- filename and line match\n";
                    if (lvalname == bug.dua.lvalname) {
                        errs() << "  lvals match too -- WE ARE THERE\n";
                        atbug = true;
                    }
                }
            }
            if (atbug) {
                *the_bug = bug;
                return true;
            }
        }
        return false;
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
    Insertions ComposeDuaNewSrc(Llval &llval, std::string filename, uint32_t line, uint32_t insertion_point) {
        Insertions inss;
        if (LavaAction == LavaQueries) {
            inss.after_part = ComposeDuaTaintQuery(llval, GetStringID(filename), line, insertion_point);
        }
        else if (LavaAction == LavaInjectBugs) {
            Bug bug;
            if (AtBug(llval.name, filename, line, /*atAttackPoint=*/false, &bug)) {
                errs() << "at bug in ComposeDuaNewSrc\n";
                inss = ComposeDuaSiphoning(bug);
            }
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
        if (LavaAction == LavaQueries) {            
            inss = ComposeAtpQuery(call_expr, filename, line);
        }
        else if (LavaAction == LavaInjectBugs) {
            Bug bug;
            if (AtBug("", filename, line, /*atAttackPoint=*/true, &bug)) {
                errs() << "at bug in ComposeAtpNewSrc\n";
                // NB: No insertion -- we insert things into the call 
                inss = ComposeAtpGlobalUse(call_expr, bug);
            }
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
        errs() << "VisitCallExpr\n";
        //        try {

        SourceManager &sm = rewriter.getSourceMgr();
        FullSourceLoc fullLoc(e->getLocStart(), sm);
        std::string src_filename = StripPfx(FullPath(fullLoc), LavaBugBuildDir);
        uint32_t src_line = fullLoc.getExpansionLineNumber(); 

        errs() << "VisitCallExpr\n";
        errs() << src_line << " \n";

        // if we dont know the filename, that indicates unhappy situation.  bail.
        if (src_filename == "") return true;
        FunctionDecl *f = e->getDirectCallee();
        // this is also bad -- bail
        if (!f) return true;
        std::string fn_name = f->getNameInfo().getName().getAsString();

        errs() << fn_name << "\n";

        /*
          if this is an attack point, we may want to insert code modulo bugs list.
          insert a query "im at an attack point" or add code to use
          lava global to manifest a bug here. 
          if its an attackpoint, figure out what code to insert
        */
        Insertions inssAtp;        
        if (IsAttackPoint(e->getDirectCallee())) {
            inssAtp = ComposeAtpNewSrc(e, src_filename, src_line);
        }
        /*
          Regardless of whether or not this is an attack point there may be 
          duas in CallExpr. Could be buried in expression args. 
          Or could be the return value. We might want to query any of these 
          lvals for taint or add code to siphon dua bytes into globals. 
        */
        Insertions inssDua;                
        // NB: there are some fns for which we will skip this step. 
        bool any_dua_insertions = false;
        if (!(InFnBlackList(fn_name))) {
            // collect lval names for this fn.
            // one for the retval (if there is one).
            // plus potentially many for each arg.
            // if arg is an expression than that could contain many lvals
            // further, if arg is a pointer to a struct we collect slot lvals 
            std::set<Llval> llvals;
            QualType rqt = e->getCallReturnType(); 
            bool has_retval = CallExprHasRetVal(rqt);
            std::string retvalname = RandVarName();            
            std::string rv_before;
            std::string rv_after;            
            Llval rv_llval;
            if (has_retval) {
                std::string pointer_tst = (rqt.getTypePtr()->isPointerType() ? retvalname : "");                
                rv_llval = {retvalname, pointer_tst};
                //                llvals.insert({retvalname, pointer_tst});
                rv_before = (rqt.getAsString()) + " " + retvalname + " = ";
                rv_after = retvalname + ";";
            }
            for ( auto it = e->arg_begin(); it != e->arg_end(); ++it) {
                Expr *arg = dyn_cast<Expr>(*it);
                // collect all lvals explicit in expr (so, 'a' and 'b' for 'a+b')
                std::set<Expr *> lvals;
                CollectLvals(arg, lvals);
                // now collect lvals as llvals
                // for lvals that are structs, for all 1st-level fields.  
                for ( auto lval : lvals ) {
                    std::string lv_name = "(" + ExprStr(lval) + ")";
                    std::string pointer_tst = (lval->getType().getTypePtr()->isPointerType() ? lv_name : "");
                    llvals.insert( {lv_name, pointer_tst} );
                    CollectLlvalsStruct(lval, llvals);
                }
            }
            // compose and collect dua code: either taint queries or dua siphoning
            std::stringstream dua_src_before;
            std::stringstream dua_src_after;            
            for ( auto llval : llvals ) {
                Insertions inss_before;
                Insertions inss_after; 
                if (LavaAction == LavaQueries) {
                    inss_before = ComposeDuaNewSrc(
                        llval, src_filename, src_line,
                        INSERTION_POINT_BEFORE_CALL);
                }
                inss_after = ComposeDuaNewSrc(
                    llval, src_filename, src_line,
                    INSERTION_POINT_AFTER_CALL);
                inssDua.top_of_file += inss_before.top_of_file;
                inssDua.top_of_file += inss_after.top_of_file;
                // NB: yes, this is correct
                dua_src_before << inss_before.after_part;
                dua_src_after << inss_after.after_part;
            }
            any_dua_insertions = !((dua_src_before.str() == "") && (dua_src_after.str() == ""));
            if (any_dua_insertions) {
                inssDua.before_part = "({" + dua_src_before.str() + rv_before;
                inssDua.after_part = ";" + dua_src_after.str();
                if (has_retval) {
                    Insertions inss = ComposeDuaNewSrc(rv_llval, src_filename, src_line, 
                        INSERTION_POINT_AFTER_CALL);
                    inssDua.top_of_file += inss.top_of_file ;
                    inssDua.after_part +=  inss.after_part ;
                }
                inssDua.after_part +=  rv_after + "})";
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
        errs() << "** EndSourceFileAction for: "
                     << sm.getFileEntryForID(sm.getMainFileID())->getName()
                     << "\n";
        // Last thing: include the right file
        // Now using our separate LAVA version
        if (LavaAction == LavaQueries) {
            new_start_of_file_src << "#include \"pirate_mark_lava.h\"\n";
        }
        rewriter.InsertText(sm.getLocForStartOfFile(sm.getMainFileID()),
                            new_start_of_file_src.str(),
                            true, true);
        errs() << "i am here\n";
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
        return make_unique<LavaTaintQueryASTConsumer>(rewriter,StringIDs);
    }

private:
    std::map<std::string,uint32_t> StringIDs;
    Rewriter rewriter;
};


int main(int argc, const char **argv) {
    CommonOptionsParser op(argc, argv, LavaCategory);
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());
    if (LavaAction == LavaInjectBugs) {
        // get bug info for the injections we are supposed to be doing.
        errs() << "LavaBugList: [" << LavaBugList << "]\n";

        std::set<uint32_t> bug_ids = parse_ints(LavaBugList);
        printf ("%d bug_ids\n", bug_ids.size());
        bugs = loadBugs(bug_ids);        
        for ( auto bug : bugs ) {
            errs() << bug.str() << "\n";
        }
    } 
    return Tool.run(newFrontendActionFactory<LavaTaintQueryFrontendAction>().get());
}

