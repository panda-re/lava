#include "includes.h"
#include "lavaDB.h"

#include "../include/lava_bugs.h"

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
enum action { QueryAction, InsertAction };
static cl::opt<action> LavaAction("action", cl::desc("LAVA Action"),
    cl::values(
        clEnumValN(Queries, "query", "Add taint queries"),
        clEnumValN(InjectBugs, "inject", "Inject bugs"),
        clEnumValEnd),
    cl::cat(LavaCategory),
    cl::Required);
static cl::opt<std::string> LavaBugList("bug-list",
    cl::desc("Comma-separated list of bug ids (from the postgres db) to inject into this file"),
    cl::cat(LavaCategory),
    cl::init("."));
static cl::opt<std::string> LavaDB("lava-db",
    cl::desc("Path to LAVA database (custom binary file for source info).  "
        "Created in query mode."),
    cl::cat(LavaCategory),
    cl::init("."));


struct Insertions {
    std::string top_of_file;  // stuff to insert at top of file
    std::string before_part;  // stuff to insert right before thing under inspection
    std::string after_part;   // stuff to insert right after the thing under inspection
};
   

std::set<std::string> blacklikstFnNames ;
blacklistFnNames.insert ("vm_lava");
blacklistFnNames.insert ("va_start");
blacklistFnNames.insert ("va_end");
blacklistFnNames.insert ("va_copy");
blacklistFnNames.insert ("va_free");


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

    // give me a decl for a struct and I'll compose a string with
    // all relevant taint queries
    // XXX: not handling more than 1st level here
    std::string ComposeTaintQueriesRecordDecl(std::string lv_name, RecordDecl *rd, std::string accessor, uint32_t src_filename, uint32_t src_linenum) {
        std::stringstream queries;
        for (auto field : rd->fields()) {
            if (!field->isBitField()) {
                // XXX Fixme!  this is crazy
                if ( (!( field->getName().str() == "__st_ino" ))
                     && (field->getName().str().size() > 0)
                    ) {
                    std::string ast_node_name = lv_name + accessor + field->getName().str();
                    uint32_t ast_node_id = GetStringID(ast_node_name);
                    queries << "vm_lava_query_buffer(";
                    queries << "&(" << ast_node_name << "), " ;
                    queries << "sizeof(" << ast_node_name << "), ";
                    queries << src_filename << ", ";
                    queries << ast_node_id << ", ";
                    queries << src_linenum << ");\n";
                    if (LavaAction == InsertAction) {
                        std::cout << "Checking for DUAs2!!\n";
                        for (auto bugIt = bugs.begin(); bugIt != bugs.end(); bugIt++){
                            if (src_linenum == (*bugIt).dua.line
                                    && ast_node_name == (*bugIt).dua.lvalname) {
                                InsertLocFound = true;
                                dua = (*bugIt).dua; // XXX STOP USING GLOBALS!
                                std::cout << "Found a DUA2!!\n";
                            }
                        }
                    } 
                }
            }
        }
        return queries.str();
    }
                          
    // Collect list of all lvals buried in an expr
    void CollectLvals(Expr *e, std::set<Expr *> &lvals) {
        Stmt *s = dyn_cast<Stmt>(e);
        if (s) {
            if (s->child_begin() == s->child_end()) {
                // e is a leaf node
                if (e->isLValue()) {
                    errs() <<  ("in CollectLvals\n");
                    e->dump();
                    StringLiteral *sl = dyn_cast<StringLiteral>(e);
                    if (!sl) {
                        errs() <<  "i'm not a string literal\n";
                        // ok its an lval that isnt a string literl
                        lvals.insert(e);
                    }
                    else {
                        errs() << "i'm a string literal\n";
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

    // e must be an lval.
    // return taint query for that lval
    std::string ComposeTaintQueryLval (Expr *e, uint32_t src_filename, uint32_t src_linenum) {
        assert (e->isLValue());
        errs() << "+++ LVAL +++\n";
        e->dump();
        DeclRefExpr *d = dyn_cast<DeclRefExpr>(e);
        if (d) errs() << "Could successfully cast\n";
        else errs() << "Could NOT successfully cast\n";
        errs() << "Can we get the size of this? " << (CanGetSizeOf(e) ? "YES" : "NO") << "\n";
        errs() << "--- LVAL ---\n";
        // Bail out early if we can't take the size of this thing
        if (!CanGetSizeOf(e)) return "";
        std::stringstream query;
        std::string lv_name = "(" + ExprStr(e) + ")";
        query << "vm_lava_query_buffer(";
        query << "&(" << lv_name << "), ";
        query << "sizeof(" << lv_name << "), ";
        query << src_filename << ", ";
        query << GetStringID(lv_name) << ", ";
        query << src_linenum  << ");\n";
        if (LavaAction == InsertAction) {
            std::cout << "Checking for DUAs3!!\n";
            for (auto bugIt = bugs.begin(); bugIt != bugs.end(); bugIt++){
                if (src_linenum == (*bugIt).dua.line
                        && lv_name == (*bugIt).dua.lvalname) {
                    InsertLocFound = true;
                    dua = (*bugIt).dua; // XXX STOP USING GLOBALS!
                    std::cout << "Found a DUA3!!\n";
                }
            }
        }
        // if lval is a struct or a ptr to a struct,
        // we want queries for all slots
        QualType qt = e->getType();
        const Type *t = qt.getTypePtr();
        if (t->isPointerType()) {
            if (t->getPointeeType()->isRecordType()) {
                // we have a ptr to a struct 
                const RecordType *rt = t->getPointeeType()->getAsStructureType();
                if (rt) {
                    query << "if (" << lv_name << ") {\n" ;
                    query << (ComposeTaintQueriesRecordDecl(lv_name, rt->getDecl(), std::string("->"), src_filename, src_linenum));
                    query << "}\n"; 
               }
            }
        }
        else {
            if (t->isRecordType()) {
                // we have a struct
                const RecordType *rt = t->getAsStructureType();
                if (rt) {
                    query << (ComposeTaintQueriesRecordDecl(lv_name, rt->getDecl(), std::string("."), src_filename, src_linenum));
                }
            }
        }
        return query.str();
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

    boolean IsAttackPoint(Expr &e) {
        CallExpr &ce;
        if (!(ce = dyn_cast<CallExpr>(e))) {
            return false;
        }
        std::string fn_name =  ce.getDirectCallee()->getNameInfo().getName().getAsString();
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
        inss.top_of_file = inss_outer.top_of_file + inss._inner.top_of_file;
        inss.before_part = inss_outer.before_part + inss_inner.before_part;
        inss.after_part = inss_inner.after_part + inss_outer.after_part;
        return inss;
    }
    
    Insertions ComposeAtpQuery(CallExpr e, std::string filename, uint32_t linenum) {
        std::string fn_name =  e->getDirectCallee()->getNameInfo().getName().getAsString();
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
            std::stringstring before;
            std::stringstring after;
            errs() << "Found attack point at " << filename << ":" << linenum << "\n";
            before << "({";
            QualType rqt = e->getCallReturnType();
            bool has_retval = CallExprHasRetVal(rqt);
            std::string retvalname = RandVarName();
            before << "vm_lava_attack_point(" << GetStringID(filename) << ", ";
            before << linenum << ", " << GetStringID(fn_name) << ");\n";
            if (has_retval) {
                before << (rqt.getAsString()) << " " << retvalname << " = ";
                after << "; " << retvalname;
            }
            after << ";})";
            inss.before_part = before;
            inss.after_part = after;
        }
        return inss;
    }
        
    // compose a lava global for this bug id
    std::string LavaGlobal(uint32_t id) {
        std::stringstream ss;
        ss << "lava_" << id;
        ss.str();
    }

    /* create code that siphons dua bytes into a global

       this is how, given a byte in a dua we'll grab it and insert into a global
       o = 3; // byte # in dua (0 is lsb)
       i = 0; // byte # in global
       lava_1 |=  (((unsigned char *) &dua))[o] << (i*8) ;
    */
    Insertion ComposeDuaSiphoning(Bug &bug) {
        std::stringstream ss;
        uint32_t i = 0;
        std::string gn = LavaGlobal(bug.id);
        ss << gn << " = 0;\n";
        for ( auto o : bug.dua.lval_offsets ) {
            // byte o in lval is dead
            ss << LavaGlobal(bug.id) << " |= (((unsigned char *) &" << bug.dua.lvalname << "))[" << o << "] << (" << i << "*8);";
            i ++;
            // only need 4 bytes
            if (i == 4) break;
        }
        Insertion inss;
        inss.after_part = ss.str();
        return inss;
    }

    // Add code to call expr to use the global.
    // NB: we dont actually know how to *change* code.
    // so we instead just add another copy of the call with one
    // of the arg perturbed by global.  :)
    Insertion ComposeAtpGlobalUse(CallExpr *call_expr, Bug &bug) {
        Insertion inss;
        std::string fn_name = call_expr->getDirectCallee()->getNameInfo().getName().getAsString();
        inss.after_part = fn_name = "(";
        uint32_t n = call_expr->getNumArgs();
        uint32_t i = 0;
        for ( auto it = call_expr->arg_begin(); it != call_expr->arg_end(); ++it) {
            i++;
            Expr *arg = dyn_cast<Expr>(*it);
            inss.after_part += ExprStr(arg) + " + " + LavaGlobal(bug.id);
            if (i < n) inss.after_part += ",";
        }
        return inss;
    }        

    /*
      NOTE: this is a little borked.
      actually, there can be more than one Bug for a lvalname/filename/linenum.
      only in the dua when it is in a loop.  lval will be same but it will be tainted
      by different parts of the input
      returns Bug 
    */
    Bug *AtBug(std::string lvalname, std::string filename, uint32_t linenum, boolean atAttackPoint ) {
        for ( auto bug : bugs ) {
            if (filename == bug.dua.filename
                && linenum == bug.dua.line) {
                if (atAttackPoint || 
                    (lvalname == bug.dua.lvalname)) {
                    // XXX just returning first!  What if there's multiple?
                    return &bug;
                }
            }
        }
        return NULL;
    }
        
    /*
      returns insertion called for @ dua: 
      lval taint queries OR siphoning lval off into bug global
      this is called once for every lval found @ source location
     */
    Insertions ComposeDuaNewSrc( std::string lval_name, Expr *lval_expr, std::string filename, uint32_t linenum ) {
        Insertsions inss;
        if (LavaAction == Queries) {
            inss = ComposeDuaQuery(lval_name, lval_expr, filename, linenum);
        }
        else if (LavaAction == InjectBugs) {
            Bug *bug = AtBug(lval_name, filename, linenum, /* atAttackPoint = */ false);
            if (bug) {
                inss = ComposeDuaSiphoning(*bug);
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
    Insertions ComposeAtpNewSrc( Expr *call_expr, std::string filename, uint32_t linenum) {
        Insertions inss;
        if (LavaAction == Queries) {            
            inss = ComposeAtpQuery(call_expr, filename, linenum);
        }
        else if (LavaAction == InjectBugs) {
            Bug *bug = AtBug(lval_name, filename, linenum, /* atAttackPoint = */ false);
            if (bug) {
                inss = ComposeAtpGlobalUse(call_expr, *bug);
            }
        }
        else {
            assert (1==0);
        }
        return inss;
    }

    boolean InBlackListFns(std::string fn_name) {
        return
            ((fn_name == "vm_lava_query_buffer")
             || (fn_name.find("va_start") != std::string::npos)
             || (fn_name == "va_arg")
             || (fn_name == "va_end")
             || (fn_name == "va_copy")
             || (fn_name.find("free") != std::string::npos));
    }

    bool VisitCallExpr(CallExpr *e) {
        SourceManager &sm = rewriter.getSourceMgr();
        FullSourceLoc fullLoc(e->getLocStart(), sm);
        std::string src_filename = FullPath(fullLoc);
        uint32_t src_linenum = fullLoc.getExpansionLineNumber(); 
        // if we dont know the filename, that indicates unhappy situation.  bail.
        if (src_filename == "") return true;
        FunctionDecl *f = e->getDirectCallee();
        // this is also bad -- bail
        if (!f) return true;
        std::string fn_name = f->getNameInfo().getName().getAsString();
        /*
          if this is an attack point, we may want to insert code modulo bugs list.
          insert a query "im at an attack point" or add code to use
          lava global to manifest a bug here. 
          if its an attackpoint, figure out what code to insert
        */
        Insertions inssAtp;        
        if (IsAttackPoint(*e)) {
            inssAtp = ComposeAtpNewSrc(e, src_filename, src_linenum);
        }
        /*
          Regardless of whether or not this is an attack point there may be 
          duas in CallExpr. Could be buried in expression args. 
          Or could be the return value. We might want to query any of these 
          lvals for taint or add code to siphon dua bytes into globals. 
        */
        Insertions inssDua;                
        // NB: there are some fns for which we will skip this step. 
        if (!(inBlacklistFnNames(fn_name))) {
            // collect set of lvals in args plus retval
            std::set<std::pair<std::string, Expr *>> lvals;
            QualType rqt = e->getCallReturnType(); 
            bool has_retval = CallExprHasRetVal(rqt);
            std::string retvalname = RandVarName();            
            if (has_retval) {
                lvals.insert(std::make_pair(retvalname, NULL));
                inssDua.before_part = " ( { " + (rqt.getAsString()) + " " + retvalname + " = ";
            }
            for ( auto it = e->arg_begin(); it != e->arg_end(); ++it) {
                Expr *arg = dyn_cast<Expr>(*it);
                std::set<Expr *> lval_exprs;
                CollectLvals(arg, lvals_exprs);            
                for ( auto lval : lvals_exprs ) {                    
                    lvals.insert(std::make_pair(ExprStr(lval), lval));
                }
            }
            // compose and collect dua code: either taint queries or dua siphoning
            for ( auto p : lvals ) {
                std::string lval_name = p.first;
                Expr *lval_expr = p.second;
                Insertions inss = ComposeDuaNewSrc(lval_name, lval_expr, src_filename, src_linenum);
                inssDua = ComposeInsertions(inssDua, inss);
            }
            if (has_retval) {
                inssDua.after_part += " " + retvalname + " ; } )";
            }
        }
        Insertions inss = ComposeInsertions(inssDua, inssAtp)
        rewriter.InsertText(e->getLocStart(), inss.before_part, true, true);        
        rewriter.InsertTextAfterToken(e->getLocEnd(), inss.after_part);
        top_of_file += inss.top_of_file;    
        return true;
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
        if (LavaAction == QueryAction) {
            new_start_of_file_src << "#include \"pirate_mark_lava.h\"\n";
        }

        rewriter.InsertText(sm.getLocForStartOfFile(sm.getMainFileID()),
                            new_start_of_file_src.str(),
                            true, true);
        }
        /*
        else if (LavaAction == InsertAction) {
            std::string temp;
            /*if (LavaInsertMode == DuaMode)
                temp = dua.getDecl();
            else
                temp = atp.getDecl();
            */
            // XXX need to determine if declarations need to be externed or not
            temp = dua.getDecl();
            rewriter.InsertText(sm.getLocForStartOfFile(sm.getMainFileID()), temp + "\n");
        }
        */
        rewriter.overwriteChangedFiles();

        // save the strings db 
        if (LavaAction == QueryAction)
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


// XXX put me in a class
std::vector<Bug> loadBugs(std::string lavaBugInfoPath){
    std::vector<Dua> duas = std::vector<Dua>();
    std::vector<AttackPoint> atps = std::vector<AttackPoint>();
    std::vector<Bug> inputBugs = std::vector<Bug>();
    std::ifstream duaFile(lavaBugInfoPath + "/lava.duas");
    std::ifstream atpFile(lavaBugInfoPath + "/lava.aps");
    std::ifstream bugsFile(lavaBugInfoPath + "/lava.bugs");
    std::string line;
    while (std::getline(duaFile, line)){
        duas.push_back(Dua(line));
    }
    while (std::getline(atpFile, line)){
        atps.push_back(AttackPoint(line));
    }
    while (std::getline(bugsFile, line)){
        // .bugs file is formatted with a pair of numbers where the first
        // corresponds to the line number in the .duas file, and the second
        // corresponds to the line number in the .aps file
        std::stringstream bugData(line);
        //Dua dua;
        //AttackPoint ap;
        std::string temp;
        int duaIndex;
        int atpIndex;
        Bug bug;
        std::getline(bugData, temp, ',');
        duaIndex = std::stol(temp);
        std::getline(bugData, temp, ',');
        atpIndex = std::stol(temp);
        bug.dua = duas[duaIndex];
        bug.attackPoint = atps[atpIndex];
        inputBugs.push_back(bug);
    }
    duaFile.close();
    atpFile.close();
    bugsFile.close();
    std::cout << "Done parsing atps and duas\n";
    return inputBugs;
}

int main(int argc, const char **argv) {
    CommonOptionsParser op(argc, argv, LavaCategory);
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());
    if (LavaAction == InsertAction) {
        // get bug info for the injections we are supposed to be doing.
        bugs = loadBugs(LavaBugList);        
    } 
    return Tool.run(newFrontendActionFactory<LavaTaintQueryFrontendAction>().get());
}

