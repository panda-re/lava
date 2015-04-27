#include "includes.h"
#include "lavaDB.h"

#define LAVA_DUA 0
#define LAVA_ATP 1
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

static cl::opt<std::string>
    LavaDB("lava-db",
    cl::desc("Path to LAVA file/AST/line database"),
    cl::cat(LavaCategory),
    cl::Required);
static cl::opt<std::string>
    LavaAction("action",
    cl::desc("LAVA action. \"query\" for taint query instrumentation, "
    "\"insert\" for bug insertion after dynamic data has been gathered."),
    cl::cat(LavaCategory),
    cl::Required);
/*  static cl::opt<std::string>
    LavaDynData("lava-dyn-data",
    cl::desc("Path to LAVA dynamic data (.duas, .bugs, .aps)"),
    cl::cat(LavaCategory)); */

static std::stringstream declInsert; 
static std::stringstream insert;

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

static int LavaInsertFlag;
static bool InsertLocFound = false;

class Dua {
std::string str() const {
    std::stringstream temp;
    temp << line << "," << lvalname << ",[";
    for ( auto l : duabytes) {
        temp << l << ",";
    }
    temp << "]";
    return temp.str();
}

public:
    Line line;
    std::string lvalname;
    std::set < Label > duabytes;
    int size;
    std::string globalname;
    
    Dua() {}
    Dua(std::string &input) {
        std::stringstream is(input);
        std::string temp;
        std::getline(is, temp, ',');
        line = std::stoul(temp);
        std::getline(is, lvalname, ',');
        assert(is.get() == '[');
        while (is.peek() != ']') {
            std::getline(is, temp, ',');
            duabytes.insert(std::stoul(temp));
        }
        std::getline(is, temp, ',');
        std::getline(is, globalname);
        size = duabytes.size();
    }

    std::string getDecl() const {
        std::stringstream temp;
        temp << "char " << globalname << " [" << size << "];"; 
    }

    std::string getMemcpy() const {
        std::stringstream temp;
        int offset = -1;
        int length = 0;
        int pos = 0;
        std::string targetptr = "&" + lvalname;
        for (auto l : duabytes) {
            if (length + offset < l) {
                if (length > 0) {
                    temp << "memcpy(" << globalname << "+" << pos << ", ";
                    temp << targetptr << "+" << offset << " , " << length;
                    temp << "); ";
                }
                offset = l; pos += length; length = 1;
            }
        }
    }

    bool operator<(Dua &other) const {
        return (str() < other.str());
    }
};

class AttackPoint {
    std::string str() const {
        std::stringstream temp;
        temp << type << "," << globalname << "," << type << "," << size; 
        return temp.str();
    }

public:
    Line line;
    std::string type;
    std::string globalname;;
    unsigned size;

    AttackPoint() {}

    AttackPoint(std::string &input) {
        std::stringstream is(input);
        std::string temp;
        std::getline(is, temp, ',');
        line = std::stoul(temp);
        std::getline(is, type, ',');
        std::getline(is, globalname, ',');
        std::getline(is, temp, ',');
        size=std::stoi(temp);
        std::getline(is, temp);
    }

    bool operator<(AttackPoint &other) const {
        return (str() < other.str());
    }

    std::string getDecl() const {
        std::stringstream temp;
        temp << "extern " << "char " << globalname << "[" << size << "];\n";
        return temp.str();
    }
};

static Dua dua;
static AttackPoint atp;

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

    bool VisitFunctionDecl(FunctionDecl *f) {
        if (f->hasBody()) {
            SourceManager &sm = rewriter.getSourceMgr();
            DeclarationName n = f->getNameInfo().getName();
            std::stringstream query;
            std::stringstream insert;
            FullSourceLoc fullLoc;
            
            query << "// Check if arguments of "
                << n.getAsString() << " are tainted\n";
            for (auto it = f->param_begin(); it != f->param_end(); ++it) {
                // Skip register variables
                if ((*it)->getStorageClass() == SC_Register) continue;

                fullLoc = (*it)->getASTContext().getFullLoc((*it)->getLocStart());
                if (LavaAction == "insert" && LavaInsertFlag == LAVA_DUA) {
                    if (fullLoc.getExpansionLineNumber() == dua.line && (*it)->getNameAsString() == dua.lvalname) {
                        InsertLocFound = true;
                    }
                } 
                query << "vm_lava_query_buffer(";
                query << "&(" << (*it)->getNameAsString() << "), ";
                query << "sizeof(" << (*it)->getNameAsString() << "), ";
                query << GetStringID(FullPath(fullLoc)) << ", ";
                query << GetStringID((*it)->getNameAsString()) << ", ";
                query << fullLoc.getExpansionLineNumber() << ");\n";
            
                const Type *t = (*it)->getType().getTypePtr();
                if (t->isPointerType() && !t->isNullPtrType()
                        && !t->getPointeeType()->isIncompleteType()) {
                    query << "if (" << (*it)->getNameAsString() << "){\n";
                    query << "    vm_lava_query_buffer(";
                    query << (*it)->getNameAsString() << ", ";
                    query << "sizeof(" << QualType::getAsString(
                        t->getPointeeType().split()) << "), ";
                    query << GetStringID(FullPath(fullLoc)) << ", ";
                    query << GetStringID((*it)->getNameAsString()) << ", ";
                    query << fullLoc.getExpansionLineNumber() << ");\n";
                    query << "}\n";
                }
            }

#if 0
            query << "// Check if global variables are tainted\n";
            for (auto it = globalVars.begin(); it != globalVars.end(); ++it) {
                populateLavaInfo(query,
                    (*it)->getASTContext().getFullLoc((*it)->getLocStart()),
                    (*it)->getNameAsString(), false);
                query << "vm_lava_query_buffer(";
                query << "&" << (*it)->getNameAsString() << ", ";
                query << "sizeof(" << (*it)->getNameAsString() << ")";
                query << ", 0";
                query << ", &pmli);\n";
                
                const Type *t = (*it)->getType().getTypePtr();
                if (t->isPointerType() && !t->isNullPtrType()
                        && !t->getPointeeType()->isIncompleteType()) {
                    query << "if (" << (*it)->getNameAsString() << "){\n";
                    populateLavaInfo(query,
                        (*it)->getASTContext().getFullLoc((*it)->getLocStart()),
                        (*it)->getNameAsString(), true);
                    query << "    vm_lava_query_buffer(";
                    query << (*it)->getNameAsString() << ", ";
                    query << "sizeof(" << QualType::getAsString(
                        t->getPointeeType().split()) << ")";
                    query << ", 0";
                    query << ", &pmli);\n";
                    query << "}\n";
                }
            }
#endif

            CompoundStmt *funcBody;
            if (!(funcBody = dyn_cast<CompoundStmt>(f->getBody())))
                    return true;

            Stmt **s = funcBody->body_begin();
            if (s) {
                SourceLocation loc = (*s)->getLocStart();
                if (LavaAction == "query")
                    rewriter.InsertText(loc, query.str(), true, true);
                else if (LavaAction == "insert" && InsertLocFound) {
                    rewriter.InsertText(loc, dua.getMemcpy() + "\n", true, true); 
                    InsertLocFound = false;
                } 
            }
        }
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
                    
                    if (LavaAction == "insert" && LavaInsertFlag == LAVA_DUA) {
                        if (src_linenum == dua.line && ast_node_name == dua.lvalname) {
                            InsertLocFound = true;     
                        }
                    } 
                }
            }
        }
        return queries.str();
    }

                          
    // Collect list of all lvals buried in an expr
    void CollectLvals(Expr *e, std::vector<Expr *> &lvals) {
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
                        lvals.push_back(e);
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

        if (LavaAction == "insert") {
            if (src_linenum == dua.line && lv_name == dua.lvalname) {
                InsertLocFound = true;
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

    std::string ComposeTaintQueriesExpr(Expr *e,  uint32_t src_filename, uint32_t src_linenum) {
        std::vector<Expr *> lvals;
        errs() << "src_filename=[" << src_filename << "] src_linenum=" << src_linenum << "\n";
        CollectLvals(e, lvals);
        std::stringstream queries;
        for ( auto *lv : lvals ) {
            queries << (ComposeTaintQueryLval(lv, src_filename, src_linenum));
        }        
        return queries.str();
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
    

    bool VisitCallExpr(CallExpr *e) {
        SourceManager &sm = rewriter.getSourceMgr();
        FullSourceLoc fullLoc(e->getLocStart(), sm);
        std::string src_filename = FullPath(fullLoc);
        // if we dont know the filename, that indicates unhappy situation.  bail.
        if (src_filename == "") 
            return true;
        uint32_t src_linenum = fullLoc.getExpansionLineNumber(); 
        std::stringstream before_part1, before_part2, after_part1, after_part2;
        bool any_insertion = false;
        /*
          insert "i'm at an attack point (memcpy)" hypercalls	
          we replace mempcy(...) with
          ({vm_lava_attack_point(...); memcpy(...);})       
        */
        {
            FunctionDecl *f = e->getDirectCallee();
            if (f) {
                std::string fn_name = f->getNameInfo().getName().getAsString();
                if (
                    (fn_name.find("memcpy") != std::string::npos) 
                    || (fn_name.find("malloc") != std::string::npos)
                    || (fn_name.find("memmove") != std::string::npos)
                    || (fn_name.find("bcopy") != std::string::npos)
                    || (fn_name.find("strcpy") != std::string::npos)
                    || (fn_name.find("strncpy") != std::string::npos)
                    || (fn_name.find("strcat") != std::string::npos)
                    || (fn_name.find("strncat") != std::string::npos)
                    || (fn_name.find("exec") != std::string::npos)
                    || (fn_name.find("popen") != std::string::npos))
                {
                    // If change memcpy
                    any_insertion = true;
                    errs() << "Found memcpy at " << src_filename << ":" << src_linenum << "\n";
                    before_part1 << "({";
                    QualType rqt = e->getCallReturnType();
                    bool has_retval = CallExprHasRetVal(rqt);
                    std::string retvalname = RandVarName();
                    before_part1 << "vm_lava_attack_point(" << GetStringID(src_filename) << ", ";
                    before_part1 << src_linenum << ", " << GetStringID(fn_name) << ");\n";
                    if (has_retval) {
                        before_part1 << (rqt.getAsString()) << " " << retvalname << " = ";
                        after_part1 << "; " << retvalname;
                    }
                    after_part1 << ";})";
                    if (LavaAction == "insert" && LavaInsertFlag == LAVA_ATP) {
                        if (src_linenum == atp.line && fn_name.find(atp.type) != std::string::npos) {
                            const Expr *first_arg = dyn_cast<Expr>(*(e->arg_begin()));
                            SourceLocation insertLoc = first_arg->getLocEnd();
                            std::stringstream temp;
                            temp << "(" << atp.globalname << "==" << RandTargetValue() << ")*";
                            temp << atp.globalname << " + ";
                            rewriter.InsertText(insertLoc, temp.str(), true, true);
                        }
                    }
                }	    
            }
        }

        /*
          insert taint queries *after* call for every arg to fn        
          For example, replace call
          int x = foo(a,b,...);
          with
          int x = ({ int ret = foo(a,b,...);  vm_lava_query_buffer(&a,...); vm_lava_query(&b,...); vm_lava_query(&ret,...);  ret })
        */          
        if (src_filename.size() > 0) 
        {
            uint32_t src_filename_id = GetStringID(src_filename);
            FunctionDecl *f = e->getDirectCallee();
            std::stringstream query;
            if (f) {
                std::string fn_name = f->getNameInfo().getName().getAsString();
                llvm::errs() << "query ins: fn_name is [" << fn_name << "]\n";
                const char *fnn = fn_name.c_str();
                if ( !
                     ((fn_name == "vm_lava_query_buffer")
                      || (fn_name.find("va_start") != std::string::npos)
                      || (fn_name == "va_arg")
                      || (fn_name == "va_end")
                      || (fn_name == "va_copy")
                      || (fn_name.find("free") != std::string::npos))
                    ) { 
                    llvm::errs() << "ok to ins \n";
                    any_insertion = true;
                    before_part2 << "({";
                    QualType rqt = e->getCallReturnType(); 
                    bool has_retval = CallExprHasRetVal(rqt);
                    std::string retvalname = RandVarName();
                    if (has_retval) {
                        llvm::errs() << "has return val" << "\n";
                        before_part2 << (rqt.getAsString()) << " " << retvalname << " = ";
                    }
                    std::stringstream queries;
                    queries << "; \n";
                    for ( auto it = e->arg_begin(); it != e->arg_end(); ++it) {
                        // for each expression, compose all taint queries we know how to create
                        Expr *arg = dyn_cast<Expr>(*it);
                        queries << (ComposeTaintQueriesExpr(arg, GetStringID(src_filename), src_linenum));
                    }            
                    after_part2 << queries.str();
                    if ( has_retval ) {
                        // make sure to compose a query for the ret val too
                        after_part2 << "vm_lava_query_buffer(&(" << retvalname << "), sizeof(" << retvalname << "), ";
                        after_part2 << GetStringID(src_filename) << "," << GetStringID(retvalname) << ", " << src_linenum << ");";
                        // make sure to return retval 
                        after_part2 << " " << retvalname << " ; ";
                        if (LavaAction == "insert" && LavaInsertFlag == LAVA_DUA) {
                            if (src_linenum == dua.line && retvalname == dua.lvalname) {
                                InsertLocFound = true;
                            }
                        }
                    }
                    after_part2 << "})";                    
                }
                else {
                    llvm::errs() << "not ok to ins\n";
                }
            }
        }

        if (LavaAction == "query" && any_insertion) {
            std::stringstream before_part, after_part;
            before_part << before_part2.str() << before_part1.str();
            after_part << after_part1.str() << after_part2.str();
            rewriter.InsertText(e->getLocStart(), before_part.str(), true, true);        
            rewriter.InsertTextAfterToken(e->getLocEnd(), after_part.str());
        }
        if (LavaAction == "insert" && InsertLocFound) {
            std::stringstream before_part, after_part;
            before_part << before_part2.str() << "; \n";
            after_part << dua.getMemcpy(); 
            QualType rqt = e->getCallReturnType();
            bool has_retval = CallExprHasRetVal(rqt);
            std::string retvalname = RandVarName(); 
            if ( has_retval ) {
                after_part2 << " " << retvalname << " ; ";
            }
            after_part << "})";                    
            rewriter.InsertText(e->getLocStart(), before_part.str(), true, true);        
            rewriter.InsertTextAfterToken(e->getLocEnd(), after_part.str());
            InsertLocFound = false;
        }
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
class LavaTaintQueryFrontendAction : public PluginASTAction {
public:
    LavaTaintQueryFrontendAction() {}
  
    void EndSourceFileAction() override {
        SourceManager &sm = rewriter.getSourceMgr();
        errs() << "** EndSourceFileAction for: "
                     << sm.getFileEntryForID(sm.getMainFileID())->getName()
                     << "\n";

        // Last thing: include the right file
        // Now using our separate LAVA version
        if (LavaAction == "query")
            rewriter.InsertText(sm.getLocForStartOfFile(sm.getMainFileID()),
            "#include \"pirate_mark_lava.h\"\n", true, true);
        else if (LavaAction == "insert") {
            std::string temp;
            if (LavaInsertFlag == LAVA_DUA)
                temp = dua.getDecl();
            else
                temp = atp.getDecl();
            rewriter.InsertText(sm.getLocForStartOfFile(sm.getMainFileID()), temp);
            std::cout << temp;
        }
        rewriter.overwriteChangedFiles();
        SaveDB(StringIDs, LavaDB);
    }

    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                     StringRef file) override {
        rewriter.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
        errs() << "** Creating AST consumer for: " << file << "\n";

        StringIDs = LoadDB(LavaDB);

        return make_unique<LavaTaintQueryASTConsumer>(rewriter,StringIDs);
    }

    /**************************************************************************/
    // Plugin-specific functions
    bool ParseArgs(const CompilerInstance &CI,
            const std::vector<std::string>& args) override {}
    
    void PrintHelp(llvm::raw_ostream& ros) {}

private:
    std::map<std::string,uint32_t> StringIDs;
    Rewriter rewriter;
};


int main(int argc, const char **argv) {
    CommonOptionsParser op(argc, argv, LavaCategory);
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());

    std::string input;
    if (LavaAction == "insert") {
        std::cin >> LavaInsertFlag;
        if (LavaInsertFlag == LAVA_DUA) {
            std::cin >> input;
            dua = Dua(input);             
        }
        else if (LavaInsertFlag == LAVA_ATP) {
            std::cin >> input;
            atp = AttackPoint(input);
        }
    } else if (LavaAction != "query") {
        errs() << "Invalid LAVA action specified. ";
        errs() << "Must be 'query' or 'insert'\n";
        exit(1);
    }

    return Tool.run(newFrontendActionFactory<LavaTaintQueryFrontendAction>().get());
}

