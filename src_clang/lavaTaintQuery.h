
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;

static llvm::cl::OptionCategory
    TransformationCategory("Lava Taint Query Transformation");


class LavaTaintQueryASTVisitor :
    public RecursiveASTVisitor<LavaTaintQueryASTVisitor> {
public:
    LavaTaintQueryASTVisitor(Rewriter &rewriter,
        std::vector< VarDecl* > &globalVars) :
            rewriter(rewriter), globalVars(globalVars)  {}

    bool VisitFunctionDecl(FunctionDecl *f) {
        if (f->hasBody()) {
            SourceManager &sm = rewriter.getSourceMgr();
            DeclarationName n = f->getNameInfo().getName();
            std::stringstream query;
            FullSourceLoc fullLoc;
            query << "// Check if arguments of "
                << n.getAsString() << " are tainted\n";
            for (auto it = f->param_begin(); it != f->param_end(); ++it) {
                fullLoc = (*it)->getASTContext().getFullLoc((*it)->getLocStart());
                query << "vm_lava_query_buffer(";
                query << "&(" << (*it)->getNameAsString() << "), ";
                query << "sizeof(" << (*it)->getNameAsString() << "), ";
                query << "\"" << sm.getFilename(fullLoc).str() << "\"" << ", ";
                query << "\"" << (*it)->getNameAsString() << "\"" << ", ";
                query << fullLoc.getExpansionLineNumber() << ");\n";
            
                const Type *t = (*it)->getType().getTypePtr();
                if (t->isPointerType() && !t->isNullPtrType()
                        && !t->getPointeeType()->isIncompleteType()) {
                    query << "if (" << (*it)->getNameAsString() << "){\n";
                    query << "    vm_lava_query_buffer(";
                    query << (*it)->getNameAsString() << ", ";
                    query << "sizeof(" << QualType::getAsString(
                        t->getPointeeType().split()) << "), ";
                    query << "\"" << sm.getFilename(fullLoc).str() << "\""
                            << ", ";
                    query << "\"" << (*it)->getNameAsString() << "\"" << ", ";
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
                rewriter.InsertText(loc, query.str(), true, true);
            }
        }
        return true;
    }

    bool VisitCallExpr(CallExpr *e) {
        SourceManager &sm = rewriter.getSourceMgr();
        FunctionDecl *f = e->getDirectCallee();
        std::stringstream query;
        if (f) {
            if (f->getNameInfo().getName().getAsString() == "memcpy") {
                FullSourceLoc fullLoc(e->getLocStart(), sm);
                llvm::errs() << "Found memcpy at " << sm.getFilename(fullLoc).str() << ":" << fullLoc.getExpansionLineNumber() << "\n";
                query << "vm_lava_attack_point(";
                query << "\"" << sm.getFilename(fullLoc).str() << "\", " << fullLoc.getExpansionLineNumber();
                query << ");\n";
                rewriter.InsertText(e->getLocStart(), query.str(), true, true);
            }
        }
        return true;
    }

#if 0
    // x = 17 is a BinaryOperator with name '='
    virtual bool VisitBinaryOperator(BinaryOperator *bo) {
        llvm::errs() << "In a binary op\n";
        switch (bo->getOpcode()) {
        case BO_Assign:
        case BO_MulAssign:
        case BO_DivAssign:
        case BO_RemAssign:
        case BO_AddAssign:
        case BO_SubAssign:
        case BO_ShlAssign:
        case BO_ShrAssign:
        case BO_AndAssign:
        case BO_XorAssign:
        case BO_OrAssign: {
            llvm::errs() << "At the thing\n";
            if (DeclRefExpr *lhs = dyn_cast<DeclRefExpr>(bo->getLHS())) {
                auto lhs_name =  lhs->getDecl()->getName().str() ;
                llvm::errs() << " bo assignment lhs = " << lhs->getDecl()->getName() << "\n";
                std::stringstream query;
                query << "query_taint(&" << lhs_name << ", sizeof(" << lhs_name << ");\n";
                SourceLocation ST = bo->getLocStart();

                rewriter.InsertText(ST, query.str(), true, true);

                
                llvm::errs() << query.str() << "\n";
            }
            break;
        }
        default:
            break;
        }
        return true;
    }
#endif

private:
    std::vector< VarDecl* > &globalVars;
    Rewriter &rewriter;

    void populateLavaInfo(std::stringstream &ss, FullSourceLoc loc,
            StringRef nodeStr, bool indent){
        SourceManager &sm = rewriter.getSourceMgr();
        if (indent) ss << "    ";
        ss << "pmli.filenamePtr = \"" << sm.getFilename(loc).str() << "\";\n";
        if (indent) ss << "    ";
        ss << "pmli.lineNum = " << loc.getExpansionLineNumber() << ";\n";
        if (indent) ss << "    ";
        ss << "pmli.astNodePtr = \"" << nodeStr.str() << "\";\n";
    }

};


class LavaTaintQueryASTConsumer : public ASTConsumer {
public:
    LavaTaintQueryASTConsumer(Rewriter &rewriter) :
        visitor(rewriter, globalVars) {}

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
        llvm::errs() << "** EndSourceFileAction for: "
                     << sm.getFileEntryForID(sm.getMainFileID())->getName()
                     << "\n";

        // Last thing: include the right file
        // Now using our separate LAVA version
        rewriter.InsertText(sm.getLocForStartOfFile(sm.getMainFileID()),
            "#include \"pirate_mark_lava.h\"\n", true, true);
        rewriter.overwriteChangedFiles();
    }

    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                     StringRef file) {
        rewriter.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
        llvm::errs() << "** Creating AST consumer for: " << file << "\n";
        return llvm::make_unique<LavaTaintQueryASTConsumer>(rewriter);
    }

    /**************************************************************************/
    // Plugin-specific functions
    bool ParseArgs(const CompilerInstance &CI,
            const std::vector<std::string>& args) {
        // No args currently
        return true;
    }
    
    void PrintHelp(llvm::raw_ostream& ros) {
        ros << "Help for taint-query plugin goes here\n";
    }

private:
    Rewriter rewriter;
};

