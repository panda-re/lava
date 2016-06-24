#include "includes.h"


/*
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
*/

using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;
using namespace llvm;

/*
static cl::OptionCategory
  LavaAttackpointsCategory("LAVA Attack Point Tool Options");
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp(
    "\nTODO: Add descriptive help message.  "
    "Automatic clang stuff is ok for now.\n\n");
*/

static cl::OptionCategory MyToolCategory("My tool options");
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp("\nMore help text...");
static cl::opt<bool> YourOwnOption(...);

enum LavaAttackType {
    LavaAttackReadPtr,
    LavaAttackWritePtr,
    LavaAttackReadArrayIndex,
    LavaAttackWriteArrayIndex
}; 



const std::string lavaAttackTypeString[] = {"ReadPtr", "WritePtr", "ReadArrayIndex", "WriteArrayIndex"};



class FindAttackPointsVisitor
    : public RecursiveASTVisitor<FindAttackPointsVisitor> {
public:
    explicit FindAttackPointsVisitor(ASTContext *Context)
    : Context(Context) {}
    
    // give me an expr and i'll return the string repr from original source
    std::string ExprStr(Expr *e) {
        const clang::LangOptions &LangOpts = Context->getLangOpts();
        clang::PrintingPolicy Policy(LangOpts);
        std::string TypeS;
        raw_string_ostream s(TypeS);
        e->printPretty(s, 0, Policy);
        return s.str();
    }

    void Attack(LavaAttackType lat, Expr *e) {
        errs() << "\nAttack type = " << lat << ":" << lavaAttackTypeString[lat] << "\n";
        //        e->dump();
        SourceManager &sm = Context->getSourceManager();
        FullSourceLoc deref_start(e->getLocStart(), sm);
        FullSourceLoc deref_end(e->getLocStart(), sm);
        std::string filename = sm.getFilename(deref_start).str();
        uint32_t deref_start_line = deref_start.getExpansionLineNumber();
        uint32_t deref_end_line = deref_end.getExpansionLineNumber();
        errs() << filename << ":" << deref_start_line << ".." << deref_end_line << ":" << (ExprStr(e)) << "\n";
    }


    void bounds(Expr *e) {
        SourceManager &sm = Context->getSourceManager();
        FullSourceLoc deref_start(e->getLocStart(), sm);
        FullSourceLoc deref_end(e->getLocStart(), sm);
        std::string filename = sm.getFilename(deref_start).str();
        uint32_t deref_start_line = deref_start.getExpansionLineNumber();
        uint32_t deref_end_line = deref_end.getExpansionLineNumber();
        errs() << filename << ":" << deref_start_line << ".." << deref_end_line << ":" << (ExprStr(e)) << "\n";
    }

    bool VisitExpr(Expr *expr) {
        //        errs() << "------------------\nVisitExpr \n";
        //        expr->dump();
        //        bounds(expr);

        if (expr->isRValue()) {
            // NB: an assignment *is* an rval because C is insane
            if (isa<BinaryOperator>(expr)) {
                BinaryOperator *bexpr = dyn_cast<BinaryOperator>(expr);
                if (bexpr->isAssignmentOp()) { 
                    //     errs() << "an assignment\n";
                    // binary assignment operator 
                    Expr *lhs = bexpr->getLHS()->IgnoreImpCasts()->IgnoreCasts();
                    if (isa<UnaryOperator>(lhs)) {
                        //      errs() << "unary operator\n";
                        UnaryOperator *uexpr = dyn_cast<UnaryOperator>(lhs);
                        if (uexpr->getOpcode() == UO_Deref) {
                            //         errs() << "deref\n";
                            // lhs is a deref so this is a write
                            Expr *ptre = uexpr->getSubExpr()->IgnoreImpCasts()->IgnoreCasts();
                            assert (ptre != NULL);
                            Attack(LavaAttackWritePtr, ptre);
                        }
                    }
                    else if (isa<ArraySubscriptExpr>(lhs)) {
                        ArraySubscriptExpr *ase = dyn_cast<ArraySubscriptExpr>(lhs);
                        Expr *index = ase->getIdx();
                        Attack(LavaAttackWriteArrayIndex, index);
                    }

                }
            }
            else {
            /*
------------------
VisitExpr
ImplicitCastExpr 0x91ca608 'char' <LValueToRValue>
`-ArraySubscriptExpr 0x91ca5f0 'char' lvalue
  |-ImplicitCastExpr 0x91ca5e0 'char *' <LValueToRValue>
  | `-MemberExpr 0x91ca5a4 'char *' lvalue ->z 0x91c9e10
  |   `-ImplicitCastExpr 0x91ca598 'Foo *' <LValueToRValue>
  |     `-DeclRefExpr 0x91ca57c 'Foo *' lvalue Var 0x91ca150 'foo' 'Foo *'
  `-IntegerLiteral 0x91ca5c8 'int' 3
file.c:564..564:foo->z[3]
------------------

             */

                //            errs() << "its an rvalue\n";
                Expr *nc_expr = expr->IgnoreImpCasts()->IgnoreCasts();                
                if (isa<UnaryOperator>(nc_expr)) {
                    //      errs() << "its a unary operator\n";
                    UnaryOperator *uexpr = dyn_cast<UnaryOperator>(nc_expr);
                    if (uexpr->getOpcode() == UO_Deref) {
                        //     errs() << "its a deref\n";
                        // expr is a deref so this is a read?
                        Expr *ptre = uexpr->getSubExpr()->IgnoreImpCasts()->IgnoreCasts();
                        Attack(LavaAttackReadPtr, ptre);
                    }
                }
                else if (isa<ArraySubscriptExpr>(nc_expr)) {
                    ArraySubscriptExpr *ase = dyn_cast<ArraySubscriptExpr>(nc_expr);
                    Expr *index = ase->getIdx();
                    Attack(LavaAttackReadArrayIndex, index);
                }
            }
        }            
         
        return true;
    }
    
private:
    ASTContext *Context;
};


class FindAttackPointsConsumer : public clang::ASTConsumer {
public:
    explicit FindAttackPointsConsumer(ASTContext *Context)
    : Visitor(Context) {}
    
    virtual void HandleTranslationUnit(clang::ASTContext &Context) {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }
private:
    FindAttackPointsVisitor Visitor;
};

class FindAttackPointsAction : public clang::ASTFrontendAction {
public:
    virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance &Compiler, llvm::StringRef InFile) {
        return std::unique_ptr<clang::ASTConsumer>(
            new FindAttackPointsConsumer(&Compiler.getASTContext()));
    }
};

int main(int argc, const char **argv) {
    CommonOptionsParser op(argc, argv, MyToolCategory);
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());

    int r = Tool.run(newFrontendActionFactory<FindAttackPointsAction>().get());
    return r;

    /* 
    if (argc > 1) {
        printf ("blah\n");
        clang::tooling::runToolOnCode(new FindAttackPointsAction, argv[1]);
    }
    */
}

