#include "clang/Frontend/FrontendPluginRegistry.h"

#include "taintQuery.h"

using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;

class TaintQueryASTAction :public TaintQueryFrontendAction,
    public PluginASTAction {
//class TaintQueryASTAction : public ASTFrontendAction {
//class TaintQueryASTAction : public TaintQueryFrontendAction {

public:
    TaintQueryASTAction(){
        //t = new TaintQueryFrontendAction();
    }
    ~TaintQueryASTAction(){
        //delete t;
    }

private:
    //Rewriter rewriter;
    //TaintQueryFrontendAction *t;
protected:

    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
            llvm::StringRef sr) {
        //return llvm::make_unique<TaintQueryASTConsumer>(rewriter);
        //return llvm::make_unique<TaintQueryFrontendAction>();
        //return llvm::make_unique<ASTConsumer>TaintQueryFrontendAction::CreateASTConsumer(CI, sr);
        //TaintQueryFrontendAction *t = new TaintQueryFrontendAction();
        //return t->CreateASTConsumer(CI, sr);
        return this->TaintQueryFrontendAction::CreateASTConsumer(CI, sr);
    }

    bool ParseArgs(const CompilerInstance &CI,
            const std::vector<std::string>& args) {
        /*for (unsigned i = 0, e = args.size(); i != e; ++i) {
          llvm::errs() << "PrintFunctionNames arg = " << args[i] << "\n";

        // Example error handling.
        if (args[i] == "-an-error") {
        DiagnosticsEngine &D = CI.getDiagnostics();
        unsigned DiagID = D.getCustomDiagID(DiagnosticsEngine::Error,
        "invalid argument '%0'");
        D.Report(DiagID) << args[i];
        return false;
        }
        }
        if (args.size() && args[0] == "help")
        PrintHelp(llvm::errs());*/

        return true;
    }
    void PrintHelp(llvm::raw_ostream& ros) {
        ros << "Help for PrintFunctionNames plugin goes here\n";
    }

    //void EndSourceFileAction() override {
    //    std::cout << "EndSourceFile in plugin?\n";
    //}

};

//}

//static FrontendPluginRegistry::Add<TaintQueryFrontendAction>
static FrontendPluginRegistry::Add<TaintQueryASTAction>
X("taint-query", "Add LAVA taint queries");

