#include "taintQuery.h"

using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;

int main(int argc, const char **argv) {
    CommonOptionsParser op(argc, argv, TransformationCategory);
  
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());
    
    return Tool.run(newFrontendActionFactory<TaintQueryFrontendAction>().get());
}

