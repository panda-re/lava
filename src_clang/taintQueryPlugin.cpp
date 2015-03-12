
#include "clang/Frontend/FrontendPluginRegistry.h"

#include "taintQuery.h"

/*
 * Usage (preprocessor):
 * clang-3.6 -cc1 -load build/taintQueryPlugin.so -plugin taint-query <C file>
 */

static FrontendPluginRegistry::Add<TaintQueryFrontendAction>
X("taint-query", "Add LAVA taint queries");

