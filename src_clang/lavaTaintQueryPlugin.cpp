
#include "clang/Frontend/FrontendPluginRegistry.h"

#include "lavaTaintQuery.h"

/*
 * Usage (preprocessor):
 * clang-3.6 -cc1 -load build/lavaTaintQueryPlugin.so -plugin lava-taint-query <C file>
 */

static FrontendPluginRegistry::Add<LavaTaintQueryFrontendAction>
X("lava-taint-query", "Add LAVA taint queries");

