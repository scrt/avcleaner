#include "Globals.h"

namespace Globs {
    std::vector<clang::SourceRange> PatchedSourceLocation;
    const uint64_t CLIMB_PARENTS_MAX_ITER = 1000; // fail safe to prevent a recursion loop when climbing the list of parents.
}