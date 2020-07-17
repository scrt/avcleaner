#pragma once

#include <vector>
#include <string>
#include <clang/Basic/SourceLocation.h>
#include <set>

namespace Globs {

    extern std::vector<clang::SourceRange> PatchedSourceLocation;
    extern const uint64_t CLIMB_PARENTS_MAX_ITER; // fail safe to prevent a recursion loop when climbing the list of parents.
}
