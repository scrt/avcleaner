#include <map>
#include "Globals.h"

namespace Globs {
    std::vector<clang::SourceRange> PatchedSourceLocation;
    std::map<std::pair<int, std::string>, std::string> TypeDefsInserted;
    bool SyscallInserted = false;
    clang::SourceLocation FirstFunctionDeclLoc;
    const uint64_t CLIMB_PARENTS_MAX_ITER = 1000; // fail safe to prevent a recursion loop when climbing the list of parents.
}