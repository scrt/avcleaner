cmake_minimum_required(VERSION 3.6)
project(avcleaner LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
#set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
#SET(CMAKE_EXE_LINKER_FLAGS $(llvm-config --ldflags))

list(APPEND CMAKE_CXX_SOURCE_FILE_EXTENSIONS c)

find_package(Clang REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "Using ClangConfig.cmake in: ${CLANG_CMAKE_DIR}")

# HandleLLVMOptions sets up compilation flags (disable warnings, etc.)
list(APPEND CMAKE_MODULE_PATH ${LLVM_DIR})
include(HandleLLVMOptions)

add_executable(avcleaner.bin
        main.cpp
        MatchHandler.cpp
        Globals.cpp
        ApiMatchHandler.cpp ApiMatchHandler.h Utils.cpp Utils.h)

include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wno-unused-parameter -fno-strict-aliasing -fno-rtti -I/usr/include -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -L/usr/lib ")

#target_link_libraries(avcleaner.bin LLVM clangTooling clangToolingInclusions clangLex clangToolingCore clangAST clangASTMatchers clangBasic clangFrontend clangFrontendTool clangRewrite clangRewriteFrontend clangSerialization

target_link_libraries(avcleaner.bin LLVM clang-cpp stdc++)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
