//
// Created by Vladimir on 20.06.20.
//

#include "ApiMatchHandler.h"

#include <random>
#include <regex>
#include <vector>
#include <string>
#include <sstream>
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/Inclusions/HeaderIncludes.h"
#include "clang/Tooling/Inclusions/IncludeStyle.h"
#include "Globals.h"

using namespace clang;

ApiMatchHandler::ApiMatchHandler(clang::Rewriter *rewriter) {
    this->ASTRewriter = rewriter;
}

void ApiMatchHandler::run(const MatchResult &Result) {
    const auto *Decl = Result.Nodes.getNodeAs<clang::StringLiteral>("decl");
}