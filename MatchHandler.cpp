//
// Created by vladimir on 28.09.19.
//

#include "MatchHandler.h"
#include <random>
#include <regex>
#include <vector>
#include <string>
#include <sstream>
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/Inclusions/HeaderIncludes.h"
#include "clang/Tooling/Inclusions/IncludeStyle.h"
#include "Globals.h"
#include "Utils.h"

using namespace clang;

MatchHandler::MatchHandler(clang::Rewriter *rewriter) {
    this->ASTRewriter = rewriter;
}

std::vector<std::string>
MatchHandler::getNodeParents(const StringLiteral &NodeString, clang::ast_type_traits::DynTypedNode Node,
                             clang::ASTContext *const Context, std::vector<std::string> &CurrentParents,
                             uint64_t Iterations) {

    if (Iterations > Globs::CLIMB_PARENTS_MAX_ITER) {
        return CurrentParents;
    }

    ASTContext::DynTypedNodeList parents = Context->getParents(NodeString);

    if (Iterations > 0) {
        parents = Context->getParents(Node);
    }

    for (const auto &parent : parents) {

        StringRef ParentNodeKind = parent.getNodeKind().asStringRef();

        if (ParentNodeKind.find("Cast") != std::string::npos) {

            return getNodeParents(NodeString, parent, Context, CurrentParents, ++Iterations);
        }

        CurrentParents.push_back(ParentNodeKind);
        return getNodeParents(NodeString, parent, Context, CurrentParents, ++Iterations);
    }

    return CurrentParents;
}

bool
MatchHandler::climbParentsIgnoreCast(const StringLiteral &NodeString, clang::ast_type_traits::DynTypedNode node,
                                     clang::ASTContext *const pContext, uint64_t iterations) {

    ASTContext::DynTypedNodeList parents = pContext->getParents(NodeString);;

    if (iterations > 0) {
        parents = pContext->getParents(node);
    }

    for (const auto &parent : parents) {

        StringRef ParentNodeKind = parent.getNodeKind().asStringRef();

        if (ParentNodeKind.find("Cast") != std::string::npos) {

            return climbParentsIgnoreCast(NodeString, parent, pContext, ++iterations);
        }

        handleStringInContext(&NodeString, pContext, parent);
    }

    return false;
}

void MatchHandler::run(const MatchResult &Result) {
    const auto *Decl = Result.Nodes.getNodeAs<clang::StringLiteral>("decl");
    clang::SourceManager &SM = ASTRewriter->getSourceMgr();

    // skip function declaration in included headers
    if (!SM.isInMainFile(Decl->getBeginLoc()))
        return;

    if (!Decl->getBytes().str().size() > 4) {
        return;
    }

    climbParentsIgnoreCast(*Decl, clang::ast_type_traits::DynTypedNode(), Result.Context, 0);

    /*
    std::vector<std::string> Parents;
    getNodeParents(*Decl, clang::ast_type_traits::DynTypedNode(), Result.Context, Parents, 0);

    std::stringstream ListOfParents;
    bool IsFirst = true; // used as a sentinel to avoid printing a "comma" for the first element.
    for (auto &CurrentParent : Parents) {

        if (IsFirst) {
            IsFirst = false;
        } else {
            ListOfParents << ", ";
        }

        ListOfParents << CurrentParent;
    }
    llvm::outs() << ListOfParents.str() << "\n";
     */
}

void MatchHandler::handleStringInContext(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                         const clang::ast_type_traits::DynTypedNode node) {

    StringRef ParentNodeKind = node.getNodeKind().asStringRef();

    if (ParentNodeKind.compare("CallExpr") == 0) {
        handleCallExpr(pLiteral, pContext, node);
    } else if (ParentNodeKind.compare("InitListExpr") == 0) {
        handleInitListExpr(pLiteral, pContext, node);
    } else {
        llvm::outs() << "Unhandled context " << ParentNodeKind << " for string " << pLiteral->getBytes() << "\n";
    }
}

bool MatchHandler::handleExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                  const clang::ast_type_traits::DynTypedNode node) {

    clang::SourceRange LiteralRange = clang::SourceRange(
            ASTRewriter->getSourceMgr().getFileLoc(pLiteral->getBeginLoc()),
            ASTRewriter->getSourceMgr().getFileLoc(pLiteral->getEndLoc())
    );

    if(shouldAbort(pLiteral, pContext, LiteralRange))
        return false;

    std::string Replacement = Utils::translateStringToIdentifier(pLiteral->getBytes().str());

    if(!insertVariableDeclaration(pLiteral, pContext, LiteralRange, Replacement))
        return false ;

    Globs::PatchedSourceLocation.push_back(LiteralRange);

    return replaceStringLiteral(pLiteral, pContext, LiteralRange, Replacement);
}

void MatchHandler::handleCallExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                  const clang::ast_type_traits::DynTypedNode node) {


    const auto *FunctionCall = node.get<clang::CallExpr>();

    if (isBlacklistedFunction(FunctionCall)) {
        return; // TODO: exclude printf-like functions when the replacement is not constant anymore.
    }

    handleExpr(pLiteral, pContext, node);
}

// TODO : search includes for "common.h" or add it
void MatchHandler::handleInitListExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                      const clang::ast_type_traits::DynTypedNode node) {

    handleExpr(pLiteral, pContext, node);
}

bool MatchHandler::insertVariableDeclaration(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                             clang::SourceRange range, const std::string& Replacement) {

    std::string StringLiteralContent = pLiteral->getBytes().str();

    bool IsInGlobalContext = isStringLiteralInGlobal(pContext, *pLiteral);

    // inject code to declare the string in an encrypted fashion
    SourceRange FreeSpace = findInjectionSpot(pContext, clang::ast_type_traits::DynTypedNode(), *pLiteral,
                                              IsInGlobalContext, 0);
    std::string StringVariableDeclaration = Utils::generateVariableDeclaration(Replacement, StringLiteralContent);

    if (!IsInGlobalContext) {
        //StringVariableDeclaration += "\tdprintf(\"" + Replacement + "\");\n";
        StringVariableDeclaration.insert(0, 1, '\t');
    }

    StringVariableDeclaration.insert(0, 1, '\n');

    bool InsertResult = ASTRewriter->InsertText(FreeSpace.getBegin(), StringVariableDeclaration);

    if (InsertResult) {
        llvm::errs()<<" Could not finish to patch the string literal.\n";
        Globs::PatchedSourceLocation.push_back(range);
    }

    return !InsertResult;
}

bool MatchHandler::replaceStringLiteral(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                        clang::SourceRange LiteralRange,
                                        const std::string& Replacement) {

    // handle "TEXT" macro argument, for instance LoadLibrary(TEXT("ntdll"));
    bool isMacro = ASTRewriter->getSourceMgr().isMacroBodyExpansion(pLiteral->getBeginLoc());

    if (isMacro) {
        StringRef OrigText = clang::Lexer::getSourceText(CharSourceRange(pLiteral->getSourceRange(), true),
                                                         pContext->getSourceManager(), pContext->getLangOpts());

        // weird bug with TEXT Macro / other macros...there must be a proper way to do this.
        if (OrigText.find("TEXT") != std::string::npos) {

            ASTRewriter->RemoveText(LiteralRange);
            LiteralRange.setEnd(ASTRewriter->getSourceMgr().getFileLoc(pLiteral->getEndLoc().getLocWithOffset(-1)));
        }
    }

    return ASTRewriter->ReplaceText(LiteralRange, Replacement);
}

SourceRange
MatchHandler::findInjectionSpot(clang::ASTContext *const Context, clang::ast_type_traits::DynTypedNode Parent,
                                const clang::StringLiteral &Literal, bool IsGlobal, uint64_t Iterations) {

    if (Iterations > Globs::CLIMB_PARENTS_MAX_ITER)
        throw std::runtime_error("Reached max iterations when trying to find a function declaration");

    ASTContext::DynTypedNodeList parents = Context->getParents(Literal);;

    if (Iterations > 0) {
        parents = Context->getParents(Parent);
    }

    for (const auto &parent : parents) {

        StringRef ParentNodeKind = parent.getNodeKind().asStringRef();

        if (ParentNodeKind.find("FunctionDecl") != std::string::npos) {
            auto FunDecl = parent.get<clang::FunctionDecl>();
            auto *Statement = FunDecl->getBody();
            auto *FirstChild = *Statement->child_begin();
            return {FirstChild->getBeginLoc(), FunDecl->getEndLoc()};

        } else if (ParentNodeKind.find("VarDecl") != std::string::npos) {

            if (IsGlobal) {
                return parent.get<clang::VarDecl>()->getSourceRange();
            }
        }

        return findInjectionSpot(Context, parent, Literal, IsGlobal, ++Iterations);
    }
}

bool MatchHandler::isBlacklistedFunction(const CallExpr *FunctionCall) {

    const FunctionDecl *FnDeclaration = FunctionCall->getDirectCallee();

    //abort if invalid call
    if (FnDeclaration == nullptr)
        return true;

    IdentifierInfo *II = FnDeclaration->getIdentifier();

    if (II == nullptr) {
        return true;
    }

    std::string ApiName = II->getName();

    return ApiName.find("dprintf") != std::string::npos;
}

bool MatchHandler::isStringLiteralInGlobal(clang::ASTContext *const Context, const clang::StringLiteral &Literal) {

    std::vector<std::string> Parents;
    getNodeParents(Literal, clang::ast_type_traits::DynTypedNode(), Context, Parents, 0);

    for (auto &CurrentParent : Parents) {

        if (CurrentParent == "FunctionDecl") {
            return false;
        }
    }

    return true;
}

bool
MatchHandler::shouldAbort(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext, SourceRange string) {

    std::string StringLiteralContent = pLiteral->getBytes().str();

    if (StringLiteralContent.size() < 6) {
        return true;
    }

    auto ShouldSkip = false;

    // does it overlap the source location of an already patched string?
    for(auto &Range : Globs::PatchedSourceLocation)  {

        if(pContext->getSourceManager().isPointWithin(string.getBegin(), Range.getBegin(), Range.getEnd())) {
            ShouldSkip = true;
        }
        else if(pContext->getSourceManager().isPointWithin(string.getEnd(), Range.getBegin(), Range.getEnd())){
            ShouldSkip = true;
        }

        if(ShouldSkip)  {
            llvm::outs() << "Ignoring " << pLiteral->getBytes() << " because it was already patched";
            return true;
        }
    }

    return false;
}

