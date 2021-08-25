//
// Created by vladimir on 28.09.19.
//

#ifndef AVCLEANER_MATCHHANDLER_H
#define AVCLEANER_MATCHHANDLER_H

#include <vector>
#include <string>
#include <memory>
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/ArrayRef.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Basic/SourceManager.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/AST/Type.h"
#include "clang/AST/Decl.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTTypeTraits.h"

#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/raw_ostream.h"

class MatchHandler : public clang::ast_matchers::MatchFinder::MatchCallback {

public:
    using MatchResult = clang::ast_matchers::MatchFinder::MatchResult;

    MatchHandler(clang::Rewriter *rewriter);

    void run(const MatchResult &Result) override; // callback function that runs when a Match is found.

private:
    clang::Rewriter *ASTRewriter; // an instance to a Rewriter to manage changes to the AST.

    // climb the list of parents recursively until it finds a useful node (i.e. not Cast-like nodes).
    bool climbParentsIgnoreCast(const clang::StringLiteral &NodeString, clang::DynTypedNode node,
                                clang::ASTContext *const pContext, uint64_t iterations, std::string StringType);
    /**
     * gets a list of all the parent nodes of a given StringLiteral node, ignoring Cast-like nodes.
     * @param NodeString a StringLiteral node
     * @param Node Holds the current parent node, empty at first iteration.
     * @param Context ASTContext of the initial node.
     * @param CurrentParents Accumulator of encountered parent nodes.
     * @param Iterations Number of iterations, used to prevent stack overflow.
     * @return a vector of strings of encountered parents NodeKind.
     */
    static std::vector<std::string>
    getNodeParents(const clang::StringLiteral &NodeString, clang::DynTypedNode Node,
                   clang::ASTContext *Context, std::vector<std::string> &CurrentParents, uint64_t Iterations);

    /**
     * @brief decides what to do according to the location in the AST of the identified string literal.
     * @param pLiteral the identified string literal.
     * @param pContext ASTContext of the string literal pLiteral.
     * @param node dummy node used to store the string literal successive parent.
     */
    void handleStringInContext(const clang::StringLiteral *pLiteral, clang::ASTContext *pContext,
                               clang::DynTypedNode node, std::string StringType);

    /**
     *
     * @param pLiteral a string occurrence to be encrypted
     * @param pContext an instance of ASTContext
     * @param node the AST node that makes use of the string pLiteral
     */
    void handleCallExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *pContext,
                        clang::DynTypedNode node, std::string StringType);


    /**
     * @brief Finds some free space to inject code that must run before the string literals usages.
     * @param Context an ASTContext instance.
     * @param Parent the current parent node of the string literal. Empty node for the first iteration.
     * @param Literal a string literal.
     * @param Iterations used to prevent a recursion infinite loop.
     * @return the location of a nice injection spot.
     */
    static clang::SourceRange
    findInjectionSpot(clang::ASTContext *Context, clang::DynTypedNode Parent,
                      const clang::StringLiteral &Literal, bool IsGlobal, uint64_t Iterations);

    /**
     * offers a chance to bail out from the refactoring process if the string literal is found in an unpatchable location.
     * @param FunctionName
     * @return true if the FunctionName is not blacklisted.
     */
    static bool isBlacklistedFunction(const clang::CallExpr *FunctionName);

    void handleInitListExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *pContext,
                            clang::DynTypedNode node, std::string StringType);

    bool shouldAbort(const clang::StringLiteral *pLiteral, clang::ASTContext *pContext, clang::SourceRange string);


    std::vector<const clang::StringLiteral*> EncounteredStrings; // collections of refactored String literals.
    static bool isStringLiteralInGlobal(clang::ASTContext *Context, const clang::StringLiteral &Literal);

    bool replaceStringLiteral(const clang::StringLiteral *pLiteral, clang::ASTContext *pContext,
                              clang::SourceRange range,
                              const std::string& string);

    bool insertVariableDeclaration(const clang::StringLiteral *pLiteral, clang::ASTContext *pContext,
                                   clang::SourceRange range, const std::string& string, std::string StringType="");

    bool handleExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *pContext,
                    clang::DynTypedNode node, std::string StringType="", std::string NewType="");

    void handleVarDeclExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *pContext,
                           clang::DynTypedNode node, std::string StringType);

    std::string findStringType(const clang::StringLiteral &NodeString, clang::ASTContext *const pContext);
};

#endif //AVCLEANER_MATCHHANDLER_H
