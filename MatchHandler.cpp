//
// Created by vladimir on 28.09.19.
//

#include "MatchHandler.h"
#include <random>
#include <regex>
#include <utility>
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
MatchHandler::getNodeParents(const StringLiteral &NodeString, clang::DynTypedNode Node,
                             clang::ASTContext *const Context, std::vector<std::string> &CurrentParents,
                             uint64_t Iterations) {

    if (Iterations > Globs::CLIMB_PARENTS_MAX_ITER) {
        return CurrentParents;
    }

    clang::DynTypedNodeList parents = Context->getParents(NodeString);

    if (Iterations > 0) {
        parents = Context->getParents(Node);
    }

    for (const auto &parent : parents) {

        StringRef ParentNodeKind = parent.getNodeKind().asStringRef();

        if (ParentNodeKind.find("Cast") != std::string::npos) {

            return getNodeParents(NodeString, parent, Context, CurrentParents, ++Iterations);
        }

        CurrentParents.push_back(ParentNodeKind.data());
        return getNodeParents(NodeString, parent, Context, CurrentParents, ++Iterations);
    }

    return CurrentParents;
}

std::string
MatchHandler::findStringType(const StringLiteral &NodeString, clang::ASTContext *const pContext) {

    clang::DynTypedNodeList parents = pContext->getParents(NodeString);;
    std::string StringType;
    for (const auto &parent : parents) {

        StringRef ParentNodeKind = parent.getNodeKind().asStringRef();

        if (ParentNodeKind.find("Cast") != std::string::npos) {

            StringType = parent.get<clang::ImplicitCastExpr>()->getType().getAsString();
            llvm::outs() << "StringType is " << StringType  << "\n";
        }

        llvm::outs() << "getParent, Node kind ot^^o: " << parent.getNodeKind().asStringRef() << "\n";
    }

    return StringType;
}

bool
MatchHandler::climbParentsIgnoreCast(const StringLiteral &NodeString, clang::DynTypedNode node,
                                     clang::ASTContext *const pContext, uint64_t iterations, std::string StringType) {

    clang::DynTypedNodeList parents = pContext->getParents(NodeString);;

    if (iterations > 0) {
        parents = pContext->getParents(node);
    }

    for (const auto &parent : parents) {

        StringRef ParentNodeKind = parent.getNodeKind().asStringRef();

        if (ParentNodeKind.find("Cast") != std::string::npos) {

            return climbParentsIgnoreCast(NodeString, parent, pContext, ++iterations, StringType);
        }

        handleStringInContext(&NodeString, pContext, parent, StringType);
    }

    return false;
}

void MatchHandler::run(const MatchResult &Result) {
    const auto *Decl = Result.Nodes.getNodeAs<clang::StringLiteral>("decl");
    clang::SourceManager &SM = ASTRewriter->getSourceMgr();

    // skip function declaration in included headers
    if (!SM.isInMainFile(Decl->getBeginLoc()))
        return;

    if (!(Decl->getBytes().str().size() > 4)) {
        return;
    }

    auto StringType = findStringType(*Decl, Result.Context);

    climbParentsIgnoreCast(*Decl, clang::DynTypedNode(), Result.Context, 0, StringType);

}

void MatchHandler::handleStringInContext(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                         const clang::DynTypedNode node, std::string StringType) {

    StringRef ParentNodeKind = node.getNodeKind().asStringRef();

    if (ParentNodeKind.compare("CallExpr") == 0) {
        handleCallExpr(pLiteral, pContext, node, StringType);
    } else if (ParentNodeKind.compare("InitListExpr") == 0) {
        handleInitListExpr(pLiteral, pContext, node, StringType);
    }/* not yet ready
 *     else if(ParentNodeKind.compare("VarDecl") == 0) {
        handleVarDeclExpr(pLiteral, pContext, node, StringType);
    }*/ else {
        llvm::outs() << "Unhandled context " << ParentNodeKind << " for string " << pLiteral->getBytes() << "\n";
    }
}

bool MatchHandler::handleExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                  const clang::DynTypedNode node, std::string StringType, std::string NewType) {

    clang::SourceRange LiteralRange = clang::SourceRange(
            ASTRewriter->getSourceMgr().getFileLoc(pLiteral->getBeginLoc()),
            ASTRewriter->getSourceMgr().getFileLoc(pLiteral->getEndLoc())
    );

    if(shouldAbort(pLiteral, pContext, LiteralRange))
        return false;

    std::string Replacement = Utils::translateStringToIdentifier(pLiteral->getBytes().str());

    if(!insertVariableDeclaration(pLiteral, pContext, LiteralRange, Replacement, StringType))
        return false ;

    if(!StringType.empty() && !NewType.empty())
        Replacement = "(" + NewType + ")" + Replacement;

    Globs::PatchedSourceLocation.push_back(LiteralRange);

    std::cout << "[*] Replacing string " << pLiteral->getBytes().str() << std::endl;
    return replaceStringLiteral(pLiteral, pContext, LiteralRange, Replacement);
}

void MatchHandler::handleCallExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                  const clang::DynTypedNode node, std::string StringType) {

    // below is an attempt to guess the correct string type
    const auto *FunctionCall = node.get<clang::CallExpr>();
    const FunctionDecl *FnDeclaration = FunctionCall->getDirectCallee();

    //abort if invalid call
    if (FnDeclaration == nullptr)
        return;

    IdentifierInfo *II = FnDeclaration->getIdentifier();

    if (II == nullptr) {
        return;
    }

    llvm::outs() << "Function is " << II->getName().data() << "\n";
    clang::LangOptions LangOpts;
    LangOpts.CPlusPlus = true;
    auto MacroName = clang::Lexer::getImmediateMacroName(FunctionCall->getSourceRange().getBegin(), pContext->getSourceManager(), LangOpts);

    if(!MacroName.empty() && MacroName.compare(II->getName().data())){
        llvm::outs() << "Macro detected, cannot guess the string type. Using TCHAR and prayers.\n";
        StringType = "TCHAR ";
    }

    for(unsigned int i = 0 ; i < FunctionCall->getDirectCallee()->getNumParams() ; i++) {

        auto ArgStart = pContext->getSourceManager().getSpellingColumnNumber(FunctionCall->getArg(i)->getBeginLoc());
        auto StringStart = pContext->getSourceManager().getSpellingColumnNumber(pLiteral->getBeginLoc());

        if(ArgStart == StringStart) {

            auto DeclType = FunctionCall->getDirectCallee()->getParamDecl(i)->getType().getAsString();
            auto Type = FunctionCall->getDirectCallee()->getParamDecl(i)->getType();

            // isConstQualified API returns incorrect result for LPCSTR or LPCWSTR, so the heuristic below is used.
            if(DeclType.find("const") == std::string::npos && DeclType.find("LPC") == std::string::npos) {

                auto keyword = std::string("const");
                auto pos = StringType.find(keyword);
                if (pos != std::string::npos){
                    StringType.erase(pos, keyword.length());
                }
            }
            break;
        }
    };

    if (isBlacklistedFunction(FunctionCall)) {
        return; // TODO: exclude printf-like functions when the replacement is not constant anymore.
    }

    handleExpr(pLiteral, pContext, node, StringType);
}

// TODO : search includes for "common.h" or add it
void MatchHandler::handleInitListExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                      const clang::DynTypedNode node, std::string StringType) {


    handleExpr(pLiteral, pContext, node, StringType);
}

void MatchHandler::handleVarDeclExpr(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                      const clang::DynTypedNode node, std::string StringType) {

    auto Identifier = node.get<clang::VarDecl>()->getIdentifier()->getName().data();
    auto TypeLoc =  node.get<clang::VarDecl>()->getTypeSourceInfo()->getTypeLoc();
    auto Type = TypeLoc.getType().getAsString();
    auto Loc = TypeLoc.getSourceRange();
    std::string LHSReplacement;
    if(Type.find(" []") != std::string::npos)
        LHSReplacement = Type.replace(Type.find(" []"),3,"* ");

    LHSReplacement.append(Identifier);

    llvm::outs() << "Type of " << Identifier << " is " << Type << "\n";
    std::string NewType = Type+" ";
    if (Type.find("BYTE*") != std::string::npos) {
        NewType = "const char ";
    } else if(Type.find("wchar") != std::string::npos){
        NewType = "const wchar_t ";
    } else if(Type.find("WCHAR") != std::string::npos){
        NewType = "const wchar_t ";
    } else if(Type.find("char*") != std::string::npos){
        NewType = "const char ";
    }

    ASTRewriter->ReplaceText(Loc, LHSReplacement);
    llvm::outs() << "Type of " << Identifier << " is " << StringType << "\n";
    
    handleExpr(pLiteral, pContext, node, NewType, Type+" ");
}


bool MatchHandler::insertVariableDeclaration(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext,
                                             clang::SourceRange range, const std::string& Replacement, std::string StringType) {

    std::string StringLiteralContent = pLiteral->getBytes().str();

    bool IsInGlobalContext = isStringLiteralInGlobal(pContext, *pLiteral);

    // inject code to declare the string in an encrypted fashion
    SourceRange FreeSpace = findInjectionSpot(pContext, clang::DynTypedNode(), *pLiteral,
                                              IsInGlobalContext, 0);

    std::string StringVariableDeclaration = Utils::generateVariableDeclaration(Replacement, StringLiteralContent, StringType);

    if (!IsInGlobalContext) {
        StringVariableDeclaration += "\tOutputDebugStringA(\"" + Replacement + "\");\n";
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
            //LiteralRange.setEnd(ASTRewriter->getSourceMgr().getFileLoc(pLiteral->getEndLoc()));
        }
    }

    return ASTRewriter->ReplaceText(LiteralRange, Replacement);
}

SourceRange
MatchHandler::findInjectionSpot(clang::ASTContext *const Context, clang::DynTypedNode Parent,
                                const clang::StringLiteral &Literal, bool IsGlobal, uint64_t Iterations) {

    if (Iterations > Globs::CLIMB_PARENTS_MAX_ITER)
        throw std::runtime_error("Reached max iterations when trying to find a function declaration");

    clang::DynTypedNodeList parents = Context->getParents(Literal);;

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

    std::string ApiName = II->getName().data();

    return ApiName.find("dprintf") != std::string::npos;
}

bool MatchHandler::isStringLiteralInGlobal(clang::ASTContext *const Context, const clang::StringLiteral &Literal) {

    std::vector<std::string> Parents;
    getNodeParents(Literal, clang::DynTypedNode(), Context, Parents, 0);

    for (auto &CurrentParent : Parents) {

        if (CurrentParent == "FunctionDecl") {
            return false;
        }
    }

    return true;
}

static bool hasPrintableChars(const std::string& text) {
    for (auto c: text) {
        if (static_cast<unsigned char>(c) > 33 or static_cast<unsigned char>(c) < 127) {
            return true;
        }
    }
    return false;
}

static int nbUniqChars(const std::string& text) {
    std::unordered_map<char, int> map;

    for (auto i = 0; i < text.length(); i++) {
        map[text[i]]++;
    }

    return map.size();
}

bool
MatchHandler::shouldAbort(const clang::StringLiteral *pLiteral, clang::ASTContext *const pContext, SourceRange string) {

    std::string StringLiteralContent = pLiteral->getBytes().str();

    if (StringLiteralContent.size() < 6) {
        std::cout << "[!] Skipped string " << StringLiteralContent << " because its size is lower than 6\n";
        return true;
    } else if(!hasPrintableChars(StringLiteralContent)) {
        std::cout << "[!] Skipped string " << StringLiteralContent << " because it appears to be a hex string and the dev is lazy\n";
        return true;
    }  else if(nbUniqChars(StringLiteralContent) < 3) {
        std::cout << "[!] Skipped string " << StringLiteralContent << " because it has very low entropy\n";
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
            llvm::outs() << "Ignoring " << pLiteral->getBytes() << " because it was already patched\n";
            return true;
        }
    }

    return false;
}

