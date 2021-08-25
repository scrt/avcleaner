//
// Created by Vladimir on 20.06.20.
//

#ifndef AVCLEANER_APIMATCHHANDLER_H
#define AVCLEANER_APIMATCHHANDLER_H

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

class ApiMatchHandler : public clang::ast_matchers::MatchFinder::MatchCallback {

    using MatchResult = clang::ast_matchers::MatchFinder::MatchResult;

public:ApiMatchHandler() = default;
    ApiMatchHandler(clang::Rewriter *rewriter, std::string ApiName, std::string TypeDef, std::string Library) : ASTRewriter(rewriter),
                                                                                           _ApiName(ApiName),
                                                                                           _TypeDef(TypeDef), _Library(Library) {}

    ApiMatchHandler(clang::Rewriter *rewriter, std::string ApiName, std::string TypeDef, std::string NtName, bool ConvertToSyscall) : ASTRewriter(rewriter),
                                                                                                                _ApiName(ApiName),
                                                                                                                _TypeDef(TypeDef),
                                                                                                                _NtName(NtName),
                                                                                                                _ConvertToSyscall(ConvertToSyscall) {
        llvm::outs() << "toto " <<  _TypeDef << "\n";
    }

    void run(const MatchResult &Result) override; // callback function that runs when a Match is found.

private:
    clang::Rewriter *ASTRewriter; // an instance to a Rewriter to manage changes to the AST.
    std::string _ApiName = "";
    std::string _TypeDef ="";
    std::string _Library = "";
    std::string _NtName = "";
    bool _ConvertToSyscall = false;
    std::vector<const clang::FunctionDecl*> TypedefAdded; // collection of locations where the TypeDef for the API was already added.

    static clang::SourceRange findInjectionSpot(clang::ASTContext *const Context, clang::DynTypedNode Parent,
                                         const clang::CallExpr &Literal, uint64_t Iterations);

    bool
    addGetProcAddress(const clang::CallExpr *pCallExpression, clang::ASTContext *const pContext,
                      const std::string &NewIdentifier, std::string &ApiName);

    std::string getFunctionIdentifier(const clang::CallExpr *CallExpression);

    bool replaceIdentifier(const clang::CallExpr *CallExpression, const std::string &ApiName,
                           const std::string &NewIdentifier);

    bool handleCallExpr(const clang::CallExpr *CallExpression, clang::ASTContext *const pContext);

    bool shouldReplaceWithSyscall(std::string ApiName);

    void rewriteApiToSyscall(const clang::CallExpr *pExpr, clang::ASTContext *const pContext, std::string ApiName);

    bool isInsideIfCondition(const clang::CallExpr *pExpr, clang::ASTContext *const pContext);

    std::vector<std::string>
    getParents(const clang::Expr &pExr, clang::DynTypedNode Node, clang::ASTContext *const Context,
                   std::vector<std::string> &CurrentParents, uint64_t Iterations);

    clang::SourceLocation findFirstFunctionDecl(const clang::Expr &pExpr, clang::DynTypedNode Node,
                                                clang::ASTContext *const Context, clang::SourceLocation Loc,
                                                uint64_t Iterations);

    std::string getCallExprAssignmentVarName(const clang::CallExpr *pExpr, clang::ASTContext *const pContext);
};

static std::map<std::string, std::string> ApiToHide_samlib = {
        /*{"SamConnect",                     "typedef NTSTATUS (__stdcall* _SamEnumerateDomainsInSamServer)(SAMPR_HANDLE ServerHandle, DWORD * EnumerationContext, PSAMPR_RID_ENUMERATION* Buffer, DWORD PreferedMaximumLength,DWORD * CountReturned);"},
        {"SamConnectWithCreds",            "typedef NTSTATUS(__stdcall* _SamConnect)(PUNICODE_STRING ServerName, SAMPR_HANDLE * ServerHandle, ACCESS_MASK DesiredAccess, BOOLEAN Trusted);"},
        {"SamEnumerateDomainsInSamServer", "typedef NTSTATUS(__stdcall* _SamConnectWithCreds)(PUNICODE_STRING ServerName, SAMPR_HANDLE * ServerHandle, ACCESS_MASK DesiredAccess, LSA_OBJECT_ATTRIBUTES * ObjectAttributes, RPC_AUTH_IDENTITY_HANDLE AuthIdentity, PWSTR ServerPrincName, ULONG * unk0);"},*/
        {"SamLookupDomainInSamServer",     "typedef NTSTATUS(__stdcall* _SamLookupDomainInSamServer)(SAMPR_HANDLE ServerHandle, PUNICODE_STRING Name, PSID * DomainId);"},
        {"SamOpenDomain",                  "typedef NTSTATUS(__stdcall* _SamOpenDomain)(SAMPR_HANDLE SamHandle, ACCESS_MASK DesiredAccess, PSID DomainId, SAMPR_HANDLE * DomainHandle);"},
        {"SamOpenUser",                    "typedef NTSTATUS(__stdcall* _SamOpenUser)(SAMPR_HANDLE DomainHandle, ACCESS_MASK DesiredAccess, DWORD UserId, SAMPR_HANDLE * UserHandle);"},
        {"SamOpenGroup",                   "typedef NTSTATUS(__stdcall* _SamOpenGroup)(SAMPR_HANDLE DomainHandle, ACCESS_MASK DesiredAccess, DWORD GroupId, SAMPR_HANDLE * GroupHandle);"},
        {"SamOpenAlias",                   "typedef NTSTATUS(__stdcall* _SamOpenAlias)(SAMPR_HANDLE DomainHandle, ACCESS_MASK DesiredAccess, DWORD AliasId, SAMPR_HANDLE * AliasHandle);"},
        {"SamQueryInformationUser",        "typedef NTSTATUS(__stdcall* _SamQueryInformationUser)(SAMPR_HANDLE UserHandle, USER_INFORMATION_CLASS UserInformationClass, PSAMPR_USER_INFO_BUFFER* Buffer);"},
        {"SamSetInformationUser",          "typedef NTSTATUS(__stdcall* _SamSetInformationUser)(SAMPR_HANDLE UserHandle, USER_INFORMATION_CLASS UserInformationClass, PSAMPR_USER_INFO_BUFFER Buffer);"},
        {"SamiChangePasswordUser",         "typedef NTSTATUS(__stdcall* _SamiChangePasswordUser)(SAMPR_HANDLE UserHandle, BOOL isOldLM, const BYTE oldLM[LM_NTLM_HASH_LENGTH], const BYTE newLM[LM_NTLM_HASH_LENGTH], BOOL isNewNTLM, const BYTE oldNTLM[LM_NTLM_HASH_LENGTH], const BYTE newNTLM[LM_NTLM_HASH_LENGTH]);"},
        {"SamGetGroupsForUser",            "typedef NTSTATUS(__stdcall* _SamGetGroupsForUser)(SAMPR_HANDLE UserHandle, PGROUP_MEMBERSHIP * Groups, DWORD * CountReturned);"},
        {"SamGetAliasMembership",          "typedef NTSTATUS(__stdcall* _SamGetAliasMembership)(SAMPR_HANDLE DomainHandle, DWORD Count, PSID * Sid, DWORD * CountReturned, PDWORD * RelativeIds);"},
        {"SamGetMembersInGroup",           "typedef NTSTATUS(__stdcall* _SamGetMembersInGroup)(SAMPR_HANDLE GroupHandle, PDWORD *Members, PDWORD *Attributes, DWORD * CountReturned);"},
        {"SamGetMembersInAlias",           "typedef NTSTATUS(__stdcall* _SamGetMembersInAlias)(SAMPR_HANDLE AliasHandle, PSID ** Members, DWORD * CountReturned);"},
        {"SamEnumerateUsersInDomain",      "typedef NTSTATUS(__stdcall* _SamEnumerateUsersInDomain)(SAMPR_HANDLE DomainHandle, PDWORD EnumerationContext, DWORD UserAccountControl, PSAMPR_RID_ENUMERATION* Buffer, DWORD PreferedMaximumLength, PDWORD CountReturned);"},
        {"SamEnumerateGroupsInDomain",     "typedef NTSTATUS(__stdcall* _SamEnumerateGroupsInDomain)(SAMPR_HANDLE DomainHandle, PDWORD EnumerationContext, PSAMPR_RID_ENUMERATION * Buffer, DWORD PreferedMaximumLength, PDWORD CountReturned);"},
        {"SamEnumerateAliasesInDomain",    "typedef NTSTATUS(__stdcall* _SamEnumerateAliasesInDomain)(SAMPR_HANDLE DomainHandle, PDWORD EnumerationContext, PSAMPR_RID_ENUMERATION * Buffer, DWORD PreferedMaximumLength, PDWORD CountReturned);"},
        {"SamLookupNamesInDomain",         "typedef NTSTATUS(__stdcall* _SamLookupNamesInDomain)(SAMPR_HANDLE DomainHandle, DWORD Count, PUNICODE_STRING Names, PDWORD * RelativeIds, PDWORD * Use);"},
        {"SamLookupIdsInDomain",           "typedef NTSTATUS(__stdcall* _SamLookupIdsInDomain)(SAMPR_HANDLE DomainHandle, DWORD Count, PDWORD RelativeIds, PUNICODE_STRING * Names, PDWORD * Use);"},
        {"SamRidToSid",                    "typedef NTSTATUS(__stdcall* _SamRidToSid)(SAMPR_HANDLE ObjectHandle, DWORD Rid, PSID * Sid);"},
        {"SamCloseHandle",                 "typedef NTSTATUS(__stdcall* _SamCloseHandle)(SAMPR_HANDLE SamHandle);"},
        {"SamFreeMemory",                  "typedef NTSTATUS(__stdcall* _SamFreeMemory)(PVOID Buffer);"}
};

static std::vector<std::string> Syscalls = {
        "WriteProcessMemory",
        "CreateRemoteThread"
};
#endif //AVCLEANER_APIMATCHHANDLER_H
