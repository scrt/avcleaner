#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Rewrite/Core/Rewriter.h"

// LLVM includes
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include "Consumer.h"
#include "MatchHandler.h"
#include "ApiMatchHandler.h"

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <fstream>


namespace ClSetup {
    static llvm::cl::OptionCategory ToolCategory("AVObfuscator");

    llvm::cl::opt<bool> IsEditEnabled("edit",
                                      llvm::cl::desc("Edit the file in place, or write a copy with .patch extension."),
                                      llvm::cl::cat(ToolCategory));
    llvm::cl::opt<bool> IsStringObfuscationEnabled("strings", llvm::cl::desc("Enable obfuscation of string literals."),
                                                   llvm::cl::cat(ToolCategory));
    llvm::cl::opt<bool> IsApiObfuscationEnabled("api", llvm::cl::desc("Enable obfuscation of api calls."),
                                                llvm::cl::cat(ToolCategory));
}

namespace AVObfuscator {

    clang::Rewriter ASTRewriter;

    class StringEncryptionConsumer : public clang::ASTConsumer {
    public:

        void HandleTranslationUnit(clang::ASTContext &Context) override {
            using namespace clang::ast_matchers;
            using namespace AVObfuscator;

            llvm::outs() << "[StringEncryption] Registering ASTMatcher...\n";
            MatchFinder Finder;
            MatchHandler Handler(&ASTRewriter);

            const auto Matcher = stringLiteral().bind("decl");

            Finder.addMatcher(Matcher, &Handler);
            Finder.matchAST(Context);
        }
    };

    class ApiCallConsumer : public clang::ASTConsumer {
    public:

        ApiCallConsumer(std::string ApiName, std::string TypeDef, std::string Library)
                : _ApiName(std::move(ApiName)), _TypeDef(std::move(TypeDef)), _Library(std::move(Library)) {}


                ApiCallConsumer(std::string ApiName, std::string TypeDef, std::string NtName, bool ConvertToSyscall)
                : _ApiName(std::move(ApiName)), _TypeDef(std::move(TypeDef)), _NtName(std::move(NtName)), _ConvertToSyscall(ConvertToSyscall) {}

        void HandleTranslationUnit(clang::ASTContext &Context) override {
            using namespace clang::ast_matchers;
            using namespace AVObfuscator;

            llvm::outs() << "[ApiCallObfuscation] Registering ASTMatcher for " << _ApiName << "\n";
            MatchFinder Finder;

            const auto Matcher = callExpr(callee(functionDecl(hasName(_ApiName)))).bind("callExpr");

            ApiMatchHandler Handler;
            if(_ConvertToSyscall) {
                Handler = ApiMatchHandler(&ASTRewriter, _ApiName, _TypeDef, _NtName, true);

            } else {
                Handler = ApiMatchHandler(&ASTRewriter, _ApiName, _TypeDef, _Library);
            }
            Finder.addMatcher(Matcher, &Handler);

            Finder.matchAST(Context);
        }

    private:
        std::string _ApiName ="";
        std::string _TypeDef ="";
        std::string _Library = "";
        std::string _NtName ="";
        bool _ConvertToSyscall;
    };

    StringEncryptionConsumer StringConsumer = StringEncryptionConsumer();

    class Action : public clang::ASTFrontendAction {

    public:
        using ASTConsumerPointer = std::unique_ptr<clang::ASTConsumer>;

        ASTConsumerPointer CreateASTConsumer(clang::CompilerInstance &Compiler,
                                             llvm::StringRef Filename) override {

            ASTRewriter.setSourceMgr(Compiler.getSourceManager(), Compiler.getLangOpts());
            std::vector<clang::ASTConsumer *> consumers;


            if (ClSetup::IsStringObfuscationEnabled) {
                consumers.push_back(&StringConsumer);
            }

            if (ClSetup::IsApiObfuscationEnabled) {

                for(auto const& el: ApiToHide_samlib){

                    auto Cons = std::make_unique<ApiCallConsumer*>(new ApiCallConsumer(el.first, el.second,
                                                                                       "samlib.dll"));
                    consumers.push_back(*Cons);
                }

                std::string MessageBoxATypeDef = "typedef int (*_MessageBoxA)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);";
                auto Cons = std::make_unique<ApiCallConsumer*>(new ApiCallConsumer("MessageBoxA", MessageBoxATypeDef,
                                                                                   "User32.dll"));
                consumers.push_back(*Cons);

                auto ZwWriteVirtualMemoryTypeDef = "typedef NTSTATUS(__stdcall *_ZwWriteVirtualMemory)(\n"
                                                                   "      HANDLE	ProcessHandle,\n"
                                                                   "      PVOID	BaseAddress,\n"
                                                                   "      PVOID	Buffer,\n"
                                                                   "      ULONG    NumberOfBytesToWrite,\n"
                                                                   "      PULONG	NumberOfBytesWritten);\n\n";
                auto Cons2 = std::make_unique<ApiCallConsumer*>(new ApiCallConsumer("WriteProcessMemory", ZwWriteVirtualMemoryTypeDef,
                                                                                                              "ZwWriteVirtualMemory", true));
                consumers.push_back(*Cons2);

                auto ZwCreateThreadExTypeDef = "typedef  NTSTATUS(__stdcall* _ZwCreateThreadEx)(HANDLE * pHandle,\n"
                                               "    ACCESS_MASK DesiredAccess,\n"
                                               "    void * pAttr, \n"
                                               "    HANDLE hProc,\n"
                                               "    void * pFunc,\n"
                                               "    void * pArg,\n"
                                               "    ULONG Flags,\n"
                                               "    SIZE_T ZeroBits,\n"
                                               "    SIZE_T StackSize,\n"
                                               "    SIZE_T MaxStackSize,\n"
                                               "    void * pAttrListOut);\n\n";
                auto Cons3 = std::make_unique<ApiCallConsumer*>(new ApiCallConsumer("CreateRemoteThread", ZwCreateThreadExTypeDef,
                                                                                    "ZwCreateThreadEx", true));
                consumers.push_back(*Cons3);
            }

            auto TheConsumer = std::make_unique<Consumer>();
            TheConsumer->consumers = consumers;
            return TheConsumer;
        }

        bool BeginSourceFileAction(clang::CompilerInstance &Compiler) override {
            llvm::outs() << "Processing file " << Compiler.getSourceManager().getFileEntryForID(Compiler.getSourceManager().getMainFileID())->getName() << '\n';

            return true;
        }

        void EndSourceFileAction() override {

            clang::SourceManager &SM = ASTRewriter.getSourceMgr();

            std::string FileName = SM.getFileEntryForID(SM.getMainFileID())->getName().data();
            llvm::errs() << "** EndSourceFileAction for: " << FileName << "\n";

            // Now emit the rewritten buffer.
            std::string TypeS;
            llvm::raw_string_ostream s(TypeS);
            auto FileID = SM.getMainFileID();
            auto ReWriteBuffer = ASTRewriter.getRewriteBufferFor(FileID);

            if (ReWriteBuffer != nullptr)
                ReWriteBuffer->write((s));
            else {
                llvm::errs() << "File was not modified\n";
                return;
            }

            std::string result = s.str();

            std::ofstream fo;

            if (ClSetup::IsEditEnabled) {
                fo.open(FileName);
            } else {
                fo.open(FileName + ".patch");
            }

            if (fo.is_open())
                fo << result;
            else
                llvm::errs() << "[!] Error saving result to " << FileName << "\n";
        }
    };
}

auto main(int argc, const char *argv[]) -> int {

    using namespace clang::tooling;
    using namespace ClSetup;

    auto option_parser = CommonOptionsParser::create(argc, argv, ToolCategory);
    ClangTool Tool(option_parser->getCompilations(),
                   option_parser->getSourcePathList());

    auto Action = newFrontendActionFactory<AVObfuscator::Action>();
    return Tool.run(Action.get());
}
