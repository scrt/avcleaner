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
#include <vector>
#include <fstream>

namespace ClSetup {
    llvm::cl::OptionCategory ToolCategory("StringEncryptor");

    llvm::cl::opt<bool> IsEditEnabled("edit", llvm::cl::desc("Edit the file in place, or write a copy with .patch extension."),llvm::cl::cat(ToolCategory));
    llvm::cl::opt<bool> IsStringObfuscationEnabled("strings", llvm::cl::desc("Enable obfuscation of string literals."),llvm::cl::cat(ToolCategory));
    llvm::cl::opt<bool> IsApiObfuscationEnabled("api", llvm::cl::desc("Enable obfuscation of api calls."),llvm::cl::cat(ToolCategory));
}

namespace StringEncryptor {

    clang::Rewriter ASTRewriter;

    class StringEncryptionConsumer : public clang::ASTConsumer {
    public:

        void HandleTranslationUnit(clang::ASTContext &Context) override {
            using namespace clang::ast_matchers;
            using namespace StringEncryptor;

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

        void HandleTranslationUnit(clang::ASTContext &Context) override {
            using namespace clang::ast_matchers;
            using namespace StringEncryptor;

            llvm::outs() << "[ApiCallObfuscation] Registering ASTMatcher...\n";
            MatchFinder Finder;
            ApiMatchHandler Handler(&ASTRewriter);

            const auto Matcher = callExpr(callee(functionDecl(hasName("WriteProcessMemory")))).bind("callExpr");

            Finder.addMatcher(Matcher, &Handler);
            Finder.matchAST(Context);
        }
    };

    StringEncryptionConsumer StringConsumer = StringEncryptionConsumer();
    ApiCallConsumer ApiConsumer = ApiCallConsumer();

    class Action : public clang::ASTFrontendAction {

    public:
        using ASTConsumerPointer = std::unique_ptr<clang::ASTConsumer>;

        ASTConsumerPointer CreateASTConsumer(clang::CompilerInstance &Compiler,
                                             llvm::StringRef Filename) override {

            ASTRewriter.setSourceMgr(Compiler.getSourceManager(), Compiler.getLangOpts());
            std::vector<clang::ASTConsumer*> consumers;


            if(ClSetup::IsStringObfuscationEnabled) {
                consumers.push_back(&StringConsumer);
            }

            if(ClSetup::IsApiObfuscationEnabled) {
                consumers.push_back(&ApiConsumer);
            }

            auto TheConsumer = llvm::make_unique<Consumer>();
            TheConsumer->consumers = consumers;
            return TheConsumer;
        }

        bool BeginSourceFileAction(clang::CompilerInstance &Compiler) override {
            llvm::outs() << "Processing file " << '\n';

            return true;
        }

        void EndSourceFileAction() override {

            clang::SourceManager &SM = ASTRewriter.getSourceMgr();

            std::string FileName = SM.getFileEntryForID(SM.getMainFileID())->getName();
            llvm::errs() << "** EndSourceFileAction for: " << FileName << "\n";

            // Now emit the rewritten buffer.
            llvm::errs() << "Here is the edited source file :\n\n";
            std::string TypeS;
            llvm::raw_string_ostream s(TypeS);
            auto FileID = SM.getMainFileID();
            llvm::errs() << "Got main file id\n";
            auto ReWriteBuffer = ASTRewriter.getRewriteBufferFor(FileID);
            llvm::errs() << "Got Rewrite buffer\n";

            if(ReWriteBuffer != nullptr)
                ReWriteBuffer->write((s));
            else{
                llvm::errs() << "File was not modified\n";
                return;
            }

            std::string result = s.str();

            std::ofstream fo;

            if(ClSetup::IsEditEnabled)  {
                fo.open(FileName);
            } else{
                fo.open(FileName +".patch");
            }

            if(fo.is_open())
                fo << result;
            else
                llvm::errs() << "[!] Error saving result to " << FileName << "\n";
        }
    };
}

auto main(int argc, const char *argv[]) -> int {

    using namespace clang::tooling;
    using namespace ClSetup;

    CommonOptionsParser OptionsParser(argc, argv, ToolCategory);
    ClangTool Tool(OptionsParser.getCompilations(),
                   OptionsParser.getSourcePathList());

    auto Action = newFrontendActionFactory<StringEncryptor::Action>();
    return Tool.run(Action.get());
}