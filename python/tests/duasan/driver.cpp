// Include the implementation so tests exercise its anonymous-namespace helpers.
// No test-only branches or exported test API are needed in the production tool.
#define main duasan_main
#include DUASAN_SOURCE
#undef main

int main(int argc, const char **argv) {
    if (argc == 4 && std::string(argv[1]) == "--prefix") {
        std::cout << StripPrefix(argv[2], argv[3]);
        return 0;
    }
    if (argc != 5 || std::string(argv[1]) != "--ast") {
        return duasan_main(argc, argv);
    }

    std::ifstream input(argv[3]);
    std::string code((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
    std::unique_ptr<ASTUnit> ast = buildASTFromCodeWithArgs(
        code, {"-std=c++17"}, argv[3]);
    if (!ast || ast->getDiagnostics().hasErrorOccurred()) {
        return 2;
    }

    const FunctionDecl *subject = nullptr;
    for (const Decl *decl : ast->getASTContext().getTranslationUnitDecl()->decls()) {
        const FunctionDecl *function = dyn_cast<FunctionDecl>(decl);
        if (function && function->getNameAsString() == "subject") {
            subject = function;
        }
    }

    if (!subject) {
        return 3;
    }

    const CompoundStmt *body = dyn_cast<CompoundStmt>(subject->getBody());
    SourceLval lval;
    lval.ast_name = argv[4];
    TestMatcher matcher;
    const SourceManager &sm = ast->getSourceManager();
    const std::string mode(argv[2]);

    if (mode == "param") {
        std::cout << matcher.paramCheck(sm, subject, &lval);
    } else if (mode == "expr") {
        for (const Stmt *statement : body->body()) {
            const DeclStmt *declarations = dyn_cast<DeclStmt>(statement);
            if (!declarations) {
                continue;
            }

            for (const Decl *decl : declarations->decls()) {
                const VarDecl *variable = dyn_cast<VarDecl>(decl);
                if (variable && variable->getNameAsString() == "probe") {
                    std::cout << matcher.rhsExprCheck(
                        variable->getInit(), xtractMembers(&lval));
                    return 0;
                }
            }
        }

        return 4;
    } else if (mode == "scope") {
        const size_t offset = code.find("/*DUA*/");
        if (offset == std::string::npos) {
            return 5;
        }

        const SourceLocation location = sm.getLocForStartOfFile(sm.getMainFileID())
            .getLocWithOffset(offset);
        const FullSourceLoc full(location, sm);
        lval.loc = ASTLoc(GetASTLoc(sm, body).filename, Loc(full), Loc(full));

        Dua dua;
        dua.lval = &lval;
        const Stmt *result = matcher.scopeCheck(sm, body, &dua);
        std::cout << (result ? GetASTLoc(sm, result).begin.line : 0);
    } else {
        return 6;
    }

    return 0;
}
