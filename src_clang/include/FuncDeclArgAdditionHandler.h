struct FuncDeclArgAdditionHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor

    void AddArg(const FunctionDecl *func) {
        SourceLocation loc = clang::Lexer::findLocationAfterToken(
                func->getLocation(), tok::l_paren, *Mod.sm, *Mod.LangOpts, true);
        if (func->getNumParams() == 0) {
          Mod.InsertAt(loc, "int *" ARG_NAME);
        } else {
          Mod.InsertAt(loc, "int *" ARG_NAME ", ");
        }
    }

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const FunctionDecl *func =
            Result.Nodes.getNodeAs<FunctionDecl>("funcDecl")->getCanonicalDecl();

        debug(FNARG) << "adding arg to " << func->getNameAsString() << "\n";

        if (func->isThisDeclarationADefinition()) debug(FNARG) << "has body\n";
        if (func->getBody()) debug(FNARG) << "can find body\n";

        if (func->getLocation().isInvalid()) return;
        if (func->getNameAsString().find("lava") == 0) return;
        if (Mod.sm->isInSystemHeader(func->getLocation())) return;
        if (Mod.sm->getFilename(func->getLocation()).empty()) return;

        debug(FNARG) << "actually adding arg\n";

        if (func->isMain()) {
            if (func->isThisDeclarationADefinition()) { // no prototype for main.
                CompoundStmt *body = dyn_cast<CompoundStmt>(func->getBody());
                assert(body);
                Stmt *first = *body->body_begin();
                assert(first);

                std::stringstream data_array;
                data_array << "int data[" << data_slots.size() << "] = {0};\n";
                data_array << "int *" ARG_NAME << "= &data;\n";
                Mod.InsertAt(first->getLocStart(), data_array.str());
            }
        } else {
            const FunctionDecl *bodyDecl = nullptr;
            func->hasBody(bodyDecl);
            if (bodyDecl) AddArg(bodyDecl);

            while (func != NULL) {
                AddArg(func);
                func = func->getPreviousDecl();
                if (func) debug(FNARG) << "found a redeclaration\n";
            }
        }
        return;
    }
};

