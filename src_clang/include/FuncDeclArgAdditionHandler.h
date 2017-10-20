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

            // Duplicating the function
            SourceRange sr = func->getSourceRange();
            Stmt *s = func->getBody();

            //Stab to determin return type
            QualType q = func->getReturnType();

            // Get name of function
            DeclarationNameInfo dni = func->getNameInfo();
            DeclarationName dn = dni.getName();
            std::string fname = dn.getAsString();

            // Point to start of the function declaration
            SourceLocation END = s->getLocEnd().getLocWithOffset(1);
            std::stringstream new_func_array;

            // adding type func name and params
            new_func_array << "\n" << q.getAsString();
            if (q.getTypePtr() && !q.getTypePtr()->isPointerType())
                new_func_array << " ";
            new_func_array << fname.data() << "_origin" << "(";
            bool print_comma = false;

            int  i = 0;
            for (; i < func->getNumParams(); ++i) {
                if (print_comma)
                    new_func_array << ", ";
                else
                    print_comma = true;

                if (i == 0)
                    new_func_array << "int *data_flow,  ";

                ParmVarDecl *parm = func->parameters()[i];
                QualType parm_type = parm->getOriginalType();
                new_func_array << parm_type.getAsString();
                if (!parm_type.getTypePtr()->isPointerType())
                    new_func_array << " ";
                new_func_array << parm->getQualifiedNameAsString();
            }
            new_func_array << ")\n";

            // Printing body
            SourceRange bodyRange = s->getSourceRange();
            bool invalid;
            StringRef str = Lexer::getSourceText(CharSourceRange::getCharRange(bodyRange),
                    *Mod.sm, *Mod.LangOpts, &invalid);
            if (invalid) return;
            new_func_array << str.str();

            // adding func name
            new_func_array << "}";
            debug(FNARG) << "Inserting mambroooo " << new_func_array.str() << "\n";
            Mod.InsertAt(END, new_func_array.str());

            while (func != NULL) {
                AddArg(func);
                func = func->getPreviousDecl();
                if (func) debug(FNARG) << "found a redeclaration\n";
            }
        }
        return;
    }
};

