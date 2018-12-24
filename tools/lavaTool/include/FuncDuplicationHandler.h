#ifndef FUNCDUPLICATIONHANDLER_H
#define FUNCDUPLICATIONHANDLER_H

struct FuncDuplicationHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const FunctionDecl *func =
            Result.Nodes.getNodeAs<FunctionDecl>("funcDecl")->getCanonicalDecl();

        debug(FNARG) << "Duplicating function " << func->getNameAsString() << "\n";

        if (func->isThisDeclarationADefinition()) debug(FNARG) << "has body\n";
        if (func->getBody()) debug(FNARG) << "can find body\n";

        if (func->getLocation().isInvalid()) return;
        if (func->getNameAsString().find("lava") == 0) return;
        if (Mod.sm->isInSystemHeader(func->getLocation())) return;
        if (Mod.sm->getFilename(func->getLocation()).empty()) return;

        debug(FNARG) << "actually performing duplication\n";

        const FunctionDecl *bodyDecl = nullptr;
        func->hasBody(bodyDecl);
        std::stringstream attr_addition;
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
        SourceLocation END_FILE =
            Mod.sm->getLocForEndOfFile(Mod.sm->getFileID(func->getLocation()));
        std::stringstream new_func_array;

        // adding type func name and params
        new_func_array << "\n" << q.getAsString();
        if (q.getTypePtr() && !q.getTypePtr()->isPointerType())
            new_func_array << " ";
        new_func_array <<" __attribute__((section(\".text_hidden\"))) "
            << fname.data() << "_origin (";
        bool print_comma = false;

        int  i = 0;
        for (; i < func->getNumParams(); ++i) {
            if (print_comma)
                new_func_array << ", ";
            else
                print_comma = true;

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
        Mod.InsertTo(END_FILE, new_func_array.str());

        return;
    }
};

#endif
