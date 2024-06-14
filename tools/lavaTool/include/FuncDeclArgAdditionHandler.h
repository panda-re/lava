#ifndef FUNCDECLARGADDITIONALHANDLER_H
#define FUNCDECLARGADDITIONALHANDLER_H

struct FuncDeclArgAdditionHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor

    void AddArg(const FunctionDecl *func) {
        SourceLocation l1 = func->getBeginLoc();
        SourceLocation l2 = func->getEndLoc();
        debug(FNARG) << "func->getBeginLoc = " << Mod.sm->getFileOffset(l1) << "\n";
        debug(FNARG) << "func->getEndLoc = " << Mod.sm->getFileOffset(l2) << "\n";
        bool inv;
        debug(FNARG) << "func : [" << getStringBetweenRange(*Mod.sm, func->getSourceRange(), &inv) << "]\n";

        // We need the end of just the type signature part.
        // If this decl has a body, then that is the first '{' right?
        SourceLocation endOfProt;
        if (func->hasBody()) {
            debug(FNARG) << "has body -- looking for {\n";
            bool inv;
            endOfProt = getLocAfterStr(*Mod.sm, l1, "{", 1, 1000, &inv);
            if (!inv) {
                // this means we found "{"
                debug(FNARG) << " FOUND {\n";
                if (srcLocCmp(*Mod.sm, l2, endOfProt) == SCMP_LESS)
                    // { is past the end of the l1..l2 range
                    endOfProt = l2;
            }
            else {
                // hmm I guess there is a body but its not right here?
                // find last ')' and use that
                SourceLocation parenLoc, lastParenLoc;
                bool foundit = false;
                while (true) {
                    parenLoc = getLocAfterStr(*Mod.sm, l1, ")", 1, 1000, &inv);
                    if (inv) {
                        printf ("foundit\n");
                        l1 = parenLoc;
                        lastParenLoc = parenLoc;
                        foundit = true;
                    }
                    else {
                        printf ("didnt foundit\n");
                        parenLoc = lastParenLoc;
                        break;
                    }
                }
                assert (foundit);
                endOfProt = parenLoc;
            }
        }
        else
            endOfProt = l2;

        // add the data_flow arg between l1 and endOfProt
        AddArgGen(Mod, l1, endOfProt, false, func->getNumParams(), 1);
    }

    virtual void handle(const MatchFinder::MatchResult &Result) {

        const FunctionDecl *func =
            Result.Nodes.getNodeAs<FunctionDecl>("funcDecl");


        auto fnname = fundecl_fun_name(Result, func);

        // only instrument if function being decl / def is in whitelist
        if (fninstr(fnname)) {
            debug(FNARG) << "FuncDeclArgAdditionHandler: Function def/decl is in whitelist     " << fnname.second << " : " << fnname.first << "\n";
        }
        else {
            debug(FNARG) << "FuncDeclArgAdditionHandler: Function def/decl is NOT in whitelist " << fnname.second << " : " << fnname.first << "\n";
            return;
        }

        if (fnname.second.find("__builtin") != std::string::npos) {
            debug(FNARG) << "FuncDeclArgAdditionHandler: Function def/decl is builtin" << func->getNameAsString() << "\n";
            return;
        }

        debug(FNARG) << "FuncDeclArgAdditionHandler handle: ok to instrument " <<  fnname.second << "\n";
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
                // Inject valid C even if we have no values
                int data_slots_size = (data_slots.size() > 0) ? data_slots.size() : 1;
                data_array << "int data[" << data_slots_size << "] = {0};\n";
                data_array << "int *" ARG_NAME << "= &data;\n";
                Mod.InsertAt(first->getBeginLoc(), data_array.str());
            }
        } else {
            const FunctionDecl *bodyDecl = nullptr;
            func->hasBody(bodyDecl);
//            if (bodyDecl) AddArg(bodyDecl);
//            while (func != NULL) {
                AddArg(func);
//                func = func->getPreviousDecl();
//                if (func) debug(FNARG) << "found a redeclaration\n";
//            }
        }
        return;
    }
};

#endif
