#ifndef FUNCDECLARGADDITIONALHANDLER_H
#define FUNCDECLARGADDITIONALHANDLER_H

struct FuncDeclArgAdditionHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor

    void AddArg(const FunctionDecl *func) {
        SourceLocation StartLoc = func->getBeginLoc();
        SourceLocation EndLoc;

        // We need the range covering the function signature (return type + name + args).
        // The previous code scanned strings for '{' to find the end.
        // In LLVM/Clang, we can just check if the function has a body.
        if (func->hasBody()) {
            // If it has a body: void foo() { ... }
            // The signature ends right before the body starts.
            // getBody()->getBeginLoc() points exactly to the '{'.
            EndLoc = func->getBody()->getBeginLoc();
        } else {
            // If it's a prototype: void foo();
            // The end location of the declaration is the semicolon or the last paren.
            EndLoc = func->getEndLoc();
        }

        // Debugging (Optional, mostly to match your previous logs)
        // You can remove these debug lines if you want to clean up further.
        debug(FNARG) << "func start: " << Mod.sm->getFileOffset(StartLoc) << "\n";
        debug(FNARG) << "func end  : " << Mod.sm->getFileOffset(EndLoc) << "\n";

        // Call the generator.
        // We don't need to manually check bounds because 'AddArgGen' (which we fixed earlier)
        // now uses the Lexer to safely find the opening parenthesis within this range.
        AddArgGen(Mod, StartLoc, EndLoc, false, func->getNumParams(), 1);
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
