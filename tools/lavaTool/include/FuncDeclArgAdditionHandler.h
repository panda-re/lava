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
        if (func->doesThisDeclarationHaveABody()) {
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

    // Where to insert declarations at the top of a function body. For an empty
    // body "{}" body_begin() == body_end(), so *body_begin() reads past the end
    // (the asserts are compiled out in Release) and handing that garbage Stmt's
    // location to the rewriter smashed the stack (FreeType's Ins_POP(void) {}).
    static SourceLocation bodyTopLoc(const CompoundStmt *body) {
        if (body->body_empty()) {
            return body->getLBracLoc().getLocWithOffset(1);
        }
        return (*body->body_begin())->getBeginLoc();
    }

    virtual void handle(const MatchFinder::MatchResult &Result) {

        const FunctionDecl *func = Result.Nodes.getNodeAs<FunctionDecl>("funcDecl");
        auto fnname = fundecl_fun_name(Result, func);

        // SHARED INVALIDATION CHECKS (Do these first before anything else)
        if (func->getSourceRange().isInvalid()) {
            return;
        }
        if (fnname.second.find("__builtin") != std::string::npos) {
            return;
        }
        if (func->getLocation().isInvalid()) {
            return;
        }
        if (func->getNameAsString().find("lava") == 0) {
            return;
        }
        if (Mod.sm->isInSystemHeader(func->getLocation())) {
            return;
        }
        if (Mod.sm->getFilename(func->getLocation()).empty()) {
            return;
        }
        if (!Mod.sm->isInMainFile(func->getLocation())) {
            return;
        }

        // 2 & 3. SQUASHED CHAFF INJECTION
        if (func->doesThisDeclarationHaveABody()) {
            CompoundStmt *body = dyn_cast<CompoundStmt>(func->getBody());
            assert(body);
            std::stringstream data;
            data << "int lava_chaff_var_0 = 0;\n";
            data << "int lava_chaff_var_1 = 0;\n";
            data << "unsigned long lava_chaff_var_2 = (unsigned long) &lava_chaff_var_0;\n";
            Mod.InsertAt(bodyTopLoc(body), data.str());
        }

        // CRITICAL: Preserve the early return for the query stage 
        // so we don't accidentally modify function signatures below.
        if (LavaAction == LavaQueries) {
            return;
        }

        // only instrument if function being decl / def is in whitelist
        // 4. LAVA + CHAFF DATA FLOW INJECTION
        if (fninstr(fnname)) {
            debug(FNARG) << "FuncDeclArgAdditionHandler: Function def/decl is in whitelist     " << fnname.second << " : " << fnname.first << "\n";
            debug(FNARG) << "adding arg to " << func->getNameAsString() << "\n";
            // You can't change arguments for main(), initialize data flow root from here
            if (func->isMain()) {
                if (func->isThisDeclarationADefinition()) { // no prototype for main.
                    CompoundStmt *body = dyn_cast<CompoundStmt>(func->getBody());
                    assert(body);
                    std::stringstream data_array;
                    // Inject valid C even if we have no values
                    int data_slots_size = (data_slots.size() > 0) ? data_slots.size() : 1;
                    data_array << "int data[" << data_slots_size << "] = {0};\n";
                    data_array << "int *" ARG_NAME << "= &data;\n";
                    Mod.InsertAt(bodyTopLoc(body), data_array.str());
                }
            } else {
                AddArg(func);
            }
            debug(FNARG) << "FuncDeclArgAdditionHandler handle: ok to instrument " <<  fnname.second << "\n";
        }
        else if (dataflowroot.count(fnname.second) != 0) {
            if (func->doesThisDeclarationHaveABody()) {
                CompoundStmt *body = dyn_cast<CompoundStmt>(func->getBody());
                assert(body);
                std::stringstream data;
                data << "int lava_chaff_data = 0;\n";
                data << "int *" ARG_NAME << "= &lava_chaff_data;\n";
                // Use InsertAfter - leave room for Abritriary variables in Stack Overrun bugs
                Mod.InsertTo(bodyTopLoc(body), data.str());
            }
        }
        else {
            debug(FNARG) << "FuncDeclArgAdditionHandler: Function def/decl is NOT in whitelist " << fnname.second << " : " << fnname.first << "\n";
        }
        return;
    }
};

#endif
