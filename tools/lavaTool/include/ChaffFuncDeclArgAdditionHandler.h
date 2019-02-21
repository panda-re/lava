#ifndef CHAFFFUNCDECLARGADDITIONHANDLER_H
#define CHAFFFUNCDECLARGADDITIONHANDLER_H

using namespace clang;

struct ChaffFuncDeclArgAdditionHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler;

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        const FunctionDecl *func = Result.Nodes.getNodeAs<FunctionDecl>("funcDecl");
        auto fnname = fundecl_fun_name(Result, func);

        if (fnname.second.find("__builtin") != std::string::npos)   return;
        if (func->getLocation().isInvalid()) return;
        if (func->getNameAsString().find("lava") == 0) return;
        if (Mod.sm->isInSystemHeader(func->getLocation())) return;
        if (Mod.sm->getFilename(func->getLocation()).empty()) return;

        // Add Arg has higher priority if there's an overlap in dataflow functions & dataflow roots
        // - THis is to avoid variable name collision
        if (fninstr(fnname)) {
            SourceLocation loc = Lexer::findLocationAfterToken(
                    func->getLocation(), tok::l_paren, *Mod.sm, *Mod.LangOpts, true);
            if (already_added_arg.count(loc) == 0) {
                already_added_arg.insert(loc);
                if (func->getNumParams() == 0) {
                    Mod.InsertAt(loc, "int *" ARG_NAME);
                } else {
                    Mod.InsertAt(loc, "int *" ARG_NAME ", ");
                }
            }
        } else if (dataflowroot.count(fnname.second) != 0) {
            if (func->hasBody()) {
                CompoundStmt *body = dyn_cast<CompoundStmt>(func->getBody());
                assert(body);
                Stmt *first = *body->body_begin();
                assert(first);
                std::stringstream data;
                data << "int lava_chaff_data = 0;\n";
                data << "int *" ARG_NAME << "= &lava_chaff_data;\n";
                // Use InsertAfter - leave room for Abritriary variables in Stack Overrun bugs
                Mod.InsertTo(first->getLocStart(), data.str());
            }
        }

        if (addvarlist.count(fnname.second) != 0) {
            if (func->hasBody()) {
                CompoundStmt *body = dyn_cast<CompoundStmt>(func->getBody());
                assert(body);
                Stmt *first = *body->body_begin();
                assert(first);
                std::stringstream data;
                data << "int lava_chaff_var_0 = 0;\n";
                data << "int lava_chaff_var_1 = 0;\n";
                // Use InsertAfter - leave room for Abritriary variables in Stack Overrun bugs
                Mod.InsertAt(first->getLocStart(), data.str());
            }
        }

        return;
    }
};

#endif
