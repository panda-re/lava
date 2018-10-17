#ifndef CALLEXPRARGADDITIONALHANDLER_H
#define CALLEXPRARGADDITIONALHANDLER_H

struct CallExprArgAdditionHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const CallExpr *call = Result.Nodes.getNodeAs<CallExpr>("callExpr");
        const FunctionDecl *func = call->getDirectCallee();
        SourceLocation loc = clang::Lexer::findLocationAfterToken(
                call->getLocStart(), tok::l_paren, *Mod.sm, *Mod.LangOpts, true);

        if (func == nullptr || func->getLocation().isInvalid()) {
            // Function Pointer
            debug(FNARG) << "FUNCTION POINTER USE: ";
            call->getLocStart().print(debug(FNARG), *Mod.sm);
            debug(FNARG) << "this many args: " << call->getNumArgs() << "\n";
            loc = call->getArg(0)->getLocStart();
        } else if (Mod.sm->isInSystemHeader(func->getLocation())) {
            return;
        }

        loc.print(debug(FNARG), *Mod.sm);

        if (call->getNumArgs() == 0) {
            Mod.InsertAt(loc, ARG_NAME);
        } else {
            Mod.InsertAt(loc, ARG_NAME ", ");
        }
    }
};

#endif
