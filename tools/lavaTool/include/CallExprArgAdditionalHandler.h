#ifndef CALLEXPRARGADDITIONALHANDLER_H
#define CALLEXPRARGADDITIONALHANDLER_H

//  Add data_flow arg to call expression
struct CallExprArgAdditionHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    void CAddArg(const CallExpr *call) {
        SourceLocation l1 = call->getBeginLoc();
        SourceLocation l2 = call->getEndLoc();
        debug(FNARG) << "call->getBeginLoc = " << Mod.sm->getFileOffset(l1) << "\n";
        debug(FNARG) << "call->getEndLoc = " << Mod.sm->getFileOffset(l2) << "\n";
        bool inv=false;
        debug(FNARG) << "call : [" << getStringBetweenRange(*Mod.sm, call->getSourceRange(), &inv) << "]\n";
        assert(!inv);
        AddArgGen(Mod, l1, l2, true, call->getNumArgs(), 5);
    }

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const CallExpr *call = Result.Nodes.getNodeAs<CallExpr>("callExpr");
        debug(FNARG) << "CallExprArgAdditionHandler\n";

        bool inv;
        SourceLocation l1 = call->getBeginLoc();
        SourceLocation l2 = call->getEndLoc();
        std::string cestr = getStringBetweenRange(*Mod.sm, call->getSourceRange(), &inv);
        assert (!inv);
        debug(FNARG) << "callexpr: [" << cestr << "\n";

        SourceLocation loc = clang::Lexer::findLocationAfterToken(
                call->getBeginLoc(), tok::l_paren, *Mod.sm, *Mod.LangOpts, true);

        // No need to check for ArgDataflow, since matcher only called then
        auto fnname = get_containing_function_name(Result, *call);
        // only instrument call if its in the body of a function that is on our whitelist
        if (fninstr(fnname)) {
            debug(FNARG) << "containing function is in whitelist " << fnname.second << " : " << fnname.first << "\n";
        }
        else {
            debug(FNARG) << "containing function is NOT in whitelist " << fnname.second << " : " << fnname.first << "\n";
            return;
        }

        // and if this is a call that is in the body of a function on our whitelist,
        // only instrument calls to functions that are themselves on our whitelist.
        const FunctionDecl *func = call->getDirectCallee();
        if (func) {
            fnname = fundecl_fun_name(Result, func);
            if (fninstr(fnname)) {
                debug(FNARG) << "called function is in whitelist " << fnname.second << " : " << fnname.first << "\n";
            } else {
                debug(FNARG) << "called function is NOT in whitelist " << fnname.second << " : " << fnname.first << "\n";
                return;
            }
        } else debug(FNARG) << "We have a func pointer?\n";

        // If we get here, we are instrumenting a call to a function on our whitelist that is in
        // the body of a function also on our whitelist.

        if (func == nullptr || func->getLocation().isInvalid()) {
            // Function Pointer
            debug(FNARG) << "function pointer use\n";
            call->getBeginLoc().print(debug(FNARG), *Mod.sm);
            debug(FNARG) << "\n";
            //debug(FNARG) << " argcount=" << call->getNumArgs() << "\n";
            //loc = call->getArg(0)->getBeginLoc();
        } else if (Mod.sm->isInSystemHeader(func->getLocation())) {
            debug(FNARG) << "in system header\n";
            return;
        } else {
            debug(FNARG) << "Neither\n";
        }

        debug(FNARG) << "Call addarg for dataflow\n";
        CAddArg(call);
        debug(FNARG) << "Done with addarg\n";

        /*
        loc.print(debug(FNARG), *Mod.sm);

        if (call->getNumArgs() == 0) {
            Mod.InsertAt(loc, ARG_NAME);
        } else {
            Mod.InsertAt(loc, ARG_NAME ", ");
        }*/
    }

};

#endif
