#ifndef FUNCTIONARGHANDLER_H
#define FUNCTIONARGHANDLER_H

using namespace clang;

/*
  This matcher handles arguments to function calls that are 'attackable', which is basically
  pointers or integers to which would could add something.
*/

struct FunctionArgHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        // this is the argument we might attack
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("arg");
        // and this is the fn call
        const CallExpr *call = Result.Nodes.getNodeAs<CallExpr>("call");
        if (call == nullptr) return;

        const SourceManager &sm = *Result.SourceManager;

        auto sl1 = call->getBeginLoc();
        auto sl2 = call->getEndLoc();
        debug(FNARG) << "start: " << sl1.printToString(sm) << "\n";
        debug(FNARG) << "end:   " << sl2.printToString(sm) << "\n";


        if (ArgDataflow) {
            auto fnname = get_containing_function_name(Result, *toAttack);

            // only instrument this function arg
            // if it's in the body of a function that is on our whitelist
            if (fninstr(fnname)) {
                debug(FNARG) << "FunctionArgHandler: Containing function is in whitelist " << fnname.second << " : " << fnname.first << "\n";
            } else {
                debug(FNARG) << "FunctionArgHandler: Containing function is NOT in whitelist " << fnname.second << " : " << fnname.first << "\n";
                return;
            }
    /*
            // and if this is a call to a function that is something like "__builtin_..." we dont instr
            // only instrument calls to functions that are themselves on our whitelist.
            assert (call != nullptr);
            assert (func != nullptr);
            fnname = fundecl_fun_name(Result, func);
            std::string filename = fnname.first;
            std::string functionname = fnname.second;

    */

            const Decl *func1 = call->getCalleeDecl();
            if (func1 != nullptr) {
                const NamedDecl *nd = dyn_cast<NamedDecl> (func1);
                if (nd != nullptr) {
                    std::string calleename = nd->getNameAsString();
                    debug(FNARG) << "Callee name is [" << calleename << "]\n";
                    if (calleename.find("__builtin_") != std::string::npos) {
                        return;
                    }
                }
            }else{
                debug(INJECT) << "Unknown (none) callee name\n";
            }

            debug(INJECT) << "FunctionArgHandler handle: ok to instrument " << fnname.second << "\n";
        }

        debug(INJECT) << "FunctionArgHandler @ " << GetASTLoc(sm, toAttack) << "\n";

/*
//        auto fnname = get_containing_function_name(Result, *toAttack);
        std::string filename = fnname.first;
        std::string functionname = fnname.second;
        if (functionname == "Notinafunction") return;


        if (functionname.find("__builtin_") != std::string::npos) {
            return;
        }
*/
        AttackExpression(sm, toAttack, nullptr, nullptr, AttackPoint::FUNCTION_ARG);
    }
};
#endif
