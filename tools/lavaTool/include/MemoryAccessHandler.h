#ifndef MEMORYACCESSHANDLER_H
#define MEMORYACCESSHANDLER_H

using namespace clang;

/*
  This handler is for AST items of the form
  LHS = RHS
  where LHS is a write to array element or via pointer.
  i.e. x[i] = ... or *p = ...
  Actually, to be precise, "lhs" binds to the 'i' or 'p'
  in the above example.

  This matcher is used to insert the 2nd half of a bug.
  That is, the use of one or more DUAs to change the array
  index of pointer value to cause a write out of bounds.

*/
struct MemoryAccessHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("innerExpr");
        const Expr *parent = Result.Nodes.getNodeAs<Expr>("lhs");

        if (ArgDataflow) {
            // data_flow bugs can only work in functions defined in the source,
            auto fnname = get_containing_function_name(Result, *toAttack);
            if (fninstr(fnname)) {
                debug(INJECT) << "MemoryAccessHandler: Containing function is in whitelist " << fnname.second << " : " << fnname.first << "\n";
            }
            else {
                debug(INJECT) << "MemoryAccessHandler: Containing function is NOT in whitelist " << fnname.second << " : " << fnname.first << "\n";
                return;
            }

            debug(INJECT) << "MemoryAccessHandler: ok to instrument " << fnname.second << "\n";;
        }

        const SourceManager &sm = *Result.SourceManager;
        LavaASTLoc ast_loc = GetASTLoc(sm, toAttack);
        //debug(INJECT) << "PointerAtpHandler @ " << ast_loc << "\n";

        const Expr *rhs = nullptr;
        AttackPoint::Type atpType = AttackPoint::POINTER_READ;

        // memwrite style attack points will have rhs bound to a node
        auto it = Result.Nodes.getMap().find("rhs");
        if (it != Result.Nodes.getMap().end()){
            atpType = AttackPoint::POINTER_WRITE;
            rhs = it->second.get<Expr>();
            assert(rhs);
        }

        AttackExpression(sm, toAttack, parent, rhs, atpType);
    }
};

#endif
