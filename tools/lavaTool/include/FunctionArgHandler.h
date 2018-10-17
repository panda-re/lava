#ifndef FUNCTIONARGHANDLER_H
#define FUNCTIONARGHANDLER_H

using namespace clang;

struct FunctionArgHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("arg");
        const SourceManager &sm = *Result.SourceManager;

        debug(INJECT) << "FunctionArgHandler @ " << GetASTLoc(sm, toAttack) << "\n";

        AttackExpression(sm, toAttack, nullptr, nullptr, AttackPoint::FUNCTION_ARG);
    }
};

#endif
