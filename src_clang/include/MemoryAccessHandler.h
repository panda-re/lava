using namespace clang;

struct MemoryAccessHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) override {
        const Expr *toAttack = Result.Nodes.getNodeAs<Expr>("innerExpr");
        const Expr *parent = Result.Nodes.getNodeAs<Expr>("lhs");
        const SourceManager &sm = *Result.SourceManager;
        LavaASTLoc ast_loc = GetASTLoc(sm, toAttack);
        debug(INJECT) << "PointerAtpHandler @ " << ast_loc << "\n";

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

