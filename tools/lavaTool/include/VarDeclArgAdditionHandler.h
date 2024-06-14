#ifndef VARDECLARGADDITIONHANDLER_H
#define VARDECLARGADDITIONHANDLER_H

using namespace clang;

struct VarDeclArgAdditionHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const VarDecl *vd = Result.Nodes.getNodeAs<VarDecl>("vardecl");
        SourceLocation l1 = vd->getBeginLoc();
        SourceLocation l2 = vd->getEndLoc();
        bool inv = false;
        debug(FNARG) << "vardecl  : [" << getStringBetweenRange(*Mod.sm, vd->getSourceRange(), &inv) << "]\n";
        if (inv) {
            debug(FNARG) << "... is invalid\n";
            return;
        }
        const clang::Type *ft = vd->getType().getTypePtr();
        assert (ft);
        if (ft->isFunctionPointerType()) {
            // field is a fn pointer
            const clang::Type *pt = ft->getPointeeType().IgnoreParens().getTypePtr();
            assert(pt);
            const clang::FunctionType *fun_type = dyn_cast<clang::FunctionType>(pt);
            //assert(fun_type);
            if (!fun_type) return;
            const FunctionProtoType *prot = dyn_cast<FunctionProtoType>(fun_type);
            // add the data_flow arg
            AddArgGen(Mod, l1, l2, false, prot->getNumParams(), 3);
        }
    }
};


#endif
