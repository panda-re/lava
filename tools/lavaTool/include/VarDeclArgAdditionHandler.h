#ifndef VARDECLARGADDITIONHANDLER_H
#define VARDECLARGADDITIONHANDLER_H
// Add arg_dataflow into a variable declatation such as
// int (*fp)(int, float) => int (*fp)(int*, int, float)
// Only expecting this to work on functionPointer vardecls

using namespace clang;

struct VarDeclArgAdditionHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const VarDecl *vd = Result.Nodes.getNodeAs<VarDecl>("vardecl");
        SourceLocation l1 = vd->getLocStart();
        SourceLocation l2 = vd->getLocEnd();

        // Since the var declaration needs fixups, don't deal with the body,
        // just the declaration itself, so ignore everything after the =
        SourceLocation endOfDecl;
        debug(FNARG) << "vardecl -- looking for =\n";
        bool inv;
        endOfDecl = getLocAfterStr(*Mod.sm, l1, "=", 1, 1000, &inv);
        if (!inv) {
            // this means we found "="
            debug(FNARG) << " FOUND =\n";
            if (srcLocCmp(*Mod.sm, l2, endOfDecl) == SCMP_LESS)
                // In case the ( is past the end of the l1..l2 range
                endOfDecl = l2;
        }else{
            endOfDecl=l2;
        }

        debug(FNARG) << "vardecl  : [" << getStringBetweenRange(*Mod.sm, vd->getSourceRange(), &inv) << "]\n";
        if (inv) {
            debug(FNARG) << "... is invalid\n";
            return;
        }
        const Type *ft = vd->getType().getTypePtr();
        assert (ft);
        if (ft->isFunctionPointerType()) {
            // field is a fn pointer
            const Type *pt = ft->getPointeeType().IgnoreParens().getTypePtr();
            assert(pt);
            const FunctionType *fun_type = dyn_cast<FunctionType>(pt);
            //assert(fun_type);
            if (!fun_type) return;
            const FunctionProtoType *prot = dyn_cast<FunctionProtoType>(fun_type);
            // add the data_flow arg
            AddArgGen(Mod, l1, endOfDecl, /*argType=*/UNNAMEDARG, /*numArgs=*/prot->getNumParams(),
                      /*callsite=*/3);
        }
    }
};


#endif
