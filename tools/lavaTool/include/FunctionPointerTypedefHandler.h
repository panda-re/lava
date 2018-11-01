#ifndef FUNCTIONPOINTERTYPEDEFHANDLER_H
#define FUNCTIONPOINTERTYPEDEFHANDLER_H
// Add dataflow to typedef'd function pointer
struct FunctionPointerTypedefHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const TypedefDecl *td = Result.Nodes.getNodeAs<TypedefDecl>("typedefdecl");
        SourceLocation l1 = td->getLocStart();
        SourceLocation l2 = td->getLocEnd();
        bool inv;
        debug(FNARG) << "typedefdecl  : [" << getStringBetween(*Mod.sm, l1, l2, &inv) << "\n";
        if (inv) {
            debug(FNARG) << "... is invalid\n";
            return;
        }
        const Type *ft = td->getUnderlyingType().getTypePtr();
        assert(ft);
        if (ft->isFunctionPointerType()) {
            // field is a fn pointer
            const Type *pt = ft->getPointeeType().IgnoreParens().getTypePtr();
            assert(pt);
            const FunctionType *fun_type = dyn_cast<FunctionType>(pt);
            assert(fun_type);
            const FunctionProtoType *prot = dyn_cast<FunctionProtoType>(fun_type);
            // add the data_flow arg
            AddArgGen(Mod, l1, l2, false, prot->getNumParams(), 4);
        }
    }
};

#endif
