#ifndef FUNCTIONPOINTERTYPEDEFHANDLER_H
#define FUNCTIONPOINTERTYPEDEFHANDLER_H
// Add dataflow to typedef'd function pointer
struct FunctionPointerTypedefHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const TypedefDecl *td = Result.Nodes.getNodeAs<TypedefDecl>("typedefdecl");
        SourceLocation l1 = td->getBeginLoc();
        SourceLocation l2 = td->getEndLoc();
        bool inv=false;
        debug(FNARG) << "typedefdecl  : [" << getStringBetweenRange(*Mod.sm, td->getSourceRange(), &inv) << "\n";
        if (inv) {
            debug(FNARG) << "... is invalid\n";
            return;
        }
        const clang::Type *ft = td->getUnderlyingType().getTypePtr();
        //assert(ft);
        if (!ft) return;
        if (ft->isFunctionPointerType()) {
            // field is a fn pointer
            const clang::Type *pt = ft->getPointeeType().IgnoreParens().getTypePtr();
            //assert(pt);
            if (!pt) return;
            const clang::FunctionType *fun_type = dyn_cast<clang::FunctionType>(pt);
            //assert(fun_type);
            if (!fun_type) return;
            const clang::FunctionProtoType *prot = dyn_cast<clang::FunctionProtoType>(fun_type);
            // add the data_flow arg
            //assert(prot);
            if (!prot) return;
            AddArgGen(Mod, l1, l2, false, prot->getNumParams(), 4);
        }
    }
};

#endif
