#ifndef FIELDDECLARGADDITIONHANDLER_H
#define FIELDDECLARGADDITIONHANDLER_H

using namespace clang;

/*
 A field in a struct or union that is fn pointer type
 field decl looks something like

 boolean (*empty_output_buffer) (j_compress_ptr cinfo);

 so all we need is to find location just after that open paren
 of fn arg type list
*/
struct FieldDeclArgAdditionHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const FieldDecl *fd =
            Result.Nodes.getNodeAs<FieldDecl>("fielddecl");
        SourceLocation l1 = fd->getBeginLoc();
        SourceLocation l2 = fd->getEndLoc();
        bool inv = false;
        debug(FNARG) << "fielddecl  : [" << getStringBetweenRange(*Mod.sm, fd->getSourceRange(), &inv) << "]\n";
        if (inv) {
            debug(FNARG) << "... is invalid\n";
            return;
        }
        const clang::Type *ft = fd->getType().getTypePtr();
        if (ft->isFunctionPointerType()) {
            // field is a fn pointer
            const clang::Type *pt = ft->getPointeeType().IgnoreParens().getTypePtr();
            //assert(pt);
            if (!pt) return;
            const clang::FunctionType *fun_type = dyn_cast<clang::FunctionType>(pt);
            if (fun_type == NULL) {
                debug(FNARG) << "... clang could not determine function type, abort\n";
                return;
            }

            //assert(fun_type);
            if (!fun_type) return;
            const clang::FunctionProtoType *prot = dyn_cast<clang::FunctionProtoType>(fun_type);
            if (!prot) return;
            // add the data_flow arg
            SourceLocation l1 = fd->getBeginLoc();
            SourceLocation l2 = fd->getEndLoc();
            AddArgGen(Mod, l1, l2, false, prot->getNumParams(), 2);
        }
    }
};

#endif
