#ifndef FUNCTIONPOINTERFIELDHANDLER_H
#define FUNCTIONPOINTERFIELDHANDLER_H

// adding data_flow.  so look for
// struct (and union) fields that are fn ptr types
// so you can add in the extra arg.
struct FunctionPointerFieldHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const FieldDecl *fd = Result.Nodes.getNodeAs<FieldDecl>("fieldDecl");
        if (!fd) {
            debug(FNARG) << "fd is null in FunctionPointerFieldHandler\n";
//        debug(FNARG) << fd->print() << "\n";
        }
        else {

            const Type *t = fd->getType().getTypePtr();
            if (t->isPointerType()) { // || t->isArrayType()) {
                const Type *pt = t->getPointeeType().getTypePtr(); // t->getPointeeOrArrayElementType();
                if (pt->isFunctionType())
                    debug(FNARG) << "Its a fn pointer!\n";
                auto sl1 = fd->getLocStart();
                auto sl2 = fd->getLocEnd();
                debug(FNARG) << "start: " << sl1.printToString(*Mod.sm) << "\n";
                debug(FNARG) << "end:   " << sl2.printToString(*Mod.sm) << "\n";

            }
            //        debug(FNARG) << decl->getLocEnd().printToString(*Mod.sm) << "\n";
            //        Mod.InsertAt(decl->getLocEnd().getLocWithOffset(-14), "int *" ARG_NAME ", ");
        }
    }
};

#endif
