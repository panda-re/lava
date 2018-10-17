#ifndef FUNCTIONPOINTERFIELDHANDLER_H
#define FUNCTIONPOINTERFIELDHANDLER_H

struct FunctionPointerFieldHandler : public LavaMatchHandler {
    using LavaMatchHandler::LavaMatchHandler; // Inherit constructor.

    virtual void handle(const MatchFinder::MatchResult &Result) {
        const FieldDecl *decl = Result.Nodes.getNodeAs<FieldDecl>("fieldDecl");
        debug(FNARG) << decl->getLocEnd().printToString(*Mod.sm) << "\n";
        Mod.InsertAt(decl->getLocEnd().getLocWithOffset(-14), "int *" ARG_NAME ", ");
    }
};

#endif
