#include "clang/Tooling/Tooling.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/ReplacementsYaml.h"

#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"

<<<<<<< HEAD
=======
#include "lava.hxx"
#include "lavaToolUtils.h"

>>>>>>> e445a95... Lava tool refactoring
using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::driver;
using namespace llvm;

struct LavaMatchHandler : public MatchFinder::MatchCallback {
    LavaMatchHandler(Modifier &Mod) : Mod(Mod) {}

    std::string ExprStr(const Stmt *e) {
        clang::PrintingPolicy Policy(*LangOpts);
        std::string TypeS;
        llvm::raw_string_ostream s(TypeS);
        e->printPretty(s, 0, Policy);
        return s.str();
    }

    LavaASTLoc GetASTLoc(const SourceManager &sm, const Stmt *s) {
        assert(!SourceDir.empty());
        FullSourceLoc fullLocStart(sm.getExpansionLoc(s->getLocStart()), sm);
        FullSourceLoc fullLocEnd(sm.getExpansionLoc(s->getLocEnd()), sm);
        std::string src_filename = StripPrefix(
                getAbsolutePath(sm.getFilename(fullLocStart)), SourceDir);
        return LavaASTLoc(src_filename, fullLocStart, fullLocEnd);
    }

    LExpr LavaAtpQuery(LavaASTLoc ast_loc, AttackPoint::Type atpType) {
        return LBlock({
                LFunc("vm_lava_attack_point2",
                    { LDecimal(GetStringID(StringIDs, ast_loc)), LDecimal(0),
                        LDecimal(atpType) }),
                LDecimal(0) });
    }

    void AttackExpression(const SourceManager &sm, const Expr *toAttack,
            const Expr *parent, const Expr *rhs, AttackPoint::Type atpType) {
        LavaASTLoc ast_loc = GetASTLoc(sm, toAttack);
        std::vector<LExpr> pointerAddends;
        std::vector<LExpr> valueAddends;

        debug(INJECT) << "Inserting expression attack (AttackExpression).\n";
        if (LavaAction == LavaInjectBugs) {
            const std::vector<const Bug*> &injectable_bugs =
                map_get_default(bugs_with_atp_at,
                        std::make_pair(ast_loc, atpType));

            // this should be a function bug -> LExpr to add.
            auto pointerAttack = KnobTrigger ? knobTriggerAttack : traditionalAttack;
            for (const Bug *bug : injectable_bugs) {
                assert(bug->atp->type == atpType);
                If (bug->type == Bug::PTR_ADD) {
                    pointerAddends.push_back(pointerAttack(bug));
                } else if (bug->type == Bug::REL_WRITE) {
                    const DuaBytes *where = db->load<DuaBytes>(bug->extra_duas[0]);
                    const DuaBytes *what = db->load<DuaBytes>(bug->extra_duas[1]);
                    pointerAddends.push_back(Test(bug) * Get(where));
                    valueAddends.push_back(Test(bug) * Get(what));
                }
            }
            bugs_with_atp_at.erase(std::make_pair(ast_loc, atpType));
        } else if (LavaAction == LavaQueries) {
            // call attack point hypercall and return 0
            pointerAddends.push_back(LavaAtpQuery(ast_loc, atpType));
            num_atp_queries++;
        }

        if (!pointerAddends.empty()) {
            LExpr addToPointer = LBinop("+", std::move(pointerAddends));
            Mod.Change(toAttack).Add(addToPointer, parent);
        }

        if (!valueAddends.empty()) {
            assert(rhs);
            LExpr addToValue = LBinop("+", std::move(valueAddends));
            Mod.Change(rhs).Add(addToValue, nullptr);
        }
    }

    virtual void handle(const MatchFinder::MatchResult &Result) = 0;
    virtual ~LavaMatchHandler() = default;

    virtual void run(const MatchFinder::MatchResult &Result) {
        const SourceManager &sm = *Result.SourceManager;
        auto nodesMap = Result.Nodes.getMap();

        debug(MATCHER) << "====== Found Match =====\n";
        for (auto &keyValue : nodesMap) {
            const Stmt *stmt = keyValue.second.get<Stmt>();
            if (stmt) {
                SourceLocation start = stmt->getLocStart();
                if (!sm.getFilename(start).empty() && sm.isInMainFile(start)
                        && !sm.isMacroArgExpansion(start)) {
                    debug(MATCHER) << keyValue.first << ": " << ExprStr(stmt) << " ";
                    stmt->getLocStart().print(debug(MATCHER), sm);
                    debug(MATCHER) << "\n";
                    if (DEBUG_FLAGS & MATCHER) stmt->dump();
                } else return;
            }
        }
        handle(Result);
    }

    const LangOptions *LangOpts = nullptr;

protected:
    Modifier &Mod;
};

