#include "clang/Tooling/Tooling.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/ReplacementsYaml.h"

#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"

#include "lava.hxx"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::driver;
using namespace llvm;

/*******************************
 * Matcher Handlers
 *******************************/

struct LavaMatchHandler : public MatchFinder::MatchCallback {
    LavaMatchHandler(Modifier &Mod) : Mod(Mod) {}

    std::set<SourceLocation> already_added_arg;

    std::string getStringBetweenRange(const SourceManager &sm, SourceRange range, bool *inv) {
        SourceLocation end = Lexer::getLocForEndOfToken(range.getEnd(), 0, sm, LangOptions());
        *inv = false;
        if (end == range.getBegin()) {
            *inv = true;
            return std::string("Invalid");
        }
        CharSourceRange char_range;
        char_range.setBegin(range.getBegin());
        char_range.setEnd(end);
        llvm::StringRef ref = Lexer::getSourceText(char_range, sm, LangOptions());
        return ref.str();
    }

    std::string getStringBetween(const SourceManager &sm, SourceLocation &l1, SourceLocation &l2, bool *inv) {
        const char *buf = sm.getCharacterData(l1, inv);
        unsigned o1 = sm.getFileOffset(l1);
        unsigned o2 = sm.getFileOffset(l2);
        if (*inv || (o1 > o2))
        return std::string("Invalid");
        return (std::string(buf, o2 - o1 + 1));
    }

    // Scans the range to find the position immediately after the
    // opening '(' of the argument list.
    SourceLocation FindInjectionPoint(const SourceManager &SM, const LangOptions &LangOpts,
                                  SourceLocation StartLoc, SourceLocation EndLoc) {

        SourceLocation CurrentLoc = StartLoc;
        SourceLocation BestOpenParen; // The winner
        int ParenLevel = 0;
        bool Invalid = false;

        // Loop through tokens until we hit EndLoc
        while (CurrentLoc < EndLoc) {
            Token Tok;
            // getRawToken is fast and doesn't require a preprocessor
            if (Lexer::getRawToken(CurrentLoc, Tok, SM, LangOpts, true)) {
                // If scanning fails (e.g., weird macro), advance by one char to avoid infinite loop
                CurrentLoc = CurrentLoc.getLocWithOffset(1);
                continue;
            }

            if (Tok.is(tok::l_paren)) {
                // We found a '('. If we are at the top level, this might be our arg list.
                // We keep updating BestOpenParen, so the *last* one we find becomes the winner.
                if (ParenLevel == 0) {
                    BestOpenParen = Tok.getEndLoc();
                }
                ParenLevel++;
            }
            else if (Tok.is(tok::r_paren)) {
                ParenLevel--;
            }
            // Move to next token
            CurrentLoc = Tok.getEndLoc();
        }
        return BestOpenParen;
    }

    /*
      The code between startLoc and endLoc contains, and, importantly,
      ends with an arg list. We want to insert data_flow at the head of it.
      We assume the *last* matching pair of open-close parens is an arg
      list. Note that this should work for calls, for fn prototypes, for
      struct/union field decls.  All end with an arg list.
      We use the isCall arg to AddArgGen to choose between adding an arg
      "data_flow" and adding a type "int *data_flow".
      And the arg numArgs tells us if there is zero args (in which case
      we dont need a comma).
    */
    void AddArgGen(Modifier &Mod, SourceLocation &startLoc, SourceLocation &endLoc,
                   bool isCall, unsigned numArgs, unsigned callsite) {

        bool inv;
        debug(FNARG) << "AddArgGen " << callsite << " : [" << getStringBetweenRange(*Mod.sm, SourceRange(startLoc, endLoc), &inv) << "]\n";
        if (inv) {
            debug(FNARG) << "invalid\n";
            return;
        }

        // Use the new robust Lexer helper
        SourceLocation loc_param_start = FindInjectionPoint(*Mod.sm, *Mod.LangOpts, startLoc, endLoc);
        if (loc_param_start.isInvalid()) {
            debug(FNARG) << "AddArgGen: Could not find argument list parenthesis.\n";
            return;
        }

        debug(FNARG) << "AddArgGen: Found injection point.\n";

        // Logic to insert the argument
        if (already_added_arg.count(loc_param_start) == 0) {
            already_added_arg.insert(loc_param_start);

            std::string dfa = ARG_NAME;
            if (!isCall) {
                dfa = "int *" ARG_NAME;
            }

            if (numArgs == 0) {
                // Case: void foo()  ->  void foo(int *data_flow)
                Mod.InsertAt(loc_param_start, dfa);
            } else {
                // Case: void foo(int a) -> void foo(int *data_flow, int a)
                Mod.InsertAt(loc_param_start, dfa + ", ");
            }
        }
    }

    std::pair<std::string,std::string> fundecl_fun_name(const MatchFinder::MatchResult &Result, const FunctionDecl *fd) {
        IdentifierInfo *II = fd->getIdentifier();
        if (II) {
            StringRef Name = II->getName();
            std::string funname = Name.str();
            std::string filename = Result.SourceManager->getFilename(fd->getLocation()).str();
            return std::make_pair(filename, funname);
        }
        return std::make_pair(std::string("Meh"),std::string("Unknown"));
    }

    std::pair<std::string,std::string> get_containing_function_name(const MatchFinder::MatchResult &Result, const Stmt &stmt) {

        const Stmt *pstmt = &stmt;

        std::pair<std::string,std::string> fail = std::make_pair(std::string("Notinafunction"), std::string("Notinafunction"));
        while (true) {
            const auto &parents = Result.Context->getParents(*pstmt);
            //debug(FNARG) << "get_containing_function_name: " << parents.size() << " parents\n";
            for (auto &parent : parents) {
                //debug(FNARG) << "parent: " << parent.getNodeKind().asStringRef().str() << "\n";
            }
            if (parents.empty()) {
                //debug(FNARG) << "get_containing_function_name: no parents for stmt? ";
                pstmt->dumpPretty(*Result.Context);
                //debug(FNARG) << "\n";
                return fail;
            }
            if (parents[0].get<TranslationUnitDecl>()) {
                //debug(FNARG)<< "get_containing_function_name: parents[0].get<TranslationUnitDecl? ";
                pstmt->dumpPretty(*Result.Context);
                //debug(FNARG) << "\n";
                return fail;
            }
            const FunctionDecl *fd = parents[0].get<FunctionDecl>();
            if (fd) return fundecl_fun_name(Result, fd);
            pstmt = parents[0].get<Stmt>();
            if (!pstmt) {
                //debug(FNARG) << "get_containing_function_name: !pstmt \n";
                const VarDecl *pvd = parents[0].get<VarDecl>();
                if (pvd) {
                    const auto &parents = Result.Context->getParents(*pvd);
                    pstmt = parents[0].get<Stmt>();
                }
                if (!pstmt)
                    return fail;
            }
        }
    }

    std::string ExprStr(const Stmt *e) {
        clang::PrintingPolicy Policy(*LangOpts);
        std::string TypeS;
        llvm::raw_string_ostream s(TypeS);
        e->printPretty(s, 0, Policy);
        return s.str();
    }

    ASTLoc GetASTLoc(const SourceManager &sm, const Stmt *s) {
        assert(!SourceDir.empty());
        FullSourceLoc fullLocStart(sm.getExpansionLoc(s->getBeginLoc()), sm);
        FullSourceLoc fullLocEnd(sm.getExpansionLoc(s->getEndLoc()), sm);
        std::string src_filename = StripPrefix(
                getAbsolutePath(sm.getFilename(fullLocStart)), SourceDir);
        return ASTLoc(src_filename, fullLocStart, fullLocEnd);
    }

    // A query inserted at a possible attack point. Used, dynamically, just to
    // tell us when an input gets to the attack point.
    LExpr LavaAtpQuery(ASTLoc ast_loc, AttackPoint::Type atpType) {
        return LBlock({
                LFunc("vm_lava_attack_point",
                    { LDecimal(GetStringID(StringIDs, ast_loc)), LDecimal(0),
                        LDecimal(atpType) }),
                LDecimal(0) });
    }

    /*
      An attack expression.  That is, this is where we would *like* to
      attack something.  Currently used by FunctionArgHandler and
      MemoryAccessHandler.  So, for
    */
    void AttackExpression(const SourceManager &sm, const Expr *toAttack,
            const Expr *parent, const Expr *rhs, AttackPoint::Type atpType) {
        ASTLoc ast_loc = GetASTLoc(sm, toAttack);
        std::vector<LExpr> pointerAddends;
        std::vector<LExpr> valueAddends;
        std::vector<LExpr> triggers;
        std::vector<Bug*> bugs;

        debug(INJECT) << "Inserting expression attack (AttackExpression).\n";
        const Bug *this_bug = NULL;

        if (LavaAction == LavaInjectBugs) {
            const std::vector<const Bug*> &injectable_bugs =
                map_get_default(bugs_with_atp_at,
                        std::make_pair(ast_loc, atpType));

            if (injectable_bugs.size() == 0 && ArgCompetition) {
                debug(INJECT) << "Abort, no injectable bugs and it's a competition\n";
                return;
            }

            // this should be a function bug -> LExpr to add.
            auto pointerAttack = KnobTrigger ? knobTriggerAttack : traditionalAttack;
            for (const Bug *bug : injectable_bugs) {
                assert(bug->atp->type == atpType);
                // was in if ArgCompetition, but we want to inject bugs more often
                Bug *bug2 = NULL;
                bug2 = (Bug*)malloc(sizeof(Bug));
                memcpy(bug2, bug, sizeof(Bug));
                bugs.push_back(bug2);

                if (bug->type == Bug::PTR_ADD) {
                    pointerAddends.push_back(pointerAttack(bug));
                    triggers.push_back(Test(bug)); //  Might fail for knobTriggers?
                } else if (bug->type == Bug::REL_WRITE) {
                    const DuaBytes *extra0 = db->load<DuaBytes>(bug2->extra_duas[0]);
                    const DuaBytes *extra1 = db->load<DuaBytes>(bug2->extra_duas[1]);
                    auto bug_combo = threeDuaTest(bug2, extra0, extra1); // Non-deterministic, need one object for triggers and ptr addends
                    triggers.push_back(bug_combo);

                    pointerAddends.push_back(bug_combo * Get(extra0));
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

            // For competitions, wrap pointer value in LAVALOG macro call-
            // it's effectively just a NOP that prints a message when the trigger is true
            // so we can identify when bugs are potentially triggered
            if (ArgCompetition) {
                assert (triggers.size() == bugs.size());

                for (int i=0; i < triggers.size(); i++) {
                    Bug *bug = bugs[i];
                    std::stringstream start_str;
                    start_str << "LAVALOG(" << bug->id << ", ";
                    Mod.Change(toAttack).InsertBefore(start_str.str());

                    std::stringstream end_str;

                    end_str << ", " << triggers[i] << ")";
                    Mod.Change(toAttack).InsertAfter(end_str.str());
                    free(bug);
                }
            }
        }

        /*
        if (!valueAddends.empty()) {
            assert(rhs);
            LExpr addToValue = LBinop("+", std::move(valueAddends));
            Mod.Change(rhs).Add(addToValue, nullptr);
        }
        */
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
                SourceLocation start = stmt->getBeginLoc();
                if (!sm.getFilename(start).empty() && sm.isInMainFile(start)
                        && !sm.isMacroArgExpansion(start)) {
                    debug(MATCHER) << keyValue.first << ": " << ExprStr(stmt) << " ";
                    stmt->getBeginLoc().print(debug(MATCHER), sm);
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

