#ifndef MODIFIER_H
#define MODIFIER_H

#include "clang/AST/AST.h"
#include "clang/Lex/Lexer.h"

#include "Insertions.h"
using namespace clang;

/*
 * Contains all the machinery necessary to insert and tries to create some
 * high-level constructs around insertion.
 * Fluent interface to make usage easier. Use Modifier::Change to point at a
 * specific clang expression and the insertion methods to make changes there.
 */
class Modifier {
private:
    const Stmt *stmt = nullptr;

public:
    Insertions &Insert;
    const LangOptions *LangOpts = nullptr;
    const SourceManager *sm = nullptr;

    Modifier(Insertions &Insert) : Insert(Insert) {}

    void Reset(const LangOptions *LangOpts_, const SourceManager *sm_) {
        LangOpts = LangOpts_;
        sm = sm_;
    }

    std::pair<clang::SourceLocation, clang::SourceLocation> range() const {
        auto startRange = sm->getExpansionRange(stmt->getBeginLoc());
        auto endRange = sm->getExpansionRange(stmt->getEndLoc());
        return std::make_pair(startRange.getBegin(), endRange.getEnd());
    }

    SourceLocation before() const {
        return range().first;
    }

    SourceLocation after() const {
        // clang stores ranges as start of first token -> start of last token.
        // so to get character range for replacement, we need to add start of
        // last token.
        SourceLocation end = range().second;
        assert(sm != NULL);
        unsigned lastTokenSize = Lexer::MeasureTokenLength(end, *sm, *LangOpts);
        return end.getLocWithOffset(lastTokenSize);
    }


    // Return a source location-offset from end
    SourceLocation endRel(unsigned int offset) const {
        // Offset is signed, no checking on its bounds
        SourceLocation end = range().second;
        assert(sm != NULL);
        unsigned lastTokenSize = Lexer::MeasureTokenLength(end, *sm, *LangOpts);
        return end.getLocWithOffset(lastTokenSize-offset);
    }

    // Return a sourceLocation+offset from start
    SourceLocation startRel(unsigned int offset) const {
        // Offset is signed, no checking on its bounds
        SourceLocation end = range().second;
        assert(sm != NULL);
        unsigned lastTokenSize = Lexer::MeasureTokenLength(end, *sm, *LangOpts);
        return end.getLocWithOffset(lastTokenSize+offset);

        SourceLocation begin = range().first;
        return begin.getLocWithOffset(offset);
    }

    const Modifier &InsertBefore(std::string str) const {
        Insert.InsertBefore(before(), str);
        return *this;
    }
    // Insert after relative offset from end
    const Modifier &InsertAfterRel(int offset, std::string str) const {
        Insert.InsertAfter(endRel(offset), str);
        return *this;
    }

    const Modifier &InsertAfter(std::string str) const {
        Insert.InsertAfter(after(), str);
        return *this;
    }

    const Modifier &InsertAt(SourceLocation loc, std::string str) const {
        Insert.InsertBefore(loc, str);
        return *this;
    }

    const Modifier &InsertAfterEnd (std::string str) const {
        SourceLocation end = range().second;
        unsigned lastTokenSize = Lexer::MeasureTokenLength(end, *sm, *LangOpts);
        Insert.InsertAfter(end.getLocWithOffset(lastTokenSize+2), str);
        return *this;
    }

    const Modifier &Change(const Stmt *stmt_) {
        stmt = stmt_;
        return *this;
    }

    const Modifier &Parenthesize() const {
        return InsertBefore("(").InsertAfter(")");
    }

    const Modifier &Operate(std::string op, const LExpr &addend, const Stmt *parent) const {
        InsertAfter(" " + op + " " + addend.render());
        if (parent && !isa<ArraySubscriptExpr>(parent)
                && !isa<ParenExpr>(parent)) {
            Parenthesize();
        }
        return *this;
    }

    const Modifier &Add(const LExpr &addend, const Stmt *parent) const {
        // If inner stmt has lower precedence than addition, add parens.
        const BinaryOperator *binop = dyn_cast<BinaryOperator>(stmt);
        if (isa<AbstractConditionalOperator>(stmt)
                || (binop && !binop->isMultiplicativeOp()
                    && !binop->isAdditiveOp())) {
            Parenthesize();
        }
        return Operate("+", addend, parent);
    }

    void InsertAt(SourceLocation loc, std::string str) {
        Insert.InsertBefore(loc, str);
    }

    void InsertTo(SourceLocation loc, std::string str) {
        Insert.InsertAfter(loc, str);
    }
};

#endif
