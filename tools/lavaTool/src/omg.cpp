#include <cassert>
#include <iostream>
#include <tuple>
#include <vector>
#include <algorithm>

using namespace std;

#include "clang/AST/AST.h"
#include "clang/Driver/Options.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
//using namespace clang::ast_matchers;
using namespace clang::driver;
using namespace llvm;

#define PARENS (1 << 0)
#define GENERAL (1 << 1)

#define DEBUG_FLAGS 0 // (PARENS | GENERAL)

static llvm::raw_null_ostream null_ostream;
#define debug(flag) ((DEBUG_FLAGS & (flag)) ? static_cast<llvm::raw_ostream&>(llvm::errs()) : static_cast<llvm::raw_ostream&>(null_ostream))

#include "omg.h"

// This file contains classes and functions that OMG why did I have to
// write them?  That is, why is clang so awful that I had to?
// Probably, clang isnt awful and I am just too dumb to figure out how
// to do these things using it.


/*
  This code undersands parenthesis structure of a string.  We use it
  for understanding fn prototypes (decl and def) and calls.  Mostly
  just this helps us find their argument or param lists.

  sourceString is a string containing text of the decl or def or call.

  The algorithm here is to search, iteratively, in the string for '('
  or ')' and keep track of nesting level.  This gives us vector of
  triples:

  <pos, openp, level>

  pos is position in string
  openp is true is this is a '(' and false if its a ')'.
  level is nesting level

  For example, consider the following.  A and B are
  startOfFnProtOrCall and endOfFnProtOrCall.  i..p are the locations
  of open or close parens.

  int (*fun)(int (*)(int), float, char *)
      i    jk    l mn   o               p

  The vector of triples for this looks like

  [(i, T, 1), (j, F, 1), (k, T, 1), (l, T, 2), (m, F, 2), (n, T, 2), (o, F, 2), (p, F, 1)]

  The last triple here must represent the close of the parens for the
  arg list (or param list).  Which can be paired to the first open,
  searching to the right in the vector from there that has the same
  level.  This is the triple (k,T,1).  So k is the location of the
  open paren that starts the arg / param list.

  Ugh!  This is obviously an inelegant solution to a ridiculous problem
  created either by Clang or my naive understanding of it.  We can't
  reliably find the source location of the start of the arg or param
  list.  So we use this to find it in the string and then map back to
  SourceLocations in SLgetParens.


  Edge cases: attributes after function definition

  int (*fun)(int (*)(int), float, char *) __attribute__ ((__format (printf, 1, 0))) something
      i    jk    l mn   o               p               qr         s            tuv

      Solution: if qr adjacent and uv adjacent, ignore them and anything between
      [... (q, T, 1), (r, T, 2), (s, T, 3), (t, F, 3), (u, F, 2), (v, F, 1)

      Implementation:
          for each element idx=x, level=1 open=T:
              check if x+1 exists with open=T, level=2, if so:
              Seek until open=F level=2 idx=y
              if y+1 exists with open=F, level=1:
                  delete from x to y, inclusive



*/


enum NextThing {NtInvalid=1, NtOpen=2, NtClose=3};

typedef std::tuple<size_t, bool, unsigned> ParenInfo;
typedef std::vector<ParenInfo> ParensInfo;

// figure out paren info for this string.
ParensInfo getParens(std::string sourceString) {
    size_t searchLoc = 0;
    unsigned level = 0;
    ParensInfo parens;
    while (true) {
        size_t nextOpen = sourceString.find("(", searchLoc);
        size_t nextClose = sourceString.find(")", searchLoc);

        NextThing nt = NtInvalid;
        if (nextOpen != std::string::npos && nextClose != std::string::npos) {
            debug(PARENS) << "Both in bounds\n";
            if (nextOpen < nextClose) nt = NtOpen;
            else nt = NtClose;
        } else {
            debug(PARENS) << "One/neither in bounds\n";
            if (nextOpen != std::string::npos) nt = NtOpen;
            else if (nextClose != std::string::npos) nt = NtClose;
        }

        if (nt == NtInvalid) break;
        size_t nextLoc;
        debug(PARENS) << "NT is " << ((nt==NtOpen)?"(":")") << "\n";
        ParenInfo pt;
        switch (nt) {
            case NtOpen:
                nextLoc = nextOpen;
                level++;
                pt = std::make_tuple(nextLoc, true, level);
                break;
            case NtClose:
                nextLoc = nextClose;
                pt = std::make_tuple(nextLoc, false, level);
                level--;
                break;
            default:
                assert(false); // should not happen
        }
        parens.push_back(pt);
        searchLoc = nextLoc + 1;
    }
    debug(PARENS) << sourceString << "\n";
    unsigned l = parens.size();
    if (l > 0) {
        std::string ws;
        if (sourceString.find("__attribute__") != std::string::npos) {
remove_attributes:
            for (auto p : parens) {
                ws = "";
                for (size_t i = 0; i < std::get<0>(p); i++) ws += " ";
                debug(PARENS) << ws << "| paren " << std::get<0>(p)
                              << " " << std::get<1>(p)
                              << " " << std::get<2>(p) << "\n";
            }

            for (auto oparen = parens.begin(); oparen != parens.end(); ++oparen) {
                unsigned int o_idx = std::get<0>(*oparen);
                bool o_open = std::get<1>(*oparen);
                unsigned int o_level = std::get<2>(*oparen);

                if (o_level != 1 || !o_open) continue;
                if ((oparen + 1) == parens.end()) continue;

                auto oparen2 = oparen + 1;
                if (std::get<0>(*oparen2) == o_idx + 1 && std::get<1>(*oparen2)) {
                    debug(PARENS) << "\tFound set of adjacent open parens at " << o_idx << "\n";

                    for (auto cparen = oparen2; cparen != parens.end(); ++cparen) {
                        unsigned int c_idx = std::get<0>(*cparen);
                        bool c_open = std::get<1>(*cparen);
                        unsigned int c_level = std::get<2>(*cparen);
                        if (!c_open && c_level == 2) {
                            debug(PARENS) << "\tFound first close paren at " << c_idx << "\n";
                            if ((cparen + 1) == parens.end()) continue;

                            auto cparen2 = cparen + 1;
                            if (std::get<0>(*cparen2) == c_idx + 1 && !std::get<1>(*cparen2)) {
                                debug(PARENS) << ("\tFOUND ((...)) pair, removing\n");
                                parens.erase(oparen, cparen2 + 1);
                                goto remove_attributes;
                            }
                            break;
                        }
                    }
                }
            }
        }

        ParenInfo &cp = parens[l - 1];
        ParenInfo &op = parens[0];
        if (std::get<1>(op) == true && std::get<1>(cp) == false) {
            if (std::get<2>(op) == 1 && std::get<2>(cp) == 1) {
                // good
            } else {
                debug(PARENS) << "Clearing parens since levels of open/close aren't both 1\n";
                parens.clear();
            }
        } else {
            debug(PARENS) << "Clearing parens since we don't have op/close as first/last\n";
            parens.clear();
        }
    }
    return parens;
}

std::string createNonNullTests(std::string sourceString) {
    ParensInfo parens = getParens(sourceString);
    debug(PARENS) << "nntest [" << sourceString << "]\n";
    size_t curr = 0;
    size_t len = parens.size();
    std::string tests = "";
    while (true) {
        unsigned i_open;
        bool found = false;
        for (i_open = curr; i_open < parens.size(); i_open++) {
            if (std::get<1>(parens[i_open])) {
                found = true;
                break;
            }
        }

        if (!found) break;
        ParenInfo oinfo = parens[i_open];
        size_t opos = std::get<0>(oinfo);
        unsigned olevel = std::get<2>(oinfo);
        unsigned i_close;
        found = false;
        for (i_close = i_open + 1; i_close < parens.size(); i_close++) {
            bool isopen = std::get<1>(parens[i_close]);
            unsigned level = std::get<2>(parens[i_close]);
            if (!isopen && level == olevel) {
                found = true;
                break;
            }
        }
        if (!found) break;
        ParenInfo cinfo = parens[i_close];
        size_t cpos = std::get<0>(cinfo);
        std::string cand = sourceString.substr(opos, cpos - opos + 1);
        unsigned num_stars = 1;
        for (num_stars = 1; num_stars < cand.size(); num_stars++)
            if (cand[num_stars] != '*') break;
        num_stars--;
        if (num_stars > 0) {
            debug(PARENS) << "cand = [" << cand << "]\n";
            debug(PARENS) << "num_stars = " << num_stars << "\n";
            for (unsigned i = 0; i < num_stars; i++) {
                size_t start = i + 2;
                size_t len = cand.size() - start - 1;
                debug(PARENS) << "start = " << start << " len = " << len << "\n";
                std::string test = " (" + (cand.substr(start, len)) + ")";
                if (tests.size() == 0)
                    tests = test;
                else
                    tests = test + " && " + tests;
            }
        }

        curr++;
    }
    return tests;
}

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

SourceLocation getLocAfterStr(const SourceManager &sm, SourceLocation &loc, const char *str, unsigned str_len, unsigned max_search, bool *inv) {
    const char *buf = sm.getCharacterData(loc, inv);
    if (*inv) {
        return loc;
    }
    debug(PARENS) << "getCharacterData succeeded\n";
    const char *p = strstr(buf, str);
    if (p == NULL) {
        *inv = true;
        return loc;
    }
    *inv = false;
    return loc.getLocWithOffset(p - buf);
}

int srcLocCmp(const SourceManager &sm, SourceLocation &l1, SourceLocation &l2) {
    unsigned o1 = sm.getFileOffset(l1);
    unsigned o2 = sm.getFileOffset(l2);
    if (o1 < o2) return SCMP_LESS;
    if (o1 > o2) return SCMP_GREATER;
    return SCMP_EQUAL;
}

typedef std::tuple<SourceLocation, bool, unsigned> SLParenInfo;
typedef std::vector<SLParenInfo> SLParensInfo;

SLParensInfo SLgetParens(const SourceManager &sm, SourceLocation &l1, SourceLocation &l2) {
    SLParensInfo slparens;
    bool inv;
    std::string sourceStr = getStringBetweenRange(sm, SourceRange(l1, l2), &inv);
    debug(GENERAL) << "SLgetParens sourceStr = [" << sourceStr << "]\n";
    if (inv) {
        debug(GENERAL) << "Invalid\n";
    } else {
        ParensInfo parens = getParens(sourceStr);
        for (auto paren : parens) {
            size_t pos = std::get<0>(paren);
            bool isopen = std::get<1>(paren);
            unsigned level = std::get<2>(paren);
            debug(GENERAL) << "Found paren pair open=" << isopen << ", level=" << level << "\n";
            SourceLocation sl = l1.getLocWithOffset(pos);
            SLParenInfo slparen = std::make_tuple(sl, isopen, level);
            slparens.push_back(slparen);
        }
    }
    return slparens;
}