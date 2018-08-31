
#include <cassert>
#include <iostream>
#include <tuple>
#include <vector>

using namespace std;


#include "clang/AST/AST.h"
#include "clang/Driver/Options.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/Lexer.h"



using namespace clang;
//using namespace clang::ast_matchers;
using namespace clang::driver;
using namespace llvm;

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

  Ugh!  This is obviously an elegant solution to a ridiculous problem
  created either by Clang or my naive understanding of it.  We can't
  reliably find the source location of the start of the arg or param
  list.  So we use this to find it in the string and then map back to
  SourceLocations in SLgetParens.
*/


enum NextThing {NtInvalid=1, NtOpen=2, NtClose=3};

// This tuple is
// position in string (unsigned)
// isOpenParen        (bool)
// level              (unsigned) 
typedef std::tuple < size_t, bool, unsigned > ParenInfo ;

typedef std::vector < ParenInfo > ParensInfo;

// figure out paren info for this string.  
ParensInfo getParens(std::string sourceString) {
    
    size_t searchLoc = 0;
    unsigned level = 0;
    ParensInfo parens;
    while (true) {
        size_t nextOpen = sourceString.find("(", searchLoc);
        size_t nextClose = sourceString.find(")", searchLoc);
        NextThing nt = NtInvalid;
        if (nextOpen != std::string::npos 
            && nextClose != std::string::npos) {
            // both are in bounds so we can compare them
            // the next one is whichever comes first
            if (nextOpen < nextClose) nt = NtOpen;
            else nt = NtClose;
        }
        else {
            // one or neither is in bounds
            // whever is in bounds is next one
            if (nextOpen != std::string::npos) nt = NtOpen;
            else if (nextClose != std::string::npos) nt = NtClose;
        }
        ParenInfo pt;
        // no valid next open or close -- exit loop
        if (nt == NtInvalid) break;
        size_t nextLoc;
        switch (nt) {
        case NtOpen:
            // '(' is next thing
            nextLoc = nextOpen;
            level ++;
            pt = std::make_tuple(nextLoc, true, level);
            break;
        case NtClose:
            // ')' is next thing
            nextLoc = nextClose;
            pt = std::make_tuple(nextLoc, false, level);
            level --;
            break;
        default:
            assert (1==0); // should not happen
        }
        // collect the tuples 
        parens.push_back(pt);
        searchLoc = nextLoc+1;
    }
    std::cout << sourceString << "\n";
    for (auto p : parens) 
        std::cout << "paren " << std::get<0>(p)
                  << " " << std::get<1>(p)
                  << " " << std::get<2>(p) << "\n";

    unsigned l = parens.size();
    if (l==0) {
        std::cout << "Hmm.  No parens at all\n";
    }
    else {
        std::cout << "There are parens\n";
        ParenInfo &cp = parens[l-1];
        ParenInfo &op = parens[0];
        if (std::get<1>(op) == true && std::get<1>(cp) == false) {
            // first is open and last is close
            if (std::get<2>(op) == 1 && std::get<2>(cp) == 1) {
                // and both are level 1 -- good
            }
            else {
                std::cout << "Clearing parens since levels of open/close arent both 1\n";
                parens.clear();
            }       
        }    
        else {
            std::cout << "Clearing parens since we dont have op/close as first/last\n";
            parens.clear();
        }       
    }
    return parens;
}


/*
  This one is really our fault.  We have the string-ified version of
  the ast node that is an lval we want to siphon off as a dua.  This
  comes from libdwarf, by way of the pri magic in PANDA.  This means
  we can get something like

  ((*((**(pdtbl)).pub)).sent_table))

  Before we siphon that dua off, we need to test the various ptrs that
  will end up getting dereferenced to make sure they aren't null.  So 
  we use getparens to find the balanced parens, and then consider each to
  see if it starts wit '(*' or '(**' or ..  And if so, we add checks to
  ensure that ptrs are non-null

  So, for this example, we want

  if (pdtbl && *pdtbl && ((**(pdtbl)).pub)) {...}

  This, too, is reprehensible.  But, gotta get things to work.  Not
  sorry.  Right solution would be to have pri figure this out?

*/

std::string createNonNullTests(std::string sourceString) {
    ParensInfo parens = getParens(sourceString);
    size_t curr = 0;
    size_t len = parens.size();
    std::string tests = "";
    while (true) {
        unsigned i_open;
        bool found = false;
        for (i_open=curr; i_open<parens.size(); i_open++) {
            if (std::get<1>(parens[i_open])) 
                // found next open
                found = true;
                break;
        }
        if (!found) break;
        ParenInfo oinfo = parens[i_open];
        size_t opos = std::get<0>(oinfo);
        unsigned olevel = std::get<2>(oinfo);
        unsigned i_close;
        found = false;
        for (i_close=i_open+1; i_close<parens.size(); i_close++) {
            bool isopen = std::get<1>(parens[i_close]);
            size_t level = std::get<2>(parens[i_close]);
            if (!isopen && level == olevel) {
                // found first close after that open
                // which is at same level
                found = true;
                break;
            }
        }
        if (!found) break;
        ParenInfo cinfo = parens[i_close];
        size_t cpos = std::get<0>(cinfo);
        std::string cand = sourceString.substr(opos, cpos-opos+1);
        // (**(pdtbl))
        unsigned num_stars=1;
        for (num_stars=1; num_stars<cand.size(); num_stars++)
            if (cand[num_stars] != '*') break;
        num_stars--;
        if (num_stars > 0) {
            std::cout << "cand = [" << cand << "]\n";
            std::cout << "num_stars = " << num_stars << "\n";
            for (unsigned i=0; i<num_stars; i++) {
                size_t start = i+2;
                size_t len = cand.size() - start - 1;
                std::cout << "start = " << start << " len = " << len << "\n";                
                std::string test = " (" + (cand.substr(start, len)) + ")";
                if (tests.size() == 0) 
                    tests = test;
                else 
                    tests = test + " && " + tests;
            }
        }

        curr ++;
    }
    return tests;
            
}



std::string getStringBetween(const SourceManager &sm, SourceLocation &l1, SourceLocation &l2, bool *inv) {
    const char *buf = sm.getCharacterData(l1, inv);
    unsigned o1 = sm.getFileOffset(l1);
    unsigned o2 = sm.getFileOffset(l2);
    if (*inv)
        return std::string("");
    return (std::string(buf, o2-o1+1));
}



// find location of str after loc
// sets *inv=true if something went wrong or we didnt find

SourceLocation getLocAfterStr(const SourceManager &sm, SourceLocation &loc, const char *str, unsigned str_len, unsigned max_search, bool *inv) {
    const char *buf = sm.getCharacterData(loc, inv);
    if (!(*inv)) {
        // getCharacterData succeeded
        const char *p = buf;
        *inv = true;
        while (true) {
            if (0 == strncmp(p, str, str_len)) {
                // found the str in the source
                *inv = false;
                break;
            }
            p++;
            if (p-buf > max_search) 
                break;
        }
        if (!(*inv)) {
            unsigned pos = p - buf;
            //debug(FNARG) << "Found [" << str << "] @ " << pos << "\n";
            std::string uptomatch = std::string(buf, str_len + pos);
            //debug(FNARG) << "uptomatch: [" << uptomatch << "]\n";
            return loc.getLocWithOffset(str_len + pos);
        }
    }
    return loc;
}            
           
        


// comparison of source locations based on file offset
// XXX better to make sure l1 and l2 in same file? 
int srcLocCmp(const SourceManager &sm, SourceLocation &l1, SourceLocation &l2) {
    unsigned o1 = sm.getFileOffset(l1);
    unsigned o2 = sm.getFileOffset(l2);
    if (o1<o2) return SCMP_LESS;
    if (o1>o2) return SCMP_GREATER;
    return SCMP_EQUAL;
}


typedef std::tuple < SourceLocation, bool, unsigned > SLParenInfo ;

typedef std::vector < SLParenInfo > SLParensInfo;

/*
  returns a vector of paren info tuples in terms of SourceLocation instead of 
  position in a string
*/

SLParensInfo SLgetParens(const SourceManager &sm, SourceLocation &l1, 
                         SourceLocation &l2) {

    SLParensInfo slparens;
    bool inv;
    std::string sourceStr = getStringBetween(sm, l1, l2, &inv);
    if (inv) {
        std::cout << "Invalid\n";
    }
    else {
        ParensInfo parens = getParens(sourceStr);
        for (auto paren : parens) {
            size_t pos = std::get<0>(paren);      
            unsigned isopen = std::get<1>(paren);
            unsigned level = std::get<2>(paren);
            SourceLocation sl = l1.getLocWithOffset(pos);
            SLParenInfo slparen = std::make_tuple(sl, isopen, level);
            slparens.push_back(slparen);
        }
    }
    return slparens;
}

