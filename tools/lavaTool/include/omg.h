#ifndef LAVA_OMG_CLANG_H_
#define LAVA_OMG_CLANG_H_


// This tuple is
// position in string (unsigned)
// isOpenParen        (bool)
// level              (unsigned)
typedef std::tuple < size_t, bool, unsigned > ParenInfo ;

typedef std::vector < ParenInfo > ParensInfo;

// figure out paren info for this string.
ParensInfo getParens(std::string sourceString);

// figure out non-null checks for this string
// which is assumed to contain 0 or more ptr dereferences
std::string createNonNullTests(std::string sourceString);

// returns the source string between a range location
std::string getStringBetweenRange(const SourceManager &sm,
                             SourceRange range, bool *inv);

// returns the source string between these two source locations
// note: *inv is set true if this fails
std::string getStringBetween(const SourceManager &sm,
                             SourceLocation &l1, SourceLocation &l2, bool *inv);

// this is what I wanted Lexer::findLocationAfterToken to do.  Well,
// this is actually a little better.  We search the code, starting at
// loc, to find the first location at which the string 'str' exists.
// Then return a SourceLocation that is immediately after that.
SourceLocation getLocAfterStr(const SourceManager &sm, SourceLocation &loc,
                              const char *str, unsigned str_len,
                              unsigned max_search, bool *inv);



#define SCMP_LESS (-1)
#define SCMP_EQUAL (0)
#define SCMP_GREATER (+1)

// Compares two source locations
int srcLocCmp(const SourceManager &sm, SourceLocation &l1, SourceLocation &l2);

typedef std::tuple < SourceLocation, bool, unsigned > SLParenInfo ;

typedef std::vector < SLParenInfo > SLParensInfo;

// Uses getparens and then re-casts result in terms of source
// locations
SLParensInfo SLgetParens(const SourceManager &sm,
                         SourceLocation &l1,
                         SourceLocation &l2);




#endif
