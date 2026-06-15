#ifndef INSERTIONS_H
#define INSERTIONS_H

#include "clang/AST/AST.h"
#include "clang/Lex/Lexer.h"

#include "clang/Tooling/Tooling.h"
#include "clang/Tooling/ReplacementsYaml.h"

using namespace clang;
using namespace clang::tooling;
/*
 * Keeps track of a list of insertions and makes sure conflicts are resolved.
 */
class Insertions {
private:
    // TODO: use map and "beforeness" concept to robustly avoid duplicate
    // insertions.
    std::map<SourceLocation, std::list<std::string>> impl;

public:
    void clear() { impl.clear(); }

    void InsertAfter(SourceLocation loc, std::string str) {
        if (!str.empty()) {
            std::list<std::string> &strs = impl[loc];
            if (strs.empty() || strs.back() != str || str == ")") {
                impl[loc].push_back(str);
            }
        }
    }

    void InsertBefore(SourceLocation loc, std::string str) {
        if (!str.empty()) {
            std::list<std::string> &strs = impl[loc];
            if (strs.empty() || strs.front() != str || str == "(") {
                impl[loc].push_front(str);
            }
        }
    }

    void render(const SourceManager &sm, std::vector<Replacement> &out) {
        out.reserve(impl.size() + out.size());
        for (const auto &keyvalue : impl) {
            // Introduce Some ordering here
            std::stringstream ss1, ss2, ss3;
            for (const std::string &s : keyvalue.second) {
                if (s.find("int lava_chaff_var") == 0) {
                    ss1 << s;
                } else if (s.find("int lava_chaff") == 0) {
                    ss2 << s;
                } else {
                    ss3 << s;
                }
            }
            out.emplace_back(sm, keyvalue.first, 0, ss1.str() + ss2.str() + ss3.str());
        }
    }
};

#endif
