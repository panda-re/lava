#ifndef INSERTIONS_H
#define INSERTIONS_H

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
            std::stringstream ss;
            for (const std::string &s : keyvalue.second) ss << s;
            out.emplace_back(sm, keyvalue.first, 0, ss.str());
        }
    }
};

#endif
