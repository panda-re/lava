#pragma once

#include <json/json.h>
#include <istream>
#include <stdexcept>
#include <string>

// Frame one object from a standard JSON array; JsonCpp still parses its contents.
// Only the current entry is buffered, including strings with escaped delimiters.
class PandalogJsonReader {
public:
    explicit PandalogJsonReader(std::istream& input) : input_(input) {
        if (take() != '[') fail("expected a top-level array");
    }

    bool next(Json::Value& entry) {
        if (finished_) return false;
        int ch = take();
        if (first_ && ch == ']') return finish();
        if (!first_) {
            if (ch == ']') return finish();
            if (ch != ',') fail("expected ',' or ']' after entry");
            ch = take();
        }
        if (ch != '{') fail("expected a pandalog object");
        first_ = false;
        std::string text(1, '{');
        size_t depth = 1;
        bool in_string = false;
        bool escaped = false;
        while (depth != 0) {
            ch = input_.get();
            if (ch == std::char_traits<char>::eof()) fail("truncated entry");
            text.push_back(static_cast<char>(ch));
            if (in_string) {
                if (escaped) escaped = false;
                else if (ch == '\\') escaped = true;
                else if (ch == '"') in_string = false;
            } else {
                if (ch == '"') in_string = true;
                else if (ch == '{' || ch == '[') ++depth;
                else if (ch == '}' || ch == ']') --depth;
            }
        }
        Json::Reader parser;
        if (!parser.parse(text, entry)) {
            throw std::runtime_error("Invalid pandalog entry: " + parser.getFormattedErrorMessages());
        }
        return true;
    }

private:
    int take() {
        int ch;
        do {
            ch = input_.get();
        } while (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n');
        if (input_.bad() || (input_.fail() && !input_.eof())) fail("read failure");
        return ch;
    }

    bool finish() {
        if (take() != std::char_traits<char>::eof()) fail("data after top-level array");
        finished_ = true;
        return false;
    }

    [[noreturn]] static void fail(const char* message) {
        throw std::runtime_error(std::string("Invalid pandalog JSON: ") + message);
    }

    std::istream& input_;
    bool first_ = true;
    bool finished_ = false;
};
