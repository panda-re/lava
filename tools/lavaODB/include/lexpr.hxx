#ifndef _LEXPR_HXX
#define _LEXPR_HXX

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

template<typename InputIt>
static void infix(InputIt first, InputIt last, std::ostream &os,
        std::string begin, std::string sep, std::string end) {
    InputIt it = first;
    os << begin;
    for (; it != last - 1; it++) {
        os << *it << sep;
    }
    os << *it << end;
}

struct LExpr {
    enum Type {
        STR, HEX, DECIMAL, BINOP, FUNC, BLOCK, IF, CAST, INDEX, ASM, DEREF,
        ASSIGN, IFDEF
    } t;

    uint32_t value;
    std::string str;
    std::vector<std::shared_ptr<LExpr>> args;
    std::vector<std::string> instrs;

    LExpr(Type t, uint32_t value, std::string str)
        : t(t), value(value), str(str) {}

    LExpr(Type t, uint32_t value, std::string str,
            std::initializer_list<std::shared_ptr<LExpr>> args)
        : t(t), value(value), str(str), args(args) {}

    LExpr(Type t, uint32_t value, std::string str,
            std::initializer_list<LExpr> init_args,
            std::initializer_list<std::string> instrs)
        : t(t), value(value), str(str), instrs(instrs) {
        for (const LExpr &arg : init_args) {
            args.emplace_back(new LExpr(arg));
        }
    }

    LExpr(Type t, uint32_t value, std::string str,
            std::initializer_list<LExpr> init_args)
        : LExpr(t, value, str, init_args, {}) {}

    LExpr(Type t, uint32_t value, std::string str,
            std::vector<LExpr> init_args)
        : t(t), value(value), str(str) {
        for (const LExpr &arg : init_args) {
            args.emplace_back(new LExpr(std::move(arg)));
        }
    }

    std::string render() const {
        std::stringstream os;
        os << *this;
        return os.str();
    }

    void infix(std::ostream &os, std::string begin, std::string sep, std::string end) const {
        auto it = args.cbegin();
        os << begin;
        if (args.size() == 0) {
            os << end;
            return;
        }
        for (; it != args.cend() - 1; it++) {
            os << **it << sep;
        }
        os << **it << end;
    }

    friend std::ostream &operator<<(std::ostream &os, const LExpr &expr) {
        if (expr.t == STR) {
            os << expr.str;
        } else if (expr.t == LExpr::HEX) {
            os << "0x" << std::hex << expr.value;
        } else if (expr.t == LExpr::DECIMAL) {
            os << std::dec << expr.value;
        } else if (expr.t == LExpr::BINOP) {
            expr.infix(os, "(", " " + expr.str + " ", ")");
        } else if (expr.t == LExpr::FUNC) {
            os << expr.str;
            expr.infix(os, "(", ", ", ")");
        } else if (expr.t == LExpr::BLOCK) {
            expr.infix(os, "{", "; ", ";}");
        } else if (expr.t == LExpr::IF) {
            os << "if (" << expr.str << ") ";
            expr.infix(os, "{\n", ";\n", ";\n}\n");
        } else if (expr.t == LExpr::CAST) {
            // Careful about precedence. Only problem is (CAST)INDEX[0].
            os << "(" << expr.str << ")" << *expr.args.at(0);
        } else if (expr.t == LExpr::INDEX) {
            // In ((CAST)X)[0], add extra parens.
            const LExpr &arg = *expr.args.at(0);
            if (arg.t == LExpr::CAST) os << "(";
            os << arg;
            if (arg.t == LExpr::CAST) os << ")";
            os << "[" << std::dec << expr.value << "]";
        } else if (expr.t == LExpr::IFDEF) {
            os << "\n#ifdef " << expr.str;
            expr.infix(os, "\n", "\n#else\n", "\n#endif\n");
        } else if (expr.t == LExpr::ASM) {
            os << "__asm__(";
            ::infix(expr.instrs.cbegin(), expr.instrs.cend(), os,
                    "\"", "\\n\\t", "\"");
            os << " : : ";
            expr.infix(os, "\"r\" (", "), \"r\" (", ")");
            os << ")";
        } else if (expr.t == LExpr::DEREF) {
            os << '*' << *expr.args.at(0);
        } else if (expr.t == LExpr::ASSIGN) {
            os << *expr.args.at(0) << " = " << *expr.args.at(1);
        } else { assert(false && "Bad expr!"); }

        return os;
    }
};

LExpr LStr(std::string str) {
    return LExpr(LExpr::STR, 0, str);
}

LExpr LHex(uint32_t value) {
    return LExpr(LExpr::HEX, value, "");
}

LExpr LDecimal(uint32_t value) {
    return LExpr(LExpr::DECIMAL, value, "");
}

// Binary operator.
LExpr LBinop(std::string op, LExpr left, LExpr right) {
    if (op == "+"
            && (right.t == LExpr::DECIMAL || right.t == LExpr::HEX)
            && right.value == 0) {
        return left;
    }
    return LExpr(LExpr::BINOP, 0, op, { left, right });
}

LExpr LBinop(std::string op, std::vector<LExpr> args) {
    size_t len = args.size();
    if (len == 0) {
        if (op == "+") return LDecimal(0);
        else if (op == "*") return LDecimal(1);
        else { assert(false); return LStr(""); }
    } else if (len == 1) {
        return args.front();
    } else {
        return LExpr(LExpr::BINOP, 0, op, std::move(args));
    }
}

LExpr operator-(LExpr us, LExpr other) { return LBinop("-", us, other); }
LExpr operator+(LExpr us, LExpr other) { return LBinop("+", us, other); }
LExpr operator*(LExpr us, LExpr other) { return LBinop("*", us, other); }
LExpr operator==(LExpr us, LExpr other) { return LBinop("==", us, other); }
LExpr operator&&(LExpr us, LExpr other) { return LBinop("&&", us, other); }
LExpr operator||(LExpr us, LExpr other) { return LBinop("||", us, other); }
LExpr operator>>(LExpr us, LExpr other) { return LBinop(">>", us, other); }
LExpr operator<<(LExpr us, LExpr other) { return LBinop("<<", us, other); }
LExpr operator&(LExpr us, LExpr other) { return LBinop("&", us, other); }
LExpr operator|(LExpr us, LExpr other) { return LBinop("|", us, other); }
LExpr operator<(LExpr us, LExpr other) { return LBinop("<", us, other); }
LExpr operator^(LExpr us, LExpr other) { return LBinop("^", us, other); }
LExpr operator%(LExpr us, LExpr other) { return LBinop("%", us, other); }

LExpr LBlock(std::initializer_list<LExpr> stmts) {
    return LExpr(LExpr::BLOCK, 0, "", stmts);
}

LExpr LFunc(std::string name, std::initializer_list<LExpr> args) {
    return LExpr(LExpr::FUNC, 0, name, args);
}

LExpr LIf(std::string cond, std::initializer_list<LExpr> stmts) {
    return LExpr(LExpr::IF, 0, cond, stmts);
}

LExpr LIf(std::string cond, LExpr stmt) {
    return LExpr(LExpr::IF, 0, cond, { stmt });
}

LExpr LIfDef(std::string cond, std::initializer_list<LExpr> stmts) {
    return LExpr(LExpr::IFDEF, 0, cond, stmts);
}

LExpr LCast(std::string type, LExpr value) {
    if (value.t == LExpr::CAST) {
        // Casting twice is a no-op.
        return LExpr(LExpr::CAST, 0, type, { value.args[0] });
    } else {
        return LExpr(LExpr::CAST, 0, type, { value });
    }
}

LExpr LIndex(LExpr array, uint32_t index) {
    return LExpr(LExpr::INDEX, index, "", { array });
}

LExpr LAsm(std::initializer_list<LExpr> args,
        std::initializer_list<std::string> instrs) {
    return LExpr(LExpr::ASM, 0, "", args, instrs);
}

LExpr LDeref(LExpr ptr) {
    return LExpr(LExpr::DEREF, 0, "", { ptr });
}

LExpr LAssign(LExpr left, LExpr right) {
    return LExpr(LExpr::ASSIGN, 0, "", { left, right });
}

LExpr LavaGet(uint32_t slot) {
    return LFunc("lava_get", { LDecimal(slot) });
}

LExpr LavaGetExtra(uint32_t slot) {
    return LFunc("lava_get_extra", { LDecimal(slot) });
}

LExpr DataFlowGet(uint32_t slot) {
    return LIndex(LStr("data_flow"), slot);
}

LExpr LRandomBytes(std::string base, uint32_t len) {
    std::string randstr = base.substr(rand() % (base.length() - len), len);
    return LStr("\"" + randstr + "\"");
}

LExpr UCharCast(LExpr arg) { return LCast("const unsigned char *", arg); }
LExpr UIntCast(LExpr arg) { return LCast("const unsigned int *", arg); }

LExpr SelectCast(const SourceLval *lval, Range selected) {
    const std::string &lval_name = lval->ast_name;
    assert(selected.size() >= 4); // Maybe too specific?

    LExpr pointer = selected.low % 4 == 0
        ? UIntCast(LStr(lval_name)) + LDecimal(selected.low / 4)
        : UIntCast(UCharCast(LStr(lval_name)) + LDecimal(selected.low));
    return LDeref(pointer);
}

LExpr LavaSet(const SourceLval *lval, Range selected, uint32_t slot) {
    return LBlock({LFunc("lava_set", { LDecimal(slot), SelectCast(lval, selected) })});
}

LExpr LavaSetExtra(const SourceLval *lval, Range selected, uint32_t slot) {
    return LBlock({LFunc("lava_set_extra", { LDecimal(slot), SelectCast(lval, selected) })});
}

LExpr DataFlowSet(const SourceLval *lval, Range selected, uint32_t slot) {
    return LFunc("DFLOG", { LDecimal(slot), SelectCast(lval, selected) });
}

template<typename UInt>
LExpr MagicTest(UInt magic_value, LExpr maskedLavaGet) {
    return LHex(magic_value) == maskedLavaGet;
}

template<LExpr Get(const Bug *)>
LExpr MagicTest(const Bug *bug) {
    return MagicTest(bug->magic, Get(bug));
}

#endif
