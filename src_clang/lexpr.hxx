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
        ASSIGN
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
            expr.infix(os, "({", "; ", ";})");
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
            os << "[" << expr.value << "]";
        } else if (expr.t == LExpr::ASM) {
            os << "__asm__(";
            ::infix(expr.instrs.cbegin(), expr.instrs.cend(), os,
                    "\"", "\\n\\t", "\"");
            os << " : : ";
            expr.infix(os, "\"rm\" (", "), \"rm\" (", ")");
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

LExpr LavaGet(uint64_t val) {
    return LFunc("lava_get", { LDecimal(val) });
}

LExpr LavaGet(const DuaBytes *dua_bytes) { return LavaGet(dua_bytes->id); }
LExpr LavaGet(const Bug *bug) { return LavaGet(bug->trigger); }

LExpr DataFlowGet(uint64_t val) {
    return LDeref(LStr("data_flow"));
}

LExpr DataFlowGet(const DuaBytes *dua_bytes) { return DataFlowGet(dua_bytes->id); }
LExpr DataFlowGet(const Bug *bug) { return DataFlowGet(bug->trigger); }

LExpr UCharCast(LExpr arg) { return LCast("const unsigned char *", arg); }
LExpr UIntCast(LExpr arg) { return LCast("const unsigned int *", arg); }

LExpr SelectCast(const DuaBytes *dua_bytes) {
    const std::string &lval_name = dua_bytes->dua->lval->ast_name;
    Range selected = dua_bytes->selected;
    assert(selected.size() == 4);

    LExpr pointer = selected.low % 4 == 0
        ? UIntCast(LStr(lval_name)) + LDecimal(selected.low / 4)
        : UIntCast(UCharCast(LStr(lval_name)) + LDecimal(selected.low));
    return LDeref(pointer);
}

LExpr LavaSet(const DuaBytes *dua_bytes) {
    return LFunc("lava_set", { LDecimal(dua_bytes->id), SelectCast(dua_bytes) });
}

LExpr DataFlowSet(const DuaBytes *dua_bytes) {
    return LAssign(LDeref(LStr("data_flow")), SelectCast(dua_bytes));
}

template<typename UInt>
LExpr MagicTest(UInt magic_value, LExpr maskedLavaGet) {
    return LHex(magic_value) == maskedLavaGet;
}

LExpr MagicTest(const Bug *bug) {
    return MagicTest(bug->magic(), LavaGet(bug));
}

// RangeTest and rangeStyleAttack are currently unused, but they're good examples of
// how to use LExpr's.
LExpr RangeTest(uint32_t magic_value, uint32_t range_size, LExpr value) {
    return LHex(magic_value - range_size) < value &&
        value < LHex(magic_value + range_size);
}

template<uint32_t num_bits>
LExpr rangeStyleAttack(const Bug *bug) {
    return LavaGet(bug) * (RangeTest(bug->magic(), 1U << num_bits, LavaGet(bug)) ||
        RangeTest(__builtin_bswap32(bug->magic()), 1U << num_bits, LavaGet(bug)));
}

#endif
