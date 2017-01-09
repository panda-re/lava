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
        STR, HEX, DECIMAL, BINOP, FUNC, BLOCK, IF, CAST, INDEX, ASM
    } t;

    uint32_t value;
    std::string str;
    std::vector<std::shared_ptr<LExpr>> args;
    std::vector<std::string> instrs;

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
            os << "((" << expr.str << ")" << *expr.args.at(0) << ")";
        } else if (expr.t == LExpr::INDEX) {
            os << *expr.args.at(0) << "[" << expr.value << "]";
        } else if (expr.t == LExpr::ASM) {
            os << "__asm__(";
            ::infix(expr.instrs.cbegin(), expr.instrs.cend(), os,
                    "\"", "\\n\\t", "\"");
            os << " : : ";
            expr.infix(os, "\"rm\" (", "), \"rm\" (", ")");
            os << ")";
        } else { assert(false && "Bad expr!"); }

        return os;
    }
};

LExpr LStr(std::string str) {
    return LExpr(LExpr::STR, 0, str, {});
}

LExpr LHex(uint32_t value) {
    return LExpr(LExpr::HEX, value, "", {});
}

LExpr LDecimal(uint32_t value) {
    return LExpr(LExpr::DECIMAL, value, "", {});
}

// Binary operator.
LExpr LBinop(std::string op, LExpr left, LExpr right) {
    return LExpr(LExpr::BINOP, 0, op, { left, right });
}

LExpr LBinop(std::string op, std::vector<LExpr> args) {
    size_t len = args.size();
    if (len == 0) {
        if (op == "+") return LDecimal(0);
        else if (op == "*") return LDecimal(1);
        else assert(false);
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

LExpr LIf(std::string cond, std::vector<LExpr> stmts) {
    return LExpr(LExpr::IF, 0, cond, stmts);
}

LExpr LIf(std::string cond, LExpr stmt) {
    return LExpr(LExpr::IF, 0, cond, { stmt });
}

LExpr LCast(std::string type, LExpr value) {
    return LExpr(LExpr::CAST, 0, type, { value });
}

LExpr LIndex(LExpr array, uint32_t index) {
    return LExpr(LExpr::INDEX, index, "", { array });
}

LExpr LAsm(std::initializer_list<LExpr> args,
        std::initializer_list<std::string> instrs) {
    return LExpr(LExpr::ASM, 0, "", args, instrs);
}

LExpr LavaGet(uint64_t val) {
    return LFunc("lava_get", { LDecimal(val) });
}

LExpr LavaGet(const Bug *bug) { return LavaGet(bug->trigger_lval->id); }
LExpr LavaGet(const Dua *dua) { return LavaGet(dua->lval->id); }
LExpr LavaGet(const SourceLval *lval) { return LavaGet(lval->id); }

LExpr UCharCast(LExpr arg) {
    return LCast("unsigned char *", arg);
}

LExpr LavaSet(const Bug *bug) {
    const std::vector<uint32_t> &offsets = bug->selected_bytes;
    const std::string &lval_name = bug->trigger_lval->ast_name;

    std::vector<LExpr> or_args;
    for (auto it = offsets.cbegin(); it != offsets.cend(); it++) {
        LExpr shift = LDecimal((it - offsets.cbegin()) * 8);
        or_args.push_back(
                LIndex(UCharCast(LStr(lval_name)), *it) << shift);
    }
    return LFunc("lava_set", { LDecimal(bug->trigger_lval->id),
            LBinop("|", or_args) });
}

template<typename UInt>
UInt BSwap(UInt x);

template<>
uint32_t BSwap<uint32_t>(uint32_t x) { return __builtin_bswap32(x); }
template<>
uint16_t BSwap<uint16_t>(uint16_t x) { return __builtin_bswap16(x); }

template<typename UInt>
LExpr MagicTest(UInt magic_value, LExpr maskedLavaGet) {
    return LHex(magic_value) == maskedLavaGet ||
        LHex(BSwap<UInt>(magic_value)) == maskedLavaGet;
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
