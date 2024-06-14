#ifndef LAVATOOL_H
#define LAVATOOL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <map>
#include <set>
#include <vector>
#include <string>
#include <memory>
#include <cstdint>
#include <cassert>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iterator>
#include <execinfo.h>

extern "C" {
#include <unistd.h>
#include <libgen.h>
}

#include <json/json.h>
#include <odb/pgsql/database.hxx>

#include "clang/AST/AST.h"
#include "clang/Lex/Lexer.h"
#include "clang/Driver/Options.h"
#include "clang/Frontend/CompilerInstance.h"

#include "clang/Tooling/Tooling.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/ReplacementsYaml.h"

#include "llvm/Option/OptTable.h"
#include "llvm/Support/raw_ostream.h"

#include "lavaDB.h"
#include "lava-odb.hxx"
#include "vector_set.hxx"
#include "Modifier.h"
#include "Insertions.h"
#include "lava_version.h"

//using namespace clang;
using namespace llvm;

using clang::tooling::getAbsolutePath;
using clang::tooling::CommonOptionsParser;

#define MATCHER (1 << 0)
#define INJECT (1 << 1)
#define FNARG (1 << 2)
#define PRI (1 << 3)

//#define DEBUG_FLAGS 0 // (MATCHER | INJECT | FNARG | PRI)
#define DEBUG_FLAGS (INJECT | FNARG | PRI)

#define ARG_NAME "data_flow"

#define MAX_STRNLEN 64

static llvm::raw_ostream &null_ostream = llvm::nulls();
#define debug(flag) ((DEBUG_FLAGS & (flag)) ? llvm::errs() : null_ostream)

enum action { LavaQueries, LavaInjectBugs, LavaInstrumentMain };

uint32_t num_atp_queries = 0;
uint32_t num_taint_queries = 0;

// white list of function names (and filenames)
// that can be instrumented
// with dua and atp queries (which will later mean bugs)
std::set<std::string> whitelist;

using namespace odb::core;
std::unique_ptr<odb::pgsql::database> db;

void my_terminate(void);

struct LvalBytes {
    const SourceLval *lval;
    ::Range selected;

    LvalBytes(const SourceLval *lval, ::Range selected)
        : lval(lval), selected(selected) {}
    LvalBytes(const DuaBytes *dua_bytes)
        : lval(dua_bytes->dua->lval), selected(dua_bytes->selected) {}

    bool operator<(const LvalBytes &other) const {
        return std::tie(lval->id, selected)
            < std::tie(other.lval->id, other.selected);
    }

    friend std::ostream &operator<<(std::ostream &os, const LvalBytes &lval_bytes) {
        os << "LvalBytes " << lval_bytes.selected << " of " << *lval_bytes.lval;
        return os;
    }
};


// Map of bugs with siphon of a given  lval name at a given loc.
std::map<LavaASTLoc, vector_set<LvalBytes>> siphons_at;
std::map<LvalBytes, uint32_t> data_slots;

std::string LavaPath;

Loc::Loc(const FullSourceLoc &full_loc)
    : line(full_loc.getExpansionLineNumber()),
    column(full_loc.getExpansionColumnNumber()) {}

static std::vector<const Bug*> bugs;
static std::set<std::string> main_files;

static std::map<std::string, uint32_t> StringIDs;

// Map of bugs with attack points at a given loc.
std::map<std::pair<LavaASTLoc, AttackPoint::Type>, std::vector<const Bug *>>
    bugs_with_atp_at;

static cl::OptionCategory
    LavaCategory("LAVA Taint Query and Attack Point Tool Options");
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp(
    "\nTODO: Add descriptive help message.  "
    "Automatic clang stuff is ok for now.\n\n");
static cl::opt<action> LavaAction("action", cl::desc("LAVA Action"),
    cl::values(
        clEnumValN(LavaQueries, "query", "Add taint queries"),
        clEnumValN(LavaInjectBugs, "inject", "Inject bugs")),
    cl::cat(LavaCategory),
    cl::Required);
static cl::opt<std::string> LavaBugList("bug-list",
    cl::desc("Comma-separated list of bug ids (from the postgres db) to inject into this file"),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<std::string> LavaWL("lava-wl",
    cl::desc("Path to whitelist of fns to instrument with bugs and data_flow "),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<std::string> LavaDB("lava-db",
    cl::desc("Path to LAVA database (custom binary file for source info).  "
        "Created in query mode."),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<std::string> DBName("db",
    cl::desc("database name."),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<std::string> ProjectFile("project-file",
    cl::desc("Path to project.json file."),
    cl::cat(LavaCategory),
    cl::init("XXX"));
static cl::opt<std::string> SourceDir("src-prefix",
    cl::desc("Path to source directory to remove as prefix."),
    cl::cat(LavaCategory),
    cl::init(""));
static cl::opt<std::string> MainFileList("main-files",
    cl::desc("Main files"),
    cl::cat(LavaCategory),
    cl::init(""));
static cl::opt<bool> KnobTrigger("kt",
    cl::desc("Inject in Knob-Trigger style"),
    cl::cat(LavaCategory),
    cl::init(false));
static cl::opt<bool> ArgDataflow("arg_dataflow",
    cl::desc("Use function args for dataflow instead of lava_[sg]et"),
    cl::cat(LavaCategory),
    cl::init(false));
static cl::opt<bool> ArgDebug("debug",
    cl::desc("DEBUG: just add dataflow"),
    cl::cat(LavaCategory),
    cl::init(false));
static cl::opt<unsigned int> ArgRandSeed("randseed",
    cl::desc("Value to use as random seed when generating solutions"),
    cl::cat(LavaCategory),
    cl::init(0));
static cl::opt<bool> ArgCompetition("competition",
    cl::desc("Log before/after bugs when competition is #defined"),
    cl::cat(LavaCategory),
    cl::init(false));
static cl::opt<std::string> DBHost("host",
    cl::desc("Remote Host"),
    cl::init("database"));
static cl::opt<int> DBPort("port",
    cl::desc("Remote Port"),
    cl::init(5432));

unsigned int RANDOM_SEED = 0;

namespace {
    // invoke set_terminate as part of global constant initialization
    static const bool SET_TERMINATE = std::set_terminate(my_terminate);
}

void my_terminate(void) {
    static int tried_throw = false;

    std::cerr << "TEST\n";

    try {
        // try once to re-throw currently active exception
        if (!tried_throw++) throw;
    }
    catch (const std::exception &e) {
        std::cerr << __FUNCTION__ << " caught unhandled exception. what(): "
                  << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << __FUNCTION__ << " caught unknown/unhandled exception."
                  << std::endl;
    }

    void * array[50];
    int size = backtrace(array, 50);

    std::cerr << __FUNCTION__ << " backtrace returned "
              << size << " frames\n\n";

    char ** messages = backtrace_symbols(array, size);

    for (int i = 0; i < size && messages != NULL; ++i) {
        std::cerr << "[bt]: (" << i << ") " << messages[i] << std::endl;
    }
    std::cerr << std::endl;

    free(messages);

    abort();
}

template<typename K, typename V>
const V &map_get_default(const std::map<K, V> &map, K key) {
    static const V default_val;
    auto it = map.find(key);
    if (it != map.end()) {
        return it->second;
    } else {
        return default_val;
    }
}

std::set<std::string> parse_commas_strings(std::string list) {
    std::istringstream ss(list);
    std::set<std::string> result;
    std::string i;
    while(std::getline(ss, i, ',')) {
        result.insert(i);
    }
    return result;
}

template<typename Elem>
std::set<Elem> parse_commas(std::string list) {
    std::istringstream ss(list);
    std::set<Elem> result;
    Elem i;
    while (ss.good()) {
        ss >> i;
        result.insert(i);
        assert(ss.eof() || ss.peek() == ',');
        ss.ignore();
    }
    return result;
}

std::string StripPrefix(std::string filename, std::string prefix) {
    size_t prefix_len = prefix.length();
    if (filename.compare(0, prefix_len, prefix) != 0) {
        printf("Not a prefix!\n");
        assert(false);
    }
    while (filename[prefix_len] == '/') prefix_len++;
    return filename.substr(prefix_len);
}

bool QueriableType(const clang::Type *lval_type) {
    if ((lval_type->isIncompleteType())
        || (lval_type->isIncompleteArrayType())
        || (lval_type->isVoidType())
        || (lval_type->isNullPtrType())
        ) {
        return false;
    }
    if (lval_type->isPointerType()) {
        const clang::Type *pt = lval_type->getPointeeType().getTypePtr();
        return QueriableType(pt);
    }
    return true;
}


bool IsArgAttackable(const Expr *arg) {
    debug(MATCHER) << "IsArgAttackable \n";
    if (DEBUG_FLAGS & MATCHER) arg->dump();

    const clang::Type *t = arg->IgnoreParenImpCasts()->getType().getTypePtr();
    if (dyn_cast<OpaqueValueExpr>(arg) || t->isStructureType() || t->isEnumeralType() || t->isIncompleteType()) {
        return false;
    }
    if (QueriableType(t)) {
        if (t->isPointerType()) {
            const clang::Type *pt = t->getPointeeType().getTypePtr();
            // its a pointer to a non-void
            if ( ! (pt->isVoidType() ) ) {
                return true;
            }
        }
        if ((t->isIntegerType() || t->isCharType()) && (!t->isEnumeralType())) {
            return true;
        }
    }
    return false;
}


uint32_t Slot(LvalBytes lval_bytes) {
    return data_slots.at(lval_bytes);
}

uint32_t alphanum(int len) {
        static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        uint32_t ret = 0;
        for (int i=0; i < len; i++) {
            char c = alphanum[rand() % (sizeof(alphanum)-1)];
            ret +=c;
            if (i+1 != len) ret = ret << 8;
        }

        return ret;
}

LExpr Get(LvalBytes x) {
    return ArgDataflow ? DataFlowGet(Slot(x)) : LavaGet(Slot(x));
}

LExpr Get(const Bug *bug) {
    return Get(bug->trigger);
}

LExpr Set(LvalBytes x) {
    return (ArgDataflow ? DataFlowSet : LavaSet)(x.lval, x.selected, Slot(x));
}

LExpr Set(const Bug *bug) {
    return Set(bug->trigger);
}

LExpr Test(const Bug *bug) {
    return MagicTest<Get>(bug);
}

LExpr threeDuaTest(Bug *bug, LvalBytes x, LvalBytes y) {
        //return (Get(bug->trigger)+Get(x)) == (LHex(bug->magic)*Get(y)); // GOOD
        //return (Get(x)) == (Get(bug->trigger)*(Get(y)+LHex(bug->magic))); // GOOD
        //return (Get(x)%(LHex(bug->magic))) == (LHex(bug->magic) - Get(bug->trigger)); // GOOD

        //return (Get(bug->trigger)<<LHex(3) == (LHex(bug->magic) << LHex(5) + Get(y))); // BAD - segfault
        //return (Get(bug->trigger)^Get(x)) == (LHex(bug->magic)*(Get(y)+LHex(7))); // Segfault

    // TESTING - simple multi dua bug if ABC are all == m we pass
    //return ((Get(x) - Get(y) + Get(bug->trigger)) == LHex(bug->magic));

    // TEST of bug type 2
    //return (Get(x)%(LHex(bug->magic))) == (LHex(bug->magic) - (Get(bug->trigger)*LHex(2)));


    // To deterministically generate solutions, we
    // reset RANDOM_SEED and run bugid times
    srand(RANDOM_SEED);
    for (int i=0;i<bug->id; i++) rand();

    uint32_t a_sol = alphanum(4);
    uint32_t b_sol = alphanum(4);
    uint32_t c_sol = alphanum(4);

    auto oldmagic = bug->magic;

    printf("Bug %lu solutions\n", bug->id);
    const int NUM_BUGTYPES=3;
    // Todo remove the pring switch or print to a debug output
    switch (oldmagic % NUM_BUGTYPES)  {
        case 0:
            bug->magic = (a_sol + b_sol) * c_sol;
            printf("SOL 0x%lx == (0x%x + 0x%x) * 0x%x\n", bug->id, a_sol, b_sol, c_sol);
            break;

        case 1:
            bug->magic = (a_sol * b_sol) - c_sol;
            printf("SOL 0x%lx id  == (0x%x * 0x%x) - 0x%x\n", bug->id, a_sol, b_sol, c_sol);
            break;

        case 2:
            bug->magic = (a_sol+2) * (b_sol+1) * (c_sol+3);
            printf("SOL 0x%lx id == (0x%x+2) *( 0x%x+1) * (0x%x+3) \n", bug->id, a_sol, b_sol, c_sol);
            break;

    }
    //bug->trigger = a_sol;

    switch (oldmagic % NUM_BUGTYPES)  {
        // bug->trigger = A
        // get(x) = B
        // get(y) = C
        // bug->magic = m
        case 0:     // (A + B)*C == M
            return (Get(bug->trigger)+Get(x))*Get(y) == (LHex(bug->magic));
            break;
        case 1:     //(A*B)-C == M
            return (Get(bug->trigger)*Get(x))-Get(y) == (LHex(bug->magic));
            break;
        case 2:     // (A+2)(C+3)(B+1) == M
            return (Get(bug->trigger)+LHex(2))*(Get(y)+LHex(3))*(Get(bug->trigger)+LHex(1))  == LHex(bug->magic);
            break;

        default: // CHAFF
            return (Get(x) == (Get(x)+ LHex(bug->magic)));
            break;
    }
}

LExpr twoDuaTest(const Bug *bug, LvalBytes x) {
    return (Get(bug->trigger)^Get(x)) == LHex(bug->magic);
}

static void printVersion(llvm::raw_ostream &OS) {
    OS << "LavaFnTool Version -- " << LAVA_VER << "\n";
}


// returns true iff this fn name is in whitelist to be instrumented
bool fninstr(std::pair<std::string, std::string> fnname) {
    std::string filename = fnname.first;
    std::string function_name = fnname.second;
    if (whitelist.size()>0) {
        if (whitelist.count(function_name) == 0)
            return false;  // dont instrument
        else
            return true;  // instrument
    }
    return false;
}

uint32_t rand_ascii4() {
    uint32_t ret = 0;
    for (int i=0; i < 4; i++) {
        ret += (rand() % (0x7F-0x20)) + 0x20;
        if (i !=3) ret = ret<<8;
    }
    return ret;
}

LExpr traditionalAttack(const Bug *bug) {
    return Get(bug) * Test(bug);
}

LExpr knobTriggerAttack(const Bug *bug) {
    LExpr lava_get_lower = Get(bug) & LHex(0x0000ffff);
    //LExpr lava_get_upper = (LavaGet(bug) >> LDecimal(16)) & LHex(0xffff);
    LExpr lava_get_upper = (Get(bug) & LHex(0xffff0000)) >> LDecimal(16);
    // this is the magic value that will trigger the bug
    // we already know that magic_kt returns uint16_t so we don't have
    // to mask it
    uint16_t magic_value = bug->magic_kt();

    return (lava_get_lower * MagicTest<uint16_t>(magic_value, lava_get_upper))
        + (lava_get_upper * MagicTest<uint16_t>(magic_value, lava_get_lower));
}

void mark_for_siphon(const DuaBytes *dua_bytes) {

    LvalBytes lval_bytes(dua_bytes);
    siphons_at[lval_bytes.lval->loc].insert(lval_bytes);

    debug(INJECT) << "    Mark siphon at " << lval_bytes.lval->loc << "\n";

    // if insert fails do nothing. we already have a slot for this one.
    data_slots.insert(std::make_pair(lval_bytes, data_slots.size()));
}

#endif
