/*
  NB: env variable PANDA points to git/panda

  ./fbi pandalog lavadb ml mtcn mc minl maxl maxlval inputfilename

  ml = 0.5 means max liveness of any byte on extent is 0.5
  mtcn = 10 means max taint compute number of any byte on extent is 10
  mc =4 means max card of a taint labelset on any byte on extent is 4
  min maxl  = 1 1000 means extents must be between 1 and 1000 bytes long
  maxlval = 16 means lvals must be no larger than 16 bytes

*/

#define __STDC_FORMAT_MACROS
#include "inttypes.h"

extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pandalog.h"
#include "pandalog_print.h"
}

#include <json/json.h>

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cassert>
#include "../src_clang/lavaDB.h"

#include "../include/pgarray.hxx"
#include "../include/lava.hxx"
#include "../include/lava-odb.hxx"
#include <odb/pgsql/database.hxx>
#include <odb/session.hxx>

#define CBNO_TCN_BIT 0
#define CBNO_CRD_BIT 1
#define CBNO_LVN_BIT 2

// number of bytes in lava magic value used to trigger bugs
#define LAVA_MAGIC_VALUE_SIZE 4
// special flag to indicate untainted byte that we want to use for fake dua                                                                          
#define FAKE_DUA_BYTE_FLAG 777

std::string inputfile;
std::string src_pfx;
// Map LavaDB string indices to actual strings.
std::map<uint32_t,std::string> ind2str;
int num_fake_bugs = 0;

using namespace odb::core;
std::unique_ptr<odb::pgsql::database> db;

bool debug = false;
#define dprintf(...) if (debug) { printf(__VA_ARGS__); }

float max_liveness = 0.0;
uint32_t max_card = 0;
uint32_t max_tcn = 0;
uint32_t max_lval = 0;

// These map pointer values in the PANDA taint run to the sets they refer to.
typedef uint64_t Ptr;
std::map<Ptr, const LabelSet*> ptr_to_labelset;

// Liveness for each input byte.
std::vector<float> liveness;

// Map from source lval to most recent DUA incarnation.
std::map<const SourceLval*, const Dua*> recent_duas;

// Templated query to ensure uniqueness across runs.
// Here's what this means. Some of our datatypes are dependent on input file.
// So it's guaranteed that those entries in the DB created by separate runs of
// FBI will be unique. So we only need to memoize local instances of those
// datatypes.
// We use the create function to do memoized-create of data types. eq_query
// specifies the types that are not run-independent and how to find them in the
// database. C++ SFINAE guarantees that the correct instance of eq_query gets
// used.
template<class T>
struct eq_query {
    typedef T disabled;
};

template<>
struct eq_query<SourceLval> {
    typedef SourceLval enabled;
    static const auto query(const SourceLval &no_id) {
        typedef odb::query<SourceLval> q;
        return q::file == no_id.file &&
            q::line == no_id.line &&
            q::ast_name == no_id.ast_name &&
            q::timing == no_id.timing &&
            q::selected_bytes == no_id.selected_bytes;
    }
};

template<>
struct eq_query<AttackPoint> {
    typedef AttackPoint enabled;
    static const auto query(const AttackPoint &no_id) {
        typedef odb::query<AttackPoint> q;
        return q::file == no_id.file &&
            q::line == no_id.line &&
            q::type == no_id.type;
    }
};

template<>
struct eq_query<SourceModification> {
    typedef SourceModification enabled;
    static const auto query(const SourceModification &no_id) {
        typedef odb::query<SourceModification> q;
        return q::atp == no_id.atp->id && q::lval == no_id.lval->id;
    }
};

// Returns a pointer to object and true if we just created it
// (false if it existed already).
template<class T, typename U = typename eq_query<T>::disabled>
static std::pair<const U*, bool> create_full(T no_id) {
    static std::set<U> existing;

    bool new_object = false;
    auto it = existing.find(no_id);
    if (it == existing.end()) {
        db->persist(no_id);

        std::tie(it, new_object) = existing.insert(no_id);
        assert(new_object);
    }
    return std::make_pair(&*it, new_object);
}

template<class T, typename U = typename eq_query<T>::enabled>
static std::pair<const T*, bool> create_full(T no_id) {
    static std::set<U> existing;

    bool new_object = false;
    auto it = existing.find(no_id);
    if (it == existing.end()) {
        const U *result;

        result = db->query_one<U>(eq_query<U>::query(no_id));
        if (!result) {
            db->persist(no_id);
            result = &no_id;
            new_object = true;
        }

        bool success = false;
        std::tie(it, success) = existing.insert(*result);
        assert(success);
    }
    return std::make_pair(&*it, new_object);
}

template<class T>
static const T* create(T no_id) {
    return create_full(no_id).first;
}

std::map<uint32_t,std::string> LoadIDB(std::string fn) {
    std::string sfn = std::string(fn);
    std::map<std::string,uint32_t> x = LoadDB(sfn);
    return InvertDB(x);
}

// if pfx is a prefix of filename, then return the remainder of filename after
// the prefix (exluding leading '/' chars).  If it is not a pfx, return
// the empty string
std::string strip_pfx(std::string filename, std::string pfx) {
    size_t pos = filename.find(pfx, 0);
    if (pos == std::string::npos
        || pos != 0) {
        // its not a prefix
        return std::string("");
    }
    size_t filename_len = filename.length();
    size_t pfx_len = pfx.length();
    if (filename[pfx_len] == '/') {
        pfx_len++;
    }
    std::string suff = filename.substr(pfx_len, filename_len - pfx_len);
    return suff;
}


void spit_tquls(const Panda__TaintQueryUniqueLabelSet *tquls) {
    printf("tquls=[ptr=0x%" PRIx64 ",n_label=%d,label=[", tquls->ptr, (int) tquls->n_label);
    for (uint32_t i=0; i<tquls->n_label; i++) {
        printf("%d", tquls->label[i]);
        if (i+1<tquls->n_label) printf(",");
    }
    printf("]]");
}

void spit_tq(Panda__TaintQuery *tq) {
    printf("tq=[ptr=0x%" PRIx64 ",tcn=%d,offset=%d]", tq->ptr, tq->tcn, tq->offset);
}

void spit_si(Panda__SrcInfo *si) {
    printf("si=[filename='%s',line=%d,", (char*) ind2str[si->filename].c_str(), si->linenum);
    printf("astnodename='%s',", (char *) ind2str[si->astnodename].c_str());
    if (si->has_insertionpoint) {
        printf("insertionpoint=%d", si->insertionpoint);
    }
    printf("]");
}

void spit_tqh(Panda__TaintQueryHypercall *tqh) {
    printf("tqh=[buf=0x%" PRIx64 ",len=%d,num_tainted=%d]", tqh->buf, tqh->len, tqh->num_tainted);
}

void spit_ap(Panda__AttackPoint *ap) {
    printf("ap=[info=%d]", ap->info);
}


void update_unique_taint_sets(const Panda__TaintQueryUniqueLabelSet *tquls) {
    if (debug) {
        printf("UNIQUE TAINT SET\n");
        spit_tquls(tquls);
        printf("\n");
    }
    // maintain mapping from ptr (uint64_t) to actual set of taint labels
    Ptr p = tquls->ptr;
    if (ptr_to_labelset.count(p) == 0) {
        const LabelSet *ls = create(LabelSet{0, p, inputfile,
                std::vector<uint32_t>(tquls->label,
                        tquls->label + tquls->n_label)});
        ptr_to_labelset[p] = ls;

        auto &labels = ls->labels;
        uint32_t max_label = *std::max_element(
                labels.begin(), labels.end());
        if (liveness.size() <= max_label) {
            liveness.resize(max_label + 1, 0);
        }
    }
    dprintf("%lu unique taint sets\n", ptr_to_labelset.size());
}

bool is_header_file(std::string filename) {
    uint32_t l = filename.length();
    return (filename[l-2] == '.' && filename[l-1] == 'h');
}

void taint_query_pri(Panda__LogEntry *ple) {
    assert (ple != NULL);
    Panda__TaintQueryPri *tqh = ple->taint_query_pri;
    assert (tqh != NULL);
    // size of query in bytes & num tainted bytes found
    uint32_t len = tqh->len;
    uint32_t num_tainted = tqh->num_tainted;
    // entry 1 is source info
    Panda__SrcInfoPri *si = tqh->src_info;
    // ignore duas in header files
    if (is_header_file(std::string(si->filename))) return;
    assert (si != NULL);
    bool ddebug = false;
    // entry 2 is callstack -- ignore
    Panda__CallStack *cs = tqh->call_stack;
    assert (cs != NULL);
    uint64_t instr = ple->instr;
    dprintf("TAINT QUERY HYPERCALL len=%d num_tainted=%d\n", len, num_tainted);

    // collects set of labels on all viable bytes that are actually used in dua
    std::set<uint32_t> all_labels;
    // keep track of min / max for each of these measures over all bytes
    // in this queried lval
    float c_max_liveness = 0.0;
    uint32_t c_max_tcn = 0, c_max_card = 0;

    // consider all bytes in this extent that were queried and found to be tainted
    // collect "ok" bytes, which have low enough taint compute num and card,
    // and also aren't tainted by too-live input bytes
    uint32_t max_offset = 0;
    // go through and deal with new unique taint sets first
    for (uint32_t i=0; i<tqh->n_taint_query; i++) {
        Panda__TaintQuery *tq = tqh->taint_query[i];
        max_offset = std::max(tq->offset, max_offset);
        if (tq->unique_label_set) {
            // collect new unique taint label sets
            update_unique_taint_sets(tq->unique_label_set);
        }
    }

    // if lval is 12 bytes, this vector will have 12 elements
    // viable_byte[i] is 0 if it is NOT viable
    // otherwise it is a ptr to a taint set.

    // Make vector of length max_offset and fill w/ zeroes.
    std::vector<const LabelSet*> viable_byte(max_offset + 1, nullptr);

    if (ddebug) printf("max_offset = %d\n", max_offset);
    if (ddebug) printf("considering taint queries on %lu bytes\n", tqh->n_taint_query);
    // bdg: don't try handle lvals that are bigger than our max lval
    // NB: must do this *after* dealing with unique taint sets
    if (max_offset + 1 > max_lval) return;

    uint32_t num_viable_bytes = 0;
    for (uint32_t i=0; i<tqh->n_taint_query; i++) {
        Panda__TaintQuery *tq = tqh->taint_query[i];
        uint32_t offset = tq->offset;
        if (ddebug) printf("considering offset = %d\n", offset);
        const LabelSet *ls = ptr_to_labelset.at(tq->ptr);

        // flag for tracking *why* we discarded a byte
        // check tcn and cardinality of taint set first
        uint32_t current_byte_not_ok = 0;
        current_byte_not_ok |= (tq->tcn > max_tcn) << CBNO_TCN_BIT;
        current_byte_not_ok |= (ls->labels.size() > max_card) << CBNO_CRD_BIT;
        if (current_byte_not_ok && debug) {
            // discard this byte
            printf("discarding byte -- here's why: %x\n", current_byte_not_ok);
            if (current_byte_not_ok & (1<<CBNO_TCN_BIT)) printf("** tcn too high\n");
            if (current_byte_not_ok & (1<<CBNO_CRD_BIT)) printf("** card too high\n");
        }
        else {
            if (ddebug) printf("retaining byte\n");
            // this byte is ok to retain.
            // keep track of highest tcn, liveness, and card for any viable byte for this lval
            c_max_tcn = std::max(tq->tcn, c_max_tcn);
            c_max_card = std::max((uint32_t) ls->labels.size(), c_max_card);
            // collect set of labels on all ok bytes for this extent
            // remember: labels are offsets into input file
            // NB: only do this for bytes that will actually be used in the dua
            all_labels.insert(ls->labels.begin(), ls->labels.end());
            dprintf("keeping byte @ offset %d\n", offset);
            // add this byte to the list of ok bytes
            viable_byte[offset] = ls;
            num_viable_bytes++;
        }
        // we can stop examining query when we have enough viable bytes
        if (num_viable_bytes >= LAVA_MAGIC_VALUE_SIZE) break;
    }
    dprintf("%u viable bytes in lval  %lu labels\n",
            num_viable_bytes, all_labels.size());
    // three possibilities at this point
    // 1. this is a dua which we can use to make bugs,
    // 2. it's a non-dua which has enough untainted parts to make a non-bug
    // 3. or its neither and we truly discard.
    bool is_dua = false;
    bool is_non_dua = false;
    // we need # of unique labels to be at least 4 since
    // that's how big our 'lava' key is
    if ((num_viable_bytes == LAVA_MAGIC_VALUE_SIZE)
        && (all_labels.size() == LAVA_MAGIC_VALUE_SIZE)) is_dua = true;
    else {
        if (len - num_tainted >= LAVA_MAGIC_VALUE_SIZE) {
            is_non_dua = true;
            // must recompute viable_byte 
            viable_offset.erase();
            viable_byte.erase();
            uint32_t count = 0;
            for (uint32_t i=0; i<tqh->n_taint_query; i++) {
                Panda__TaintQuery *tq = tqh->taint_query[i];
                uint32_t offset = tq->offset;
                // if tainted, its not viable...
                viable_byte[offset] = (tq->ptr) ? 0 : FAKE_DUA_BYTE_FLAG;
            }                
        }
    }
    if (is_dua || is_non_dua) {
        // keeping track of dead, uncomplicated data extents we have
        // encountered so far in the trace
        assert (si->has_insertionpoint);
        // this is set of lval offsets that will be used to construct the dua
        // and thus is part of what determines the precise src mods
        std::set<uint32_t> viable_offsets;
        for (uint32_t i = 0; i < viable_byte.size(); i++) {
            if (viable_byte[i] != nullptr) viable_offsets.insert(i);
        }
        assert(viable_offsets.size() == LAVA_MAGIC_VALUE_SIZE);
        std::string relative_filename = strip_pfx(std::string(si->filename), src_pfx);
        assert(relative_filename.size() > 0);
        const SourceLval *d_key = create(SourceLval{0,
                relative_filename, si->linenum,
                std::string(si->astnodename), (SourceLval::Timing)si->insertionpoint,
                std::vector<uint32_t>(viable_offsets.begin(), viable_offsets.end())});
        if (debug) {
            printf("querying labels [");
            for (uint32_t l : all_labels) printf("%d ", l);
            printf("]\n");
        }
        for (uint32_t l : all_labels) {
            c_max_liveness = std::max(c_max_liveness, liveness.at(l));
        }
        // tainted lval we just considered was deemed viable
        const Dua *dua = create(Dua{0, d_key, viable_byte,
                std::vector<uint32_t>(all_labels.begin(), all_labels.end()),
                inputfile, c_max_tcn, c_max_card, c_max_liveness,
                    ple->instr}, is_non_dua);
        dprintf("OK DUA.\n");
        if (debug) {
            if (recent_duas.count(d_key)==0) printf("new dua key\n");
            else printf("previously observed dua key\n");
        }
        recent_duas[d_key] = dua;
    }
    else {
        if (debug) {
            std::cout << "discarded " << num_viable_bytes << " viable bytes "
                      << all_labels.size() << " labels "
                      << std::string(si->filename) << " "
                      << si->linenum << " "
                      << std::string(si->astnodename) << " "
                      << si->insertionpoint << "\n";
        }
    }
}


// update liveness measure for each of taint labels (file bytes) associated with a byte in lval that was queried
void update_liveness(Panda__LogEntry *ple) {
    assert (ple != NULL);
    Panda__TaintedBranch *tb = ple->tainted_branch;
    assert (tb != NULL);
    dprintf("TAINTED BRANCH\n");

    for (uint32_t i=0; i<tb->n_taint_query; i++) {
        Panda__TaintQuery *tq = tb->taint_query[i];
        assert (tq);
        if (tq->unique_label_set) {
            // keep track of unique taint label sets
            update_unique_taint_sets(tq->unique_label_set);
        }
        if (debug) { spit_tq(tq); printf("\n"); }
        // this tells us what byte in the extent this query was for
        for ( uint32_t l : ptr_to_labelset.at(tq->ptr)->labels ) {
            liveness.at(l)++;
        }
    }
}

template<class T>
uint32_t count_nonzero(std::vector<T> arr) {
    uint32_t count = 0;
    for (T t : arr) { if (t != 0) count++; }
    return count;
}

// determine if this dua is viable
bool is_dua_viable(const Dua &dua) {
    dprintf("checking viability of dua: currently %u viable bytes\n",
            count_nonzero(dua.viable_bytes));

    // NB: we have already checked dua for viability wrt tcn & card at induction
    // these do not need re-checking as they are to be captured at dua siphon point
    // Note, also, that we are only checking the 4 or so bytes that were previously deemed viable
    uint32_t num_viable = 0;
    bool viable = false;
    for (const LabelSet *ls : dua.viable_bytes) {
        if (ls) {
            num_viable++;
            // determine if liveness for this offset is still low enough
            for (auto l : ls->labels) {
                if (liveness.at(l) > max_liveness) {
                    dprintf("byte offset is nonviable b/c label %d has liveness %.3f\n",
                            l, liveness[l]);
                    num_viable--;
                    break;
                }
            }
            if ((viable = (num_viable == LAVA_MAGIC_VALUE_SIZE)))
                break;
        }
    }
    dprintf("%s\ndua has %u viable bytes\n", std::string(dua).c_str(), num_viable);
    // dua is viable iff it has more than one viable byte
    return viable;
}

uint32_t num_bugs = 0;

uint64_t num_bugs_added_to_db = 0;
uint64_t num_bugs_attempted = 0;

/*
def collect_bugs(attack_point):
  for dua in duas:
    viable_count = 0
    for file_offset in dua:
      if (check_liveness(file_offset)):
        viable_count ++
    if (viable_count >= bytes_needed):
      bugs.add((dua, attack_point))
*/

/*
  we are at an attack point
  iterate over all currently viable duas and
  look for bug inj opportunities
*/
void find_bug_inj_opportunities(Panda__LogEntry *ple) {
    assert (ple != NULL);
    uint64_t instr = ple->instr;
    Panda__AttackPoint *pleatp = ple->attack_point;
    assert (pleatp != NULL);
    Panda__SrcInfo *si = pleatp->src_info;
    // ignore duas in header files
    if (is_header_file(ind2str[si->filename])) return;

    assert (si != NULL);
    dprintf("ATTACK POINT\n");
    if (recent_duas.size() == 0) {
        dprintf("no duas yet -- discarding attack point\n");
        return;
    }

    std::vector<const SourceLval*> non_viable_duas;
    dprintf("checking viability of %lu duas\n", recent_duas.size());
    // collect list of nonviable duas
    for (auto kvp : recent_duas) {
        const SourceLval *dk = kvp.first;
        const Dua *dua = kvp.second;
        // is this dua still viable?
        if (!is_dua_viable(*dua)) {
            dprintf("%s\n ** DUA not viable\n", std::string(*dua).c_str());
            non_viable_duas.push_back(dk);
        }
    }
    dprintf("%lu non-viable duas \n", non_viable_duas.size());
    // discard non-viable duas
    for (auto dk : non_viable_duas) {
        recent_duas.erase(dk);
    }

    dprintf("%lu viable duas remain\n", recent_duas.size());
    std::string relative_filename = strip_pfx(ind2str[si->filename], src_pfx);
    assert(relative_filename.size() > 0);
    const AttackPoint *atp = create(AttackPoint{0, 
            relative_filename, si->linenum, AttackPoint::ATP_FUNCTION_CALL});
    dprintf("@ATP: %s\n", std::string(*atp).c_str());

    // every still viable dua is a bug inj opportunity at this point in trace
    for ( auto kvp : recent_duas ) {
        const SourceLval *dk = kvp.first;
        const Dua *dua = kvp.second;

        const SourceModification *source_mod;
        bool new_mod;
        std::tie(source_mod, new_mod) =
            create_full(SourceModification{0, dk, atp});

        if (new_mod) {
            // this is a new bug (new src mods for both dua and atp)
            const Bug *bug = create(Bug{0, dua, atp});
            float rdf_frac = ((float)dua->instr) / ((float)instr);
            dprintf("i1=%lu i2=%lu rdf_frac=%f\n", dua->instr, instr, rdf_frac);
            num_bugs_added_to_db++;
        }
        else dprintf("not a new bug\n");
        num_bugs_attempted ++;
    }
}

struct SrcFunction {
    uint64_t id;
    std::string filename;
    uint64_t line;
    std::string name;
};

//namespace std {
    //template<>
    //struct less<Panda__DwarfCall> {
        //bool operator() (const Panda__DwarfCall &A, const Panda__DwarfCall &B) const {
            //int64_t cmp = strcmp(A.file_callee, B.file_callee);
            //if (cmp != 0) return cmp > 0;

            //cmp = strcmp(A.function_name_callee, B.function_name_callee);
            //if (cmp != 0) return cmp > 0;

            //if (A.line_number_callee != B.line_number_callee)
                //return A.line_number_callee > B.line_number_callee;

            //cmp = strcmp(A.file_callsite, B.file_callsite);
            //if (cmp != 0) return cmp > 0;

            //return A.line_number_callsite > B.line_number_callsite;
        //}
    //};
//}
//std::map<Panda__DwarfCall, std::vector<uint64_t> > dwarf_call_to_instr;

void record_call(Panda__LogEntry *ple) {
    assert(ple->dwarf_call);
    //dwarf_call_to_instr[*ple->dwarf_call].push_back(ple->instr);
}

void record_ret(Panda__LogEntry *ple) {
    /*// Find corresponding call for this return.
    assert(ple->dwarf_ret);
    Panda__DwarfCall *dwarf_ret = ple->dwarf_ret;

    std::vector<uint64_t> &calls = dwarf_call_to_instr[*dwarf_ret];
    assert(!calls.empty());

    uint64_t call_instr = calls.back(), ret_instr = ple->instr;
    calls.pop_back();

    SrcFunction &func = memoized_create(SrcFunction{dwarf_ret->file_callee,
            dwarf_ret->line_number_callee, dwarf_ret->function_name_callee});

    std::string callsite_filename = strip_pfx(dwarf_ret->file_callsite, src_pfx);
    int callsite_filename_id = addstr(conn, "sourcefile", callsite_filename);
    std::stringstream sql;
    sql << "INSERT INTO call (call_instr, ret_instr, "
        << "called_function, filename_id, line) VALUES ("
        << call_instr << ", " << ret_instr << ", " << func.id << ", "
        << callsite_filename_id << ", " << dwarf_ret->line_number_callsite << ");";*/
}

int main (int argc, char **argv) {
    if (argc != 5) {
        printf("usage: fbi project.json src_pfx pandalog inputfile\n");
        printf("    src_pfx: Prefix of source tree from lavaTool queries, so we can strip it\n");
        printf("    JSON file should have properties:\n");
        printf("        max_liveness: Maximum liveness for DUAs\n");
        printf("        max_cardinality: Maximum cardinality for labelsets on DUAs\n");
        printf("        max_tcn: Maximum taint compute number for DUAs\n");
        printf("        max_lval_size: Maximum bytewise size for \n");
        printf("    pandalog: Pandalog. Should be like queries-file-5.22-bash.iso.plog\n");
        printf("    inputfile: Input file basename, like malware.pcap\n");
        exit (1);
    }

    std::ifstream json_file(argv[1]);
    Json::Value root;
    json_file >> root;

    std::string root_directory = root["directory"].asString();
    std::string name = root["name"].asString();
    std::string directory = root_directory + "/" + name;

    std::string plog(argv[3]);
    std::string lavadb = directory + "/lavadb";

    // panda log file
    const char *plf = plog.c_str();
    // maps from ind -> (filename, lvalname, attackpointname)
    ind2str = LoadIDB(lavadb);
    printf("%d strings in lavadb\n", (int) ind2str.size());

    max_liveness = root["max_liveness"].asFloat();
    printf("maximum liveness score of %.2f\n", max_liveness);
    max_card = root["max_cardinality"].asUInt();
    printf("max card of taint set returned by query = %d\n", max_card);
    max_tcn = root["max_tcn"].asUInt();
    printf("max tcn for addr = %d\n", max_tcn);
    max_lval = root["max_lval_size"].asUInt();
    printf("max lval size = %d\n", max_lval);
    inputfile = std::string(argv[4]);
    src_pfx = std::string(argv[2]);

    db.reset(new odb::pgsql::database("postgres", "postgrespostgres",
                root["db"].asString(), root["dbhost"].asString()));
    transaction t(db->begin());
    /*
     re-read pandalog, this time focusing on taint queries.  Look for
     dead available data, attack points, and thus bug injection oppotunities
    */
    pandalog_open(plf, "r");
    uint64_t num_entries_read = 0;

    while (1) {
        // collect log entries that have same instr count (and pc).
        // these are to be considered together.
        Panda__LogEntry *ple = pandalog_read_entry();
        if (ple == NULL)  break;
        num_entries_read++;
        if ((num_entries_read % 10000) == 0) {
            printf("processed %lu pandalog entries \n", num_entries_read);
            std::cout << num_bugs_added_to_db << " added to db "
                << num_bugs_attempted << " total attempted. "
                << recent_duas.size() << " duas\n";
        }

        if (ple->taint_query_pri) {
            taint_query_pri(ple);
        } else if (ple->tainted_branch) {
            update_liveness(ple);
        } else if (ple->attack_point) {
            find_bug_inj_opportunities(ple);
        } else if (ple->dwarf_call) {
            record_call(ple);
        } else if (ple->dwarf_ret) {
            record_ret(ple);
        }
        pandalog_free_entry(ple);
    }
    std::cout << num_bugs_added_to_db << " added to db " << num_bugs_attempted << " total attempted\n";
    pandalog_close();
    t.commit();
}
