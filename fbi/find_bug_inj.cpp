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

#include "panda/plog.h"
#include "panda/plog_print.h"
}

#include <json/json.h>

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <unordered_set>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cassert>
#include "lavaDB.h"

#include "pgarray.hxx"
#include "lava.hxx"
#include "lava-odb.hxx"
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

uint64_t num_fake_bugs = 0;
uint64_t num_bugs_added_to_db = 0;
uint64_t num_bugs_of_type[Bug::TYPE_END] = {0};

using namespace odb::core;
std::unique_ptr<odb::pgsql::database> db;

bool debug = false;
#define dprintf(...) if (debug) { printf(__VA_ARGS__); }

uint64_t max_liveness = 0;
uint32_t max_card = 0;
uint32_t max_tcn = 0;
uint32_t max_lval = 0;

uint32_t num_potential_bugs = 0;
uint32_t num_potential_nonbugs = 0;

// These map pointer values in the PANDA taint run to the sets they refer to.
typedef uint64_t Ptr;
std::map<Ptr, const LabelSet*> ptr_to_labelset;

// Liveness for each input byte.
std::vector<uint64_t> liveness;

// Map from source lval ID to most recent DUA incarnation.
std::map<unsigned long, const Dua*> recent_dead_duas;

// Map from label to duas that are tainted by that label.
// So when we update liveness, we know what duas might be invalidated.
std::map<uint32_t, std::set<const Dua *> > dua_dependencies;

// Returns true with probability 1/ratio.
inline bool decimate(double ratio) {
    return rand() * ratio < RAND_MAX;
}

// This will make bugs less likely to be injected if there are more of that
// type. Returns true if we should inject bug.
inline bool decimate_by_type(Bug::Type bug_type) {
    uint64_t num_types_injected_already = 0;
    for (unsigned i = 0; i < Bug::TYPE_END; i++) {
        if (num_bugs_of_type[i] > 0) num_types_injected_already++;
    }
    if (num_types_injected_already == 0) return true;

    uint64_t average_num_bugs = num_bugs_added_to_db /
        num_types_injected_already;
    int64_t diff = num_bugs_of_type[bug_type] - average_num_bugs;
    return diff <= 10000 || decimate(1 + (diff - 10000) * 0.05);
}

// Print stuff to stream separated by commas.
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
    static constexpr const char *name = "sourcelval-value";

    typedef SourceLval Params;

    static const auto query(const Params *param) {
        typedef odb::query<SourceLval> q;
        return q::loc.filename == q::_ref(param->loc.filename) &&
            q::loc.begin.line == q::_ref(param->loc.begin.line) &&
            q::loc.begin.column == q::_ref(param->loc.begin.column) &&
            q::loc.end.line == q::_ref(param->loc.end.line) &&
            q::loc.end.column == q::_ref(param->loc.end.column) &&
            q::ast_name == q::_ref(param->ast_name) &&
            q::timing == q::_ref(param->timing);
    }
};

template<>
struct eq_query<AttackPoint> {
    static constexpr const char *name = "attackpoint-value";

    typedef AttackPoint Params;

    static const auto query(const Params *param) {
        typedef odb::query<AttackPoint> q;
        return q::loc.filename == q::_ref(param->loc.filename) &&
            q::loc.begin.line == q::_ref(param->loc.begin.line) &&
            q::loc.begin.column == q::_ref(param->loc.begin.column) &&
            q::loc.end.line == q::_ref(param->loc.end.line) &&
            q::loc.end.column == q::_ref(param->loc.end.column) &&
            q::type == q::_ref(param->type);
    }
};

// Returns a pointer to object and true if we just created it
// (false if it existed already).
template<class T, typename U = typename eq_query<T>::disabled>
static std::pair<const U*, bool> create_full(T no_id) {
    static std::set<U> existing;

    bool new_object = false;
    auto it = existing.lower_bound(no_id);
    // it now guaranteed to be >= no_id. make sure not ==.
    if (it == existing.end() || no_id < *it) {
        db->persist(no_id);
        it = existing.insert(it, no_id);
        new_object = true;
    }
    return std::make_pair(&*it, new_object);
}

template<class T, typename P = typename eq_query<T>::Params>
static std::pair<const T*, bool> create_full(T no_id) {
    static std::set<T> existing;

    bool new_object = false;
    auto it = existing.lower_bound(no_id);
    // see note above.
    if (it == existing.end() || no_id < *it) {
        P *param;
        odb::prepared_query<T> pq(db->lookup_query<T>(eq_query<T>::name, param));
        if (!pq) {
            std::unique_ptr<P> param_ptr(new P(no_id));
            param = param_ptr.get();
            pq = db->prepare_query<T>(eq_query<T>::name, eq_query<T>::query(param));
            db->cache_query(pq, std::move(param_ptr));
        }
        *param = P(no_id);

        const T *result = pq.execute_one();
        if (!result) {
            db->persist(no_id);
            result = &no_id;
            new_object = true;
        }

        it = existing.insert(it, *result);
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
    auto it = ptr_to_labelset.lower_bound(p);
    if (it == ptr_to_labelset.end() || p < it->first) {
        const LabelSet *ls = create(LabelSet{0, p, inputfile,
                std::vector<uint32_t>(tquls->label,
                        tquls->label + tquls->n_label)});
        ptr_to_labelset.insert(it, std::make_pair(p, ls));

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

template<typename T, class InputIt>
inline void merge_into(InputIt first, InputIt last, size_t size, std::vector<T> &dest) {
    // Make empty array and swap with all_labels.
    std::vector<T> prev_dest;
    prev_dest.swap(dest);

    dest.reserve(prev_dest.size() + size);
    std::set_union(
            prev_dest.begin(), prev_dest.end(),
            first, last, std::back_inserter(dest));
}

template<typename T, class InputIt>
inline void merge_into(InputIt first, InputIt last, std::vector<T> &dest) {
    merge_into(first, last, last - first, dest);
}

template<class T>
uint32_t count_nonzero(std::vector<T> arr) {
    uint32_t count = 0;
    for (T t : arr) { if (t != 0) count++; }
    return count;
}

// get still-viable offsets for a dua.
inline std::vector<uint32_t> get_dua_dead_offsets(const Dua *dua) {
    const auto &viable_bytes = dua->viable_bytes;
    dprintf("checking viability of dua: currently %u viable bytes\n",
            count_nonzero(viable_bytes));

    // NB: we have already checked dua for viability wrt tcn & card at induction
    // these do not need re-checking as they are to be captured at dua siphon point
    std::vector<uint32_t> viable_offsets;
    viable_offsets.reserve(LAVA_MAGIC_VALUE_SIZE);
    for (uint32_t i = 0; i < viable_bytes.size(); i++) {
        const LabelSet *ls = viable_bytes[i];
        if (ls) {
            bool byte_viable = true;
            // determine if liveness for this offset is still low enough
            for (auto l : ls->labels) {
                if (liveness[l] > max_liveness) {
                    dprintf("byte offset is nonviable b/c label %d has liveness %lu\n",
                            l, liveness[l]);
                    byte_viable = false;
                    break;
                }
            }
            if (byte_viable) viable_offsets.push_back(i);
            // Once we know we have at least 4 viable bytes, we can stop
            if (viable_offsets.size() >= LAVA_MAGIC_VALUE_SIZE) break;
        }
    }
    dprintf("%s\ndua has %lu viable bytes\n", std::string(*dua).c_str(),
            viable_offsets.size());
    // dua is viable iff it has more than one viable byte
    return viable_offsets;
}

struct Range {
    uint32_t low;
    uint32_t high;
    inline uint32_t size() const { return high - low; }
    inline bool empty() const { return high <= low; }
};
inline Range get_dua_exploit_pad(const Dua *dua) {
    // Each is a range of offsets with large run of DUA bytes.
    std::vector<Range> runs;
    Range current_run{0, 0};
    const auto &viable_bytes = dua->viable_bytes;
    for (uint32_t i = 0; i < viable_bytes.size(); i++) {
        const LabelSet *ls = viable_bytes[i];
        // This test means tainted, uncomplicated, dead.
        if (ls && ls->labels.size() == 1 && dua->byte_tcn[i] == 0
                && liveness.at(*ls->labels.begin()) == 0) {
            if (current_run.empty()) {
                current_run = Range{i, i + 1};
            } else {
                current_run.high++;
            }
        } else {
            if (!current_run.empty()) {
                runs.push_back(current_run);
            }
            current_run = Range{0, 0};
        }
    }
    if (!current_run.empty()) {
        runs.push_back(current_run);
    }

    auto it = std::max_element(runs.begin(), runs.end(),
            [](const Range &run1, const Range &run2) {
        return run1.size() < run2.size();
    });
    return it == runs.end() ? Range{0, 0} : *it;
}

// determine if this dua is viable at all.
inline bool is_dua_dead(const Dua *dua) {
    return get_dua_dead_offsets(dua).size() == LAVA_MAGIC_VALUE_SIZE;
}

void record_injectable_bugs_at(const AttackPoint *atp, bool is_new_atp,
        const Bug::Type bug_type, std::vector<const Dua *> extra_duas,
        uint32_t exploit_pad_offset = 0);

void taint_query_pri(Panda__LogEntry *ple) {
    assert (ple != NULL);
    Panda__TaintQueryPri *tqh = ple->taint_query_pri;
    assert (tqh != NULL);
    // size of query in bytes & num tainted bytes found
    // bdg: don't try handle lvals that are bigger than our max lval
    uint32_t len = std::min(tqh->len, max_lval);
    uint32_t num_tainted = tqh->num_tainted;
    // entry 1 is source info
    Panda__SrcInfoPri *si = tqh->src_info;
    // ignore duas in header files
    if (is_header_file(std::string(si->filename))) return;
    assert (si != NULL);
    // entry 2 is callstack -- ignore
    Panda__CallStack *cs = tqh->call_stack;
    assert (cs != NULL);
    uint64_t instr = ple->instr;
    dprintf("TAINT QUERY HYPERCALL len=%d num_tainted=%d\n", len, num_tainted);

    // collects set (as sorted vec) of labels on all viable bytes
    std::vector<uint32_t> all_labels;
    // keep track of min / max for each of these measures over all bytes
    // in this queried lval
    uint32_t c_max_tcn = 0, c_max_card = 0;

    transaction t(db->begin());

    // consider all bytes in this extent that were queried and found to be tainted
    // collect "ok" bytes, which have low enough taint compute num and card,
    // and also aren't tainted by too-live input bytes
    // go through and deal with new unique taint sets first
    for (uint32_t i=0; i<tqh->n_taint_query; i++) {
        Panda__TaintQuery *tq = tqh->taint_query[i];
        if (tq->unique_label_set) {
            // collect new unique taint label sets
            update_unique_taint_sets(tq->unique_label_set);
        }
    }

    // if lval is 12 bytes, this vector will have 12 elements
    // viable_byte[i] is 0 if it is NOT viable
    // otherwise it is a ptr to a taint set.

    // Make vector of length len and fill w/ zeroes.
    std::vector<const LabelSet*> viable_byte(len, nullptr);
    std::vector<uint32_t> byte_tcn(len, 0);

    dprintf("considering taint queries on %lu bytes\n", tqh->n_taint_query);

    bool is_dua = false;
    bool is_fake_dua = false;
    uint32_t num_viable_bytes = 0;
    // optimization. don't need to check each byte if we don't have enough.
    if (num_tainted >= LAVA_MAGIC_VALUE_SIZE) {
        for (uint32_t i = 0; i < tqh->n_taint_query; i++) {
            Panda__TaintQuery *tq = tqh->taint_query[i];
            uint32_t offset = tq->offset;
            dprintf("considering offset = %d\n", offset);
            const LabelSet *ls = ptr_to_labelset.at(tq->ptr);

            byte_tcn[offset] = tq->tcn;

            // flag for tracking *why* we discarded a byte
            // check tcn and cardinality of taint set first
            uint32_t current_byte_not_ok = 0;
            current_byte_not_ok |= (tq->tcn > max_tcn) << CBNO_TCN_BIT;
            current_byte_not_ok |= (ls->labels.size() > max_card) << CBNO_CRD_BIT;
            if (current_byte_not_ok && debug) {
                // discard this byte
                dprintf("discarding byte -- here's why: %x\n", current_byte_not_ok);
                if (current_byte_not_ok & (1<<CBNO_TCN_BIT)) printf("** tcn too high\n");
                if (current_byte_not_ok & (1<<CBNO_CRD_BIT)) printf("** card too high\n");
            } else {
                dprintf("retaining byte\n");
                // this byte is ok to retain.
                // keep track of highest tcn, liveness, and card for any viable byte for this lval
                c_max_tcn = std::max(tq->tcn, c_max_tcn);
                c_max_card = std::max((uint32_t) ls->labels.size(), c_max_card);
                // collect set of labels on all ok bytes for this extent
                // remember: labels are offsets into input file
                // NB: only do this for bytes that will actually be used in the dua
                merge_into(ls->labels.begin(), ls->labels.end(), all_labels);
                dprintf("keeping byte @ offset %d\n", offset);
                // add this byte to the list of ok bytes
                viable_byte[offset] = ls;
                num_viable_bytes++;
            }
        }

        dprintf("%u viable bytes in lval  %lu labels\n",
                num_viable_bytes, all_labels.size());
        // three possibilities at this point
        // 1. this is a dua which we can use to make bugs,
        // 2. it's a non-dua which has enough untainted parts to make a fake bug
        // 3. or its neither and we truly discard.
        if ((num_viable_bytes >= LAVA_MAGIC_VALUE_SIZE)
            && (all_labels.size() >= LAVA_MAGIC_VALUE_SIZE)) {
            is_dua = true;
        }
    } else if (len - num_tainted >= LAVA_MAGIC_VALUE_SIZE) {
        dprintf("not enough taint -- what about non-taint?\n");
        dprintf("tqh->n_taint_query=%d\n", (int) tqh->n_taint_query);
        dprintf("len=%d num_tainted=%d\n",len, num_tainted);
        viable_byte.assign(viable_byte.size(), nullptr);
        uint32_t count = 0;
        for (uint32_t i = 0; i < tqh->n_taint_query; i++) {
            Panda__TaintQuery *tq = tqh->taint_query[i];
            uint32_t offset = tq->offset;
            // if untainted, we can guarantee that we can use the untainted
            // bytes to produce a bug that definitely won't trigger.
            // so we create a fake, empty labelset.
            if (!tq->ptr) {
                count++;
                viable_byte[offset] = create(LabelSet{0,
                        FAKE_DUA_BYTE_FLAG, "/hi/patrick",
                        std::vector<uint32_t>()});
            }
        }
        assert(count >= LAVA_MAGIC_VALUE_SIZE);
        is_fake_dua = true;
    }

    // we need # of unique labels to be at least 4 since
    // that's how big our 'lava' key is
    dprintf("is_dua=%d is_fake_dua=%d\n", is_dua, is_fake_dua);
    if (is_dua || is_fake_dua) {
        // keeping track of uncomplicated data extents we have
        // encountered so far in the trace
        // NB: we don't know liveness info yet. defer byte selection until later.
        assert(si->has_insertionpoint && si->has_ast_loc_id);

        LavaASTLoc ast_loc(ind2str[si->ast_loc_id]);
        assert(ast_loc.filename.size() > 0);

        const SourceLval *lval = create(SourceLval{0, ast_loc, si->astnodename,
                (SourceLval::Timing)si->insertionpoint, len});

        if (debug) {
            infix(all_labels.begin(), all_labels.end(), std::cout,
                    "querying labels [", " ", "]\n");
        }
        // tainted lval we just considered was deemed viable
        const Dua *dua = create(Dua{0, lval, viable_byte, byte_tcn, all_labels,
                inputfile, c_max_tcn, c_max_card, ple->instr, is_fake_dua});
        for (uint32_t l : all_labels) {
            dua_dependencies[l].insert(dua);
        }

        const AttackPoint *pad_atp;
        bool is_new_atp;
        std::tie(pad_atp, is_new_atp) = create_full(
                AttackPoint::QueryPoint(
                    ast_loc, std::string(si->astnodename)));
        if (is_dua && len >= 20 && decimate_by_type(Bug::RET_BUFFER)) {
            Range range = get_dua_exploit_pad(dua);
            if (range.size() >= 20) {
                record_injectable_bugs_at(pad_atp, is_new_atp, Bug::RET_BUFFER,
                        { dua }, range.low);
            }
        }

        dprintf("OK DUA.\n");
        if (debug) {
            if (recent_dead_duas.count(lval->id) == 0) printf("new lval\n");
            else printf("previously observed lval\n");
        }
        recent_dead_duas[lval->id] = dua;
    } else {
        dprintf("discarded %u viable bytes %lu labels %s:%u %s",
                num_viable_bytes, all_labels.size(), si->filename, si->linenum,
                si->astnodename);
    }
    t.commit();
}

// update liveness measure for each of taint labels (file bytes) associated with a byte in lval that was queried
void update_liveness(Panda__LogEntry *ple) {
    assert (ple != NULL);
    Panda__TaintedBranch *tb = ple->tainted_branch;
    assert (tb != NULL);
    dprintf("TAINTED BRANCH\n");

    transaction t(db->begin());
    std::vector<uint32_t> all_labels;
    for (uint32_t i=0; i<tb->n_taint_query; i++) {
        Panda__TaintQuery *tq = tb->taint_query[i];
        assert (tq);
        if (tq->unique_label_set) {
            // keep track of unique taint label sets
            update_unique_taint_sets(tq->unique_label_set);
        }
        if (debug) { spit_tq(tq); printf("\n"); }

        // This should be O(mn) for m sets, n elems each.
        // though we should have n >> m in our worst case.
        const std::vector<uint32_t> &cur_labels =
            ptr_to_labelset.at(tq->ptr)->labels;
        merge_into(cur_labels.begin(), cur_labels.end(), all_labels);
    }
    t.commit();

    // For each label, look at all duas tainted by that label.
    // If they aren't viable anymore, erase them from recent_dead_duas list and
    // also erase them from dependency tracker.
    std::vector<const Dua *> duas_to_check;
    for (uint32_t l : all_labels) {
        liveness[l]++;

        dprintf("checking viability of %lu duas\n", recent_dead_duas.size());
        auto it_duas = dua_dependencies.find(l);
        if (it_duas != dua_dependencies.end()) {
            std::set<const Dua *> &depends = it_duas->second;
            merge_into(depends.begin(), depends.end(), depends.size(), duas_to_check);
        }
    }

    std::vector<const Dua *> non_viable_duas;
    for (const Dua *dua : duas_to_check) {
        // is this dua still viable?
        if (!is_dua_dead(dua)) {
            dprintf("%s\n ** DUA not viable\n", std::string(*dua).c_str());
            recent_dead_duas.erase(dua->lval->id);
            non_viable_duas.push_back(dua);
        }
    }

    dprintf("%lu non-viable duas \n", non_viable_duas.size());
    // discard non-viable duas
    for (const Dua *dua : non_viable_duas) {
        for (uint32_t l : dua->all_labels) {
            auto it_depend = dua_dependencies.find(l);
            if (it_depend != dua_dependencies.end()) {
                dua_dependencies.erase(it_depend);
            }
        }
    }
}

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
struct BugParam {
    unsigned long atp_id;
    Bug::Type type;
    uint64_t extra_duas_hash;
};
void record_injectable_bugs_at(const AttackPoint *atp, bool is_new_atp,
        const Bug::Type bug_type, std::vector<const Dua *> extra_duas,
        uint32_t exploit_pad_offset) {
    std::vector<unsigned long> skip_lval_ids;
    if (!is_new_atp) {
        // This means that all bug opportunities here might be repeats: same
        // atp/lval/type combo. Let's head that off at the pass.
        // So get all lval_ids that have been used with this ATP/type/extra dua
        // before, and skip them as we iterate over recent_dead_duas.
        const char *query_name = "atp-shortcut";
        typedef odb::query<BugLval> q;
        BugParam *param;
        odb::prepared_query<BugLval> pq(
                db->lookup_query<BugLval>(query_name, param));
        if (!pq) {
            std::unique_ptr<BugParam> param_ptr(new BugParam);
            param = param_ptr.get();
            pq = db->prepare_query<BugLval>(query_name,
                    q::atp == q::_ref(param->atp_id) &&
                    q::type == q::_ref(param->type) &&
                    q::extra_duas_hash == q::_ref(param->extra_duas_hash));
            db->cache_query(pq, std::move(param_ptr));
        }
        param->atp_id = atp->id;
        param->type = bug_type;
        param->extra_duas_hash = 0;

        // guaranteed to be unique as long as < 4B duas, < 2 extra_duas in vector
        for (size_t i = 0; i < extra_duas.size(); i++) {
            param->extra_duas_hash ^= (extra_duas[i]->id + 1) << (32 * (i % 2));
        }

        auto result = pq.execute();
        skip_lval_ids.reserve(result.size());
        for (auto it = result.begin(); it != result.end(); it++) {
            skip_lval_ids.push_back(it->trigger_lval);
        }
    }

    // every still viable dua is a bug inj opportunity at this point in trace
    // NB: recent_dead_duas sorted by lval_id
    // so we can do set-subtraction (recent_dead_duas - skip_lval_ids)
    // in linear time
    auto skip_it = skip_lval_ids.begin();
    for ( const auto &kvp : recent_dead_duas ) {
        unsigned long lval_id = kvp.first;
        while (skip_it != skip_lval_ids.end() && *skip_it < lval_id) skip_it++;
        if (skip_it != skip_lval_ids.end() && *skip_it == lval_id) continue;

        const Dua *dua = kvp.second;
        // Need to select bytes now.
        std::vector<uint32_t> selected_bytes = get_dua_dead_offsets(dua);

        // lval skip list guarantees this is a new (lval, atp) combo not seen
        // before.
        uint64_t c_max_liveness = 0;
        for (uint32_t offset : selected_bytes) {
            for (uint32_t l : dua->viable_bytes.at(offset)->labels) {
                c_max_liveness = std::max(c_max_liveness, liveness.at(l));
            }
        }

        Bug bug;
        if ((atp->type == AttackPoint::FUNCTION_ARG
                    || atp->type == AttackPoint::POINTER_RW)
                && bug_type == Bug::PTR_ADD) {
            bug = Bug::PtrAdd(dua, selected_bytes, c_max_liveness, atp);
        } else if (atp->type == AttackPoint::QUERY_POINT
                && bug_type == Bug::RET_BUFFER) {
            bug = Bug::RetBuffer(dua, selected_bytes, c_max_liveness, atp,
                        extra_duas[0], exploit_pad_offset);
        } else if ((atp->type == AttackPoint::FUNCTION_ARG
                    || atp->type == AttackPoint::POINTER_RW)
                && bug_type == Bug::REL_WRITE) {
            bug = Bug::RelWrite(dua, selected_bytes, c_max_liveness, atp, extra_duas);
        } else assert(false && "Bad bug type/atp type combination!");
        num_bugs_of_type[bug.type]++;
        db->persist(bug);

        num_bugs_added_to_db++;
        if (dua->fake_dua) {
            num_potential_nonbugs++;
        } else {
            num_potential_bugs++;
        }
    }
}

void attack_point_lval_usage(Panda__LogEntry *ple) {
    assert (ple != NULL);
    Panda__AttackPoint *pleatp = ple->attack_point;
    assert (pleatp != NULL);
    Panda__SrcInfo *si = pleatp->src_info;
    // ignore duas in header files
    if (is_header_file(ind2str[si->filename])) return;

    assert (si != NULL);
    dprintf("ATTACK POINT\n");
    if (recent_dead_duas.size() == 0) {
        dprintf("no duas yet -- discarding attack point\n");
        return;
    }

    dprintf("%lu viable duas remain\n", recent_dead_duas.size());
    assert(si->has_ast_loc_id);
    LavaASTLoc ast_loc(ind2str[si->ast_loc_id]);
    assert(ast_loc.filename.size() > 0);
    transaction t(db->begin());
    const AttackPoint *atp;
    bool is_new_atp;
    std::tie(atp, is_new_atp) = create_full(AttackPoint{0,
            ast_loc, ind2str[si->astnodename],
            (AttackPoint::Type)pleatp->info});
    dprintf("@ATP: %s\n", std::string(*atp).c_str());

    // Don't decimate PTR_ADD bugs.
    record_injectable_bugs_at(atp, is_new_atp, Bug::PTR_ADD, { }, 0);
    for (auto kvp_distance : recent_dead_duas) {
        for (auto kvp_value : recent_dead_duas) {
            if (atp->type == AttackPoint::POINTER_RW
                    && decimate_by_type(Bug::REL_WRITE)) {
                record_injectable_bugs_at(atp, is_new_atp, Bug::REL_WRITE,
                        { kvp_distance.second, kvp_value.second }, 0);
            }
        }
    }

    t.commit();
}

void record_call(Panda__LogEntry *ple) { }

void record_ret(Panda__LogEntry *ple) { }

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

    // We want decimation to be deterministic, so srand w/ magic value.
    srand(0x6c617661);

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

    max_liveness = root["max_liveness"].asUInt();
    printf("maximum liveness score of %lu\n", max_liveness);
    max_card = root["max_cardinality"].asUInt();
    printf("max card of taint set returned by query = %d\n", max_card);
    max_tcn = root["max_tcn"].asUInt();
    printf("max tcn for addr = %d\n", max_tcn);
    max_lval = root["max_lval_size"].asUInt();
    printf("max lval size = %d\n", max_lval);
    inputfile = std::string(argv[4]);
    src_pfx = std::string(argv[2]);

    db.reset(new odb::pgsql::database("postgres", "postgrespostgres",
                root["db"].asString()));
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
                << recent_dead_duas.size() << " duas\n";
        }

        if (ple->taint_query_pri) {
            taint_query_pri(ple);
        } else if (ple->tainted_branch) {
            update_liveness(ple);
        } else if (ple->attack_point) {
            attack_point_lval_usage(ple);
        } else if (ple->dwarf_call) {
            record_call(ple);
        } else if (ple->dwarf_ret) {
            record_ret(ple);
        }
        pandalog_free_entry(ple);
    }
    std::cout << num_bugs_added_to_db << " added to db ";
    pandalog_close();

    std::cout << num_potential_bugs << " potential bugs\n";
    std::cout << num_potential_nonbugs << " potential non bugs\n";

}
