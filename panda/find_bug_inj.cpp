/*
  NB: env variable PANDA points to git/panda
  
  g++ -g -o fbi   find_bug_inj.cpp  \
    ../sql/lava_sql.cpp \
    ../src_clang/lavaDB.cpp \
    ../../panda/qemu/panda/pandalog.c \
    ../../panda/qemu/panda/pandalog.pb-c.c \
    -L/usr/local/lib -lprotobuf-c  -I ../../panda/qemu -I ../../panda/qemu/panda  -lz -D PANDALOG_READER  -std=c++11  -O2 -lpq
    
  ./fbi pandalog lavadb ml mtcn mc minl maxl inputfilename

  ml = 0.5 means max liveness of any byte on extent is 0.5
  mtcn = 10 means max taint compute number of any byte on extent is 10
  mc =4 means max card of a taint labelset on any byte on extent is 4
  min maxl  = 1 1000 means extents must be between 1 and 1000 bytes long

*/

#define __STDC_FORMAT_MACROS
#include "inttypes.h"

extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

}

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <sstream>
#include "pandalog.h"
#include "../src_clang/lavaDB.h"
#include "../include/lava_bugs.h"


#define CBNO_TCN_BIT 0
#define CBNO_CRD_BIT 1
#define CBNO_LVN_BIT 2



std::string inputfile;
std::string src_pfx;
int inputfile_id;
std::map<uint32_t,std::string> ind2str;


Instr last_instr_count;


bool debug = true;


void get_last_instr(char *pandalog_filename) {
    printf ("Computing dua and ap stats\n");
    pandalog_open(pandalog_filename, "r");
    while (1) {
        Panda__LogEntry *ple = pandalog_read_entry();
        if (ple == NULL) break;
        if (ple->instr != -1) {
            last_instr_count = ple->instr;
        }
    }
    //    printf ("%" PRIu64 "is last instr\n", last_instr_count);
    pandalog_close();
}
    

std::pair<float, float> update_range(float val, std::pair<float, float> range) {
    if (val < range.first) {
        range.first = val;
    }
    if (val > range.second) {
        range.second = val;
    }
    return range;
}

std::pair<uint32_t, uint32_t> update_range(uint32_t val, std::pair<uint32_t, uint32_t> range) {
    if (val < range.first) {
        range.first = val;
    }
    if (val > range.second) {
        range.second = val;
    }
    return range;
}


std::map<uint32_t,std::string> LoadIDB(std::string fn) {
    std::string sfn = std::string(fn);
    std::map<std::string,uint32_t> x = LoadDB(sfn);
    return InvertDB(x);
}



void spit_res(PGresult *res) {
    int i,j;   
    /* first, print out the attribute names */
    int nFields = PQnfields(res);
    for (i = 0; i < nFields; i++)
        printf("%-15s", PQfname(res, i));
    printf("\n\n");    
    /* next, print out the rows */
    for (i = 0; i < PQntuples(res); i++)
    {
        for (j = 0; j < nFields; j++)
            printf("%-15s", PQgetvalue(res, i, j));
        printf("\n");
    }
}




uint32_t stou(std::string s) {
    const char * cs = s.c_str();
    return (uint32_t) atoi(cs);
}


int get_num_rows(PGconn *conn, std::string table) {
    std::string sql = "select count(*) from " + table + ";";
    PGresult *res = pg_exec(conn, (const char *) sql.c_str());
    assert (PQresultStatus(res) == PGRES_TUPLES_OK);
    uint32_t n = stou(PQgetvalue(res, 0, 0));
    PQclear(res);
    return n;
}



// add this string to this table and retrieve 
// the id it got (serial row #)
// column name is "nm"
int addstr(PGconn *conn, std::string table, std::string str) {
    std::stringstream sql;
    // is str already there?
    sql << "SELECT * FROM " << table << " where " << table << "_nm='" << str << "';";
    PGresult *res = pg_exec_ss(conn, sql);
    if (PQntuples(res) > 0 ) {
        PQclear(res);

        //        printf ("its already there\n");
    }
    else {
        PQclear(res);
        // it isnt here -- add it
        std::stringstream sql;
        sql << "INSERT INTO " << table << " (" << table << "_nm) VALUES ('" << str << "');";
        //        printf ("sql = [%s]\n", (char *) sql.str().c_str());        
        res = pg_exec_ss(conn, sql);
        //        printf ("status = %d\n", PQresultStatus(res));
    }
    // return id assigned to str
    sql.str("");
    sql << "SELECT * FROM " << table << " where " << table << "_nm='" << str << "';";
    //    printf ("sql = [%s]\n", (char *) sql.str().c_str());
    res = pg_exec_ss(conn, sql);
    //    printf ("status = %d\n", PQresultStatus(res));
    uint32_t n = stou(PQgetvalue(res, 0, 0));        
    PQclear(res);
    return n;
}



std::map<DuaKey,int> dua_id;
std::map<AttackPoint,int> atp_id;


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

                                                                               
// returns dua_id assigned by postgres
// -1 if none (error or already there)
int postgres_new_dua(PGconn *conn, Dua &dua) {
    PGresult *res;
    // add source filename to sourcefile table
    std::string filename = dua.filename;
    int filename_id = addstr(conn, "sourcefile", strip_pfx(filename, src_pfx));
    std::string lvalname = dua.lvalname;
    int lval_id = addstr(conn, "lval", lvalname);
    std::stringstream sql;
    sql << "INSERT INTO dua (filename_id,line,lval_id,insertionpoint,file_offsets,lval_offsets,inputfile_id,max_liveness,max_tcn,max_card,dua_icount,dua_scount) VALUES ("
        << filename_id << ","
        << dua.line << ","  
        << lval_id << ","
        << dua.insertionpoint << ","
        // offsets within the input file that taint dua
        << "'{" << iset_str(dua.file_offsets) << "}'" << ","
        // offsets within the lval that are duas
        << "'{"  << iset_str(dua.lval_offsets) << "}'" << ","
        << inputfile_id << ","
        << dua.max_liveness << "," << dua.max_tcn << "," << dua.max_card 
        << ",0,0) RETURNING dua_id;";
    res = pg_exec_ss(conn,sql);
    int n = -1;
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        n = (int) stou(PQgetvalue(res, 0, 0));
        if (debug) std::cout << "Added to db id=" << n << " DUA = [" << dua.str() << "]\n";
    }
    PQclear(res);
    return n;
}


// replace dua with this id
void postgres_replace_dua(PGconn *conn, Dua &dua, int dua_id) {
    std::stringstream sql;    
    sql << "UPDATE dua SET file_offsets = "
        << "'{" << iset_str(dua.file_offsets) << "}'" << ","
        << "lval_offsets = "        
        << "'{"  << iset_str(dua.lval_offsets) << "}'" << ","
        << "max_liveness = " << dua.max_liveness << ","
        << "max_tcn = " << dua.max_tcn << ","
        << "max_card = " << dua.max_card
        << " WHERE dua_id=" << dua_id << ";";
    PGresult *res = pg_exec_ss(conn,sql);
    if (debug) printf ("update result: %d\n", PQresultStatus(res) );
    assert (PQresultStatus(res) == PGRES_COMMAND_OK);
    if (debug) std::cout << "Replaced dua id=" << dua_id << "\n";
    PQclear(res);
}
    


// returns atp_id assigned by postgres
// -1 if non (error or already there)
int postgres_dump_atp(PGconn *conn, AttackPoint &atp) {
    PGresult *res;
    // add source filename to sourcefile table
    std::string filename = atp.filename;
    int filename_id = addstr(conn, "sourcefile", strip_pfx(filename, src_pfx));
    std::string info = atp.typ;
    int typ_id = addstr(conn, "atptype", info);
    std::stringstream sql;
    sql << "INSERT INTO atp (filename_id,line,typ_id,inputfile_id,atp_icount,atp_scount) VALUES ("
        << filename_id << ","
        << atp.line << ","
        << typ_id << ","
        << inputfile_id << ","
        << "0,0) RETURNING atp_id;";
    res = pg_exec_ss(conn,sql);
    int n = -1;
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        n = stou(PQgetvalue(res, 0, 0));
        atp_id[atp] = n;
        if (debug) std::cout << "Added to db id=" << n << " ATP= [" << atp.str() << "]\n";
    }
    PQclear(res);
    return n;
}


void add_bug_to_db(PGconn *conn, uint32_t dua_id, uint32_t atp_id) {
    std::stringstream sql;
    // we don't need to get bug_id back
    sql << "INSERT INTO bug (dua_id,atp_id,inj) VALUES ("
        << dua_id << ","
        << atp_id <<
        ",false);";
    PGresult *res = pg_exec_ss(conn,sql);
    //        assert (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);    
}



void spit_tquls(Panda__TaintQueryUniqueLabelSet *tquls) {
    printf ("tquls=[ptr=0x%" PRIx64 ",n_label=%d,label=[", tquls->ptr, (int) tquls->n_label);
    for (uint32_t i=0; i<tquls->n_label; i++) {
        printf ("%d", tquls->label[i]);
        if (i+1<tquls->n_label) printf (",");
    }
    printf("]]");
}


void spit_tq(Panda__TaintQuery *tq) {
    printf ("tq=[ptr=0x%" PRIx64 ",tcn=%d,offset=%d]", tq->ptr, tq->tcn, tq->offset);
}


void spit_si(Panda__SrcInfo *si) {
    printf ("si=[filename='%s',line=%d,", (char*) ind2str[si->filename].c_str(), si->linenum);
    printf ("astnodename='%s',", (char *) ind2str[si->astnodename].c_str());
    if (si->has_insertionpoint) {
        printf ("insertionpoint=%d", si->insertionpoint);
    }
    printf ("]");
}


void spit_tqh(Panda__TaintQueryHypercall *tqh) {
    printf ("tqh=[buf=0x%" PRIx64 ",len=%d,num_tainted=%d]", tqh->buf, tqh->len, tqh->num_tainted);
}


void spit_ap(Panda__AttackPoint *ap) {
    printf("ap=[info=%d]", ap->info);
}

        
uint64_t i0 = 0;


            
            
            
void update_unique_taint_sets(Panda__TaintQueryUniqueLabelSet *tquls, std::map<Ptr,std::set<uint32_t>> &ptr_to_set) {                                
    if (debug) {
        printf ("UNIQUE TAINT SET\n");
        spit_tquls(tquls);
        printf ("\n");
    }
    // maintain mapping from ptr (uint64_t) to actual set of taint labels 
    uint32_t i;
    Ptr p = tquls->ptr;
    for (i=0; i<tquls->n_label; i++) {
        uint32_t l = tquls->label[i];
        ptr_to_set[p].insert(l);
    }
}



void taint_query_hypercall(Panda__LogEntry *ple,
                           std::map<Ptr,std::set<uint32_t>> &ptr_to_set,
                           std::map <uint32_t, float> &liveness,
                           std::map <DuaKey,Dua> &duas,
                           float max_liveness,
                           uint32_t max_tcn,
                           uint32_t max_card,
                           PGconn *conn) {
    assert (ple != NULL);
    Panda__TaintQueryHypercall *tqh = ple->taint_query_hypercall;
    assert (tqh != NULL);
    // size of query in bytes & num tainted bytes found
    uint32_t len = tqh->len;
    uint32_t num_tainted = tqh->num_tainted;
    // entry 1 is source info
    Panda__SrcInfo *si = tqh->src_info;
    assert (si != NULL);
    // entry 2 is callstack -- ignore
    Panda__CallStack *cs = tqh->call_stack;
    assert (cs != NULL);
    uint64_t instr = ple->instr;
    if (debug) printf ("TAINT QUERY HYPERCALL len=%d num_tainted=%d\n", len, num_tainted);
    std::set<uint32_t> labels;
    std::set <uint32_t> ok_bytes;
    // keep track of min / max for each of these measures over all bytes
    // in this queried lval
    float c_max_liveness = 0.0;
    uint32_t c_max_tcn, c_max_card;
    c_max_tcn = c_max_card = 0;    
    std::vector<ByteTaint> viable_bytes;
    for (uint32_t i=0; i<tqh->n_taint_query; i++) {
        Panda__TaintQuery *tq = tqh->taint_query[i];        
        if (tq->unique_label_set) {
            // this one tells us about a new unique taint label set
            update_unique_taint_sets(tq->unique_label_set, ptr_to_set);
        }
        /*
          this taint query is for a byte on the current extent under consideration
          offset is where it is in the original extent queried.
          We will decide that this byte is useable iff
          1. tcn is low enough (indicating that this byte is not too computationally 
          distant from input)
              2. cardinality is low enough (indicating this byte not too compilcated a fn of inpu?)
              3. none of the labels in this byte's taint label set has a liveness score that is too high
        */            
        uint32_t offset = tq->offset;
        // flag for tracking *why* we discarded a byte
        uint32_t current_byte_not_ok = 0;
        current_byte_not_ok |= 
            (((tq->tcn > max_tcn) << CBNO_TCN_BIT)
             | ((ptr_to_set[tq->ptr].size() > max_card) << CBNO_CRD_BIT));
        if (current_byte_not_ok == 0) {
            // this byte is still ok -- check liveness
            Ptr p = tq->ptr;
            assert (ptr_to_set.count(p) != 0);
            assert (ptr_to_set[p].size() != 0);
            // check for too-live data on any label from which this byte derives
            for ( uint32_t l : ptr_to_set[p] ) {
                current_byte_not_ok |= ((liveness[l] > max_liveness) << CBNO_LVN_BIT);
                if (current_byte_not_ok != 0) break;
                // collect set of labels on ok bytes for the entire extent
                labels.insert(l);       
                // max liveness of a taint label for this lval
                c_max_liveness = std::max(liveness[l],c_max_liveness);
            }
        }
        if (current_byte_not_ok) {
            // we are discarding this byte
            if (debug) {
                printf ("discarding byte -- n");
                if (current_byte_not_ok & CBNO_TCN_BIT) printf ("** tcn too high\n");
                if (current_byte_not_ok & CBNO_CRD_BIT) printf ("** card too high\n");
                if (current_byte_not_ok & CBNO_LVN_BIT) printf ("** liveness too high\n");
            }
        }
        else {
            // byte is ok to retain.
            // keep track of highest tcn and card for ok bytes
            c_max_tcn = std::max(tq->tcn, c_max_tcn);
            c_max_card = std::max((uint32_t) ptr_to_set[tq->ptr].size(), c_max_card);
            if (debug) printf ("keeping byte @ offset %d\n", offset); 
            // add this byte to the list of ok bytes
            ok_bytes.insert(offset);
            ByteTaint vb = {offset, tq->ptr};            
            viable_bytes.push_back(vb);
        }
    }
    if (debug) {
        printf ("%d ok bytes in lval  %d labels\n",
                (int) ok_bytes.size(), (int) labels.size());
    }
    if ((ok_bytes.size() >= 1) && (labels.size() >= 1)) {
        // great -- extent we just looked at was deemed acceptable
        Dua dua = {
            ind2str[si->filename], 
            si->linenum, 
            ind2str[si->astnodename],
            si->insertionpoint,
            viable_bytes,           // viable, tainted bytes
            labels,       // file offsets
            ok_bytes,     // lval offsets
            inputfile,   
            c_max_liveness, c_max_tcn, c_max_card,
            0,0,instr
        };

        if (i0 == 0) {
            i0 = instr;
        }

        if (debug) {
            printf ("OK DUA.\n");
            std::cout << dua.str() << "\n";
        }
        // keeping track of dead, uncomplicated data extents we have
        // encountered so far in the trace
        assert (si->has_insertionpoint);
        // this key distinguishes between duas that correspond to the same source code modification
        DuaKey key = {si->filename, si->linenum, si->astnodename, si->insertionpoint};        
        if (dua_id.count(key) == 0) {
            // new dua (in terms of src mod)
            dua_id[key] = postgres_new_dua(conn, dua);
            duas[key] = dua;
            if (debug) printf ("dua is new (by src mod).  Adding id %d\n", dua_id[key]);
        }
        else {
            // we've added dua before that corresponds to this same src change
            // so now we need to replace
            postgres_replace_dua(conn, dua, dua_id[key]);
            duas[key] = dua; 
            if (debug) printf ("dua is old (by src mod):  Replacing id %d\n", dua_id[key]);
       }        
    }
    else {
        if (debug) printf ("discarded %d ok bytes  %d labels\n", (int) ok_bytes.size(), (int) labels.size());
    }
}

// update liveness measure for each of taint labels (file bytes) associated with a byte in lval that was queried
void update_liveness(Panda__LogEntry *ple,    
                     std::map<Ptr,std::set<uint32_t>> &ptr_to_set,
                     std::map <uint32_t, float> &liveness) {
    assert (ple != NULL);
    Panda__TaintedBranch *tb = ple->tainted_branch;
    assert (tb != NULL);
    if (debug) printf ("TAINTED BRANCH\n");
    for (uint32_t i=0; i<tb->n_taint_query; i++) {
        Panda__TaintQuery *tq = tb->taint_query[i];
        assert (tq);
        if (tq->unique_label_set) {
            // this one tells us about a new unique taint label set
            update_unique_taint_sets(tq->unique_label_set, ptr_to_set);
        }
        if (debug) {
            spit_tq(tq);
            printf ("\n");
        }
        // this tells us what byte in the extent this query was for
        //        uint32_t offset = tq->offset;
        Ptr p = tq->ptr;
        for ( uint32_t l : ptr_to_set[p] ) {
            liveness[l] ++;
        }
    }
}


// determine if this dua is viable
bool check_dua_viability (Dua &dua, std::map <uint32_t,float> &liveness,
                          std::map<Ptr,std::set<uint32_t>> &ptr_to_set,
                          float max_liveness) {                         
    std::vector<ByteTaint> new_viable_bytes;
    if (debug)
        printf ("checking viability of dua: currently %d viable bytes\n",
                (int) dua.viable_bytes.size());
    for (auto vb : dua.viable_bytes) {
        // vb is a viable byte of this lval.
        // liveness is below threshold and its tainted
        uint32_t off = vb.offset;
        Ptr ts = vb.taintset;
        bool viable = true;
        // iterate over file offsets (labels) in taint set
        for (auto l : ptr_to_set[ts]) {
            if (liveness[l] > max_liveness) {
                // this byte is no longer viable; liveness for one
                // of the file offsets from which it derives is too high
                if (debug)
                    printf ("byte offset=%d is nonviable b/c label %d has liveness %.3f",
                            off, l, liveness[l]);
                viable = false;
                break;
            }
        }
        if (viable) {
            new_viable_bytes.push_back(vb);
        }
    }
    dua.viable_bytes = new_viable_bytes;
    if (debug) printf ("dua has %d viable bytes\n", (int) new_viable_bytes.size());
    // dua is viable iff it has more than one viable byte
    return (new_viable_bytes.size() > 1);
}



uint32_t num_bugs = 0;


std::set<BugKey> bugs;


/*
  we are at an attack point
  iterate over all currently viable duas and
  look for bug inj opportunities
*/
void find_bug_inj_opportunities(Panda__LogEntry *ple,
                                std::map <DuaKey,Dua> &duas,                                
                                std::map <Ptr,std::set<uint32_t>> &ptr_to_set,
                                std::map <uint32_t,float> &liveness,
                                float max_liveness,
                                PGconn *conn) {
    assert (ple != NULL);
    uint64_t instr = ple->instr;
    Panda__AttackPoint *pleatp = ple->attack_point;
    assert (pleatp != NULL);
    Panda__SrcInfo *si = pleatp->src_info;
    assert (si != NULL);
    if (debug) printf ("ATTACK POINT\n");
    if (duas.size() == 0) {
        if (debug) printf ("no duas yet -- discarding atp\n");
        return;
    }
    std::set <DuaKey> non_viable_duas;
    if (debug)  printf ("checking viability of %d duas\n", (int) duas.size());
    for (auto kvp : duas) {
        DuaKey dk = kvp.first;
        Dua dua = kvp.second;
        // is this dua still viable?
        if (!(check_dua_viability(dua, liveness, ptr_to_set, max_liveness))) {
            if (debug) printf (" ** DUA %d not viable\n", dua_id[dk]);
            non_viable_duas.insert(dk);
        }
    }
    if (debug) printf ("Found %d nonviable duas \n", (int) non_viable_duas.size());
    // discard unviable duas
    for (auto dk : non_viable_duas) {
        duas.erase(dk);
    }
    AttackPoint atp = {ind2str[si->filename], si->linenum, ind2str[pleatp->info]};      
    AttackPointKey atpk = {si->filename, si->linenum, pleatp->info};
    if (atp_id.count(atp) == 0) {
        // new attack point
        atp_id[atp] = postgres_dump_atp(conn, atp);
        if (debug) printf ("** new ATP id %d\n", atp_id[atp]);
    }
    if (debug) {
        std::cout << "@ ATP: " << atp.str() << "\n";
    }
    uint32_t num_bugs_added_to_db = 0;
    // every viable dua is a bug inj opportunity at this point in trace
    for ( auto kvp : duas ) {
        DuaKey dk = kvp.first;
        BugKey b = {dk, atpk};
        if (debug) {
            printf ("considering bug {dua_id=%d atp_id=%d} \n", dua_id[dk], atp_id[atp]);
        }
        if (bugs.count(b) == 0) {
            // this is a new bug 
            bugs.insert(b);
            /*
            std::cout << "dua: " << duas[dk].str() << "\n";
            std::cout << "atp: " << atp.str() << "\n";
            */
            //            if (debug) {
            uint64_t i1 = duas[dk].instr ;
            uint64_t i2 = instr ;
            float rdf_frac = ((float)i1) / ((float)i2);
            printf ("new bug.  Added to db:  bug -- %d %d i1=%" PRId64 " i2=%" PRId64 " rdf_frac=%.5f\n",  dua_id[dk], atp_id[atp], i1, i2, rdf_frac);            
                //            }                                  
            add_bug_to_db(conn, dua_id[dk], atp_id[atp]);
            num_bugs_added_to_db ++;
        }
        else {
            if (debug) {
                printf ("not a new bug\n");
            }
        }

    }
    printf ("instr  %" PRId64 " -- %d viable duas -- ", instr, (int) duas.size());
    printf ("Added %d new bugs to db -- ", num_bugs_added_to_db);
    printf ("total of %d injectable bugs\n", (int) bugs.size());
   
}


int main (int argc, char **argv) {

    if (argc != 8) {
        printf ("usage: fbi plog lavadb max_liveness max_card max_tcn inputfile src_pfx\n");
        exit (1);
    }

    // panda log file
    char *plf = argv[1];

    // maps from ind -> (filename, lvalname, attackpointname)
    ind2str = LoadIDB(argv[2]);
    printf ("%d strings in lavadb\n", (int) ind2str.size());
    
    get_last_instr(plf);

    float max_liveness = atof(argv[3]);
    printf ("maximum liveness score of %.2f\n", max_liveness);

    uint32_t max_card = stou(argv[4]);
    printf ("max card of taint set returned by query = %d\n", max_card);

    uint32_t max_tcn = stou(argv[5]);
    printf ("max tcn for addr = %d\n", max_tcn);

    inputfile = std::string(argv[6]);

    src_pfx = std::string(argv[7]);

    std::map <uint32_t, float> liveness;

    PGconn *conn = pg_connect();    

    inputfile_id = addstr(conn, "inputfile", inputfile);
    
    /*
     re-read pandalog, this time focusing on taint queries.  Look for
     dead available data, attack points, and thus bug injection oppotunities
    */

    pandalog_open(plf, "r");
    std::map <Ptr, std::set<uint32_t> > ptr_to_set;
    uint64_t ii=0;
    std::map <DuaKey,Dua> duas;
    std::set <AttackPoint> u_atp;
    std::set <Bug> injectable_bugs;
    
    while (1) {
        // collect log entries that have same instr count (and pc).
        // these are to be considered together.
        Panda__LogEntry *ple = pandalog_read_entry();
        if (ple == NULL)  break;
        ii ++;
        if ((ii % 10000) == 0) {
            printf ("processed %lu pandalog entries.", ii);
        }
        if (ple->taint_query_hypercall) {
            taint_query_hypercall(ple, ptr_to_set, liveness, duas, max_liveness,
                                  max_tcn, max_card, conn);
        }
        if (ple->tainted_branch) {
            update_liveness(ple, ptr_to_set, liveness);
        }
        if (ple->attack_point) {
            find_bug_inj_opportunities(ple, duas, ptr_to_set,
                                       liveness, max_liveness, conn);
        }
    }
    
    pandalog_close();

/*
    printf ("%u queried extents\n", num_queried_extents);

    printf ("%u dead-uncomplicated-available-data.  %u attack-points\n",
            (uint32_t) u_dua.size(), (uint32_t) u_atp.size());

    printf ("%u injectable bugs\n", (uint32_t) injectable_bugs.size());

    PGresult   *res;

    postgresql_dump_duas(conn,u_dua);
    postgresql_dump_atps(conn,u_atp);
    postgresql_dump_bugs(conn,injectable_bugs);
    PQfinish(conn);
*/
}




