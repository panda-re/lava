/*
  NB: env variable PANDA points to git/panda
  
  g++ -g -o fbi   find_bug_inj.cpp  \
    ../sql/lava_sql.cpp \
    ../src_clang/lavaDB.cpp \
    ../../panda/qemu/panda/pandalog.c \
    ../../panda/qemu/panda/pandalog.pb-c.c \
    ../../panda/qemu/panda/pandalog_print.c \
    -L/usr/local/lib -lprotobuf-c  -I ../../panda/qemu -I ../../panda/qemu/panda  -lz -D PANDALOG_READER  -std=c++11  -O2 -lpq
    
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

}

#include <json/json.h>

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <sstream>
#include <algorithm>
#include "pandalog.h"
#include "pandalog_print.h"
#include "../src_clang/lavaDB.h"
#include "../include/lava_bugs.h"

#define CBNO_TCN_BIT 0
#define CBNO_CRD_BIT 1
#define CBNO_LVN_BIT 2

// number of bytes in lava magic value used to trigger bugs
#define LAVA_MAGIC_VALUE_SIZE 4

std::string inputfile;
std::string src_pfx;
int inputfile_id;
std::map<uint32_t,std::string> ind2str;

bool debug = true;

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


// postgres unique ids for dua and attack point 
std::map<Dua,int> dua_id;
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


// returns -1 if dua isnt there.  else returns dua_id
int postgres_get_dua_id(PGconn *conn, Dua &dua) {
    PGresult *res;
    // add source filename to sourcefile table
    std::string filename = dua.filename;
    int filename_id = addstr(conn, "sourcefile", strip_pfx(filename, src_pfx));
    std::string lvalname = dua.lvalname;
    int lval_id = addstr(conn, "lval", lvalname);
    std::stringstream sql;
    sql << "SELECT dua_id from dua where "
        << " filename_id = " << filename_id 
        << " and line = " << dua.line   
        << " and lval_id = " << lval_id 
        << " and insertionpoint = " << dua.insertionpoint
        << " and file_offset = " << "'{" << iset_str(dua.file_offsets) << "}'" 
        << " and lval_taint = " << "'{" << pvec_str(dua.lval_taint) << "}'" 
        << " and inputfile_id = " << inputfile_id
        << " and max_liveness = " << dua.max_liveness
        << " and max_tcn = " << dua.max_tcn
        << " and max_card = " << dua.max_card 
        << " and instr = " << dua.instr << ";";
    res = pg_exec_ss(conn,sql);
    assert (PQresultStatus(res) == PGRES_TUPLES_OK);
    if (PQntuples(res) == 1) {
        return stou(PQgetvalue(res, 0, 0));
    }
    else return -1;
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
    sql << "INSERT INTO dua (filename_id,line,lval_id,insertionpoint,file_offset,lval_taint,inputfile_id,max_tcn,max_card,max_liveness,dua_icount,dua_scount,instr) VALUES ("
        << filename_id << ","
        << dua.line << ","  
        << lval_id << ","
        << dua.insertionpoint << ","
        // offsets within the input file that taint dua
        << "'{" << iset_str(dua.file_offsets) << "}'" << ","
        // a list of ptrs to taint sets. 0 means this byte in the lval in untainted
        << "'{" << pvec_str(dua.lval_taint) << "}'" << ","
        << inputfile_id << ","
        << dua.max_tcn << "," << dua.max_card << "," << dua.max_liveness
        << ",0,0, "
        << dua.instr << ") RETURNING dua_id;";
    res = pg_exec_ss(conn,sql);
    int n = -1;
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        n = (int) stou(PQgetvalue(res, 0, 0));
        if (debug) std::cout << "Added to db id=" << n << " DUA = [" << dua.str() << "]\n";
    }
    PQclear(res);
    return n;
}


int postgres_get_atp_id(PGconn *conn, AttackPoint &atp) {
    PGresult *res;
    // add source filename to sourcefile table
    std::string filename = atp.filename;
    int filename_id = addstr(conn, "sourcefile", strip_pfx(filename, src_pfx));
    std::string info = atp.typ;
    int typ_id = addstr(conn, "atptype", info);
    std::stringstream sql;
    sql << "SELECT atp_id from atp where " // (filename_id,line,typ_id,inputfile_id,atp_icount,atp_scount) VALUES ("
        << " filename_id = " << filename_id 
        << " and line = " << atp.line 
        << " and typ_id = " << typ_id 
        << " and inputfile_id = " << inputfile_id << ";";
    res = pg_exec_ss(conn,sql);
    assert (PQresultStatus(res) == PGRES_TUPLES_OK);
    if (PQntuples(res) == 1) {
        return stou(PQgetvalue(res, 0, 0));
    }
    else return -1;
}
    

// returns atp_id assigned by postgres
// -1 if non (error or already there)
int postgres_new_atp(PGconn *conn, AttackPoint &atp) {
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


// add bug corresponding to this dua / atp combo to db
// add the dua & atp first, if necessary
// ... unless its already there in which case we don't add it
// returns True iff this is a new bug
bool add_bug_to_db(PGconn *conn, Dua &dua, AttackPoint &atp, BugKey &b) {
    std::stringstream sql;
    int did = postgres_get_dua_id(conn, dua);
    if (did == -1) {
        did = postgres_new_dua(conn, dua);
        dua_id[dua] = did; 
    }
    int aid = postgres_get_atp_id(conn, atp);
    if (aid == -1 ) {
        aid = postgres_new_atp(conn, atp);
        atp_id[atp] = aid;
    }
    assert (did != -1);
    assert (aid != -1);
    // is the bug already there?
    sql << "SELECT * from bug where dua_id = " << did
        << " and atp_id = " << aid << ";";
    PGresult *res = pg_exec_ss(conn,sql);
    assert (PQresultStatus(res) == PGRES_TUPLES_OK);
    if (PQntuples(res) == 1) {
        if (debug) printf ("bug is already in db\n");
        PQclear(res);
        return false;
    }
    // is the bug there from a previous run?
    int dua_filename_id = addstr(conn, "sourcefile", strip_pfx(ind2str[b.dk.filename], src_pfx));
    int dua_lval_id = addstr(conn, "lval", ind2str[b.dk.astnodename]);
    int atp_filename_id = addstr(conn, "sourcefile", strip_pfx(ind2str[b.atpk.filename], src_pfx));
    int atp_typ_id = addstr(conn, "atptype", ind2str[b.atpk.typ]);
    sql.str("");
    sql.clear();
    sql << "INSERT INTO bugkey (dua_filename_id, dua_line, dua_lval_id, dua_insertionpoint, dua_file_offset, atp_filename_id, atp_line, atp_typ_id) VALUES (";
    sql << dua_filename_id << ","
        << b.dk.linenum << ","
        << dua_lval_id << ","
        << b.dk.insertionpoint << ","
        << "'{" << iset_str(b.dk.lval_offsets_tainted) << "}'" << ","
        << atp_filename_id << ","
        << b.atpk.line << ","
        << atp_typ_id << ");";
    res = pg_exec_ss(conn,sql);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        if (std::string(PQresultErrorMessage(res)).find("duplicate key value") != std::string::npos) {
            return false;
        }
        else {
            // Some other error - fail!
            printf("Fatal postgresql error %s: %s\n", PQresStatus(PQresultStatus(res)), PQresultErrorMessage(res));
            assert(false);
        }
    }

    printf ("-----------------------------------------------------\n");
    printf ("Adding new bug to db.  dua_id = %d  atp_id = %d\n", did, aid);
    std::cout << "Dua:\n" << dua.str() << "\n";
    std::cout << "Atp:\n" << atp.str() << "\n";
    // we don't need to get bug_id back
    sql.str("");
    sql.clear();
    sql << "INSERT INTO bug (dua_id,atp_id,inj) VALUES ("
        << did << "," << aid <<
        ",false) returning bug_id;";
    PQclear(res);
    res = pg_exec_ss(conn,sql);
    int bug_id = -1;
    assert (PQresultStatus(res) == PGRES_TUPLES_OK);
    bug_id = stou(PQgetvalue(res, 0, 0));
    std::cout << "bug_id = " << bug_id << "\n";
    printf ("-----------------------------------------------------\n");
    PQclear(res);
    return true;
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


void update_unique_taint_sets(PGconn *conn, Panda__TaintQueryUniqueLabelSet *tquls, uint32_t max_card,
                              std::map<Ptr,std::set<uint32_t>> &ptr_to_set) {                                
    if (debug) {
        printf ("UNIQUE TAINT SET\n");
        spit_tquls(tquls);
        printf ("\n");
    }
    // maintain mapping from ptr (uint64_t) to actual set of taint labels 
    uint32_t i;
    Ptr p = tquls->ptr;
    if (ptr_to_set.count(p) == 0) {
        // new taint set
        for (i=0; i<tquls->n_label; i++) {
            uint32_t l = tquls->label[i];
            ptr_to_set[p].insert(l);
        }
        // Don't try to put huge taint sets into the db
        if (tquls->n_label <= max_card) {
            std::stringstream sql;
            sql << "INSERT INTO unique_taint_set (ptr,file_offset,inputfile_id) VALUES ("
                << p << ","
                << "'{" << iset_str(ptr_to_set[p]) << "}',"
                << inputfile_id << ");";
            PGresult *res = pg_exec_ss(conn,sql);
            assert (PQresultStatus(res) == PGRES_COMMAND_OK);
        }
    }
    if (debug) printf ("%d unique taint sets\n", ptr_to_set.size());
}


uint32_t count_viable_bytes(std::map<uint32_t, Ptr> viable_byte) {
    uint32_t num_viable = 0;
    for ( auto kvp : viable_byte) {
        Ptr p = kvp.second;
        num_viable += (p!=0);
    }
    return num_viable;
}

uint32_t count_viable_bytes2(std::vector<Ptr> viable_byte) {
    uint32_t num_viable = 0;
    for ( auto p : viable_byte) num_viable += (p!=0);
    return num_viable;
}

void taint_query_hypercall(Panda__LogEntry *ple,
                           std::map<Ptr,std::set<uint32_t>> &ptr_to_set,
                           std::map <uint32_t, float> &liveness,
                           std::map <DuaKey,Dua> &duas,
                           float max_liveness,
                           uint32_t max_tcn,
                           uint32_t max_card,
                           uint32_t max_lval,
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
    bool ddebug = true;
    
    // entry 2 is callstack -- ignore
    Panda__CallStack *cs = tqh->call_stack;
    assert (cs != NULL);
    uint64_t instr = ple->instr;
    if (debug) printf ("TAINT QUERY HYPERCALL len=%d num_tainted=%d\n", len, num_tainted);
    // collects set of labels on all viable bytes that are actually used in dua
    std::set<uint32_t> labels;
    // keep track of min / max for each of these measures over all bytes
    // in this queried lval
    float c_max_liveness = 0.0;
    uint32_t c_max_tcn, c_max_card;
    c_max_tcn = c_max_card = 0;
    // if lval is 12 bytes, this vector will have 12 elements
    // viable_byte[i] is 0 if it is NOT viable
    // otherwise it is a ptr to a taint set.
    std::map<uint32_t, Ptr> viable_byte;
    // consider all bytes in this extent that were queried and found to be tainted
    // collect "ok" bytes, which have low enough taint compute num and card,
    // and also aren't tainted by too-live input bytes
    uint32_t max_offset = 0;
    // determine largest offset into this lval
    if (ddebug) pprint_taint_query_hypercall(tqh);
    for (uint32_t i=0; i<tqh->n_taint_query; i++) {
        Panda__TaintQuery *tq = tqh->taint_query[i];        
        // offset w/in lval for the byte that was queried for taint
        uint32_t offset = tq->offset;
        max_offset = std::max(offset,max_offset);
    }
    if (ddebug) printf ("max_offset = %d\n", max_offset);
    if (ddebug) printf ("considering taint queries on %d bytes\n", tqh->n_taint_query);
    // go through and deal with new unique taint sets first
    for (uint32_t i=0; i<tqh->n_taint_query; i++) {
        Panda__TaintQuery *tq = tqh->taint_query[i];        
        uint32_t offset = tq->offset;    
        if (ddebug) printf ("offset = %d\n", offset);
        if (tq->unique_label_set) {
            // collect new unique taint label sets
            update_unique_taint_sets(conn, tq->unique_label_set, max_card, ptr_to_set);
        }
    }
    // bdg: don't try handle lvals that are bigger than our max lval
    // NB: must do this *after* dealing with unique taint sets
    if (max_offset > max_lval) return;
    for (uint32_t i=0; i<tqh->n_taint_query; i++) {
        Panda__TaintQuery *tq = tqh->taint_query[i];        
        uint32_t offset = tq->offset;    
        viable_byte[offset] = 0;
        // flag for tracking *why* we discarded a byte
        uint32_t current_byte_not_ok;
        // check tcn and cardinality of taint set first
        current_byte_not_ok = (((tq->tcn > max_tcn) << CBNO_TCN_BIT)
                               | ((ptr_to_set[tq->ptr].size() > max_card) << CBNO_CRD_BIT));
        float current_byte_max_liveness = 0.0;
        if (current_byte_not_ok == 0) {
            if (ddebug) printf ("tcn and card ok.  checking liveness\n");
            // check for too-live taint label associated with this byte
            Ptr p = tq->ptr;
            for ( uint32_t l : ptr_to_set[p] ) {
                current_byte_not_ok |= ((liveness[l] > max_liveness) << CBNO_LVN_BIT);
                current_byte_max_liveness = std::max(liveness[l], current_byte_max_liveness);
                // dont bother looking at any more labels if we've seen one thats too live
                if (current_byte_not_ok != 0) {
                    if (ddebug) printf ("label %d is too live (%d). discarding byte\n", l, liveness[l]);
                    break;
                }
            }             
        }
        if (current_byte_not_ok) {
            // discard this byte
            if (debug) {
                printf ("discarding byte -- here's why: %x\n", current_byte_not_ok);
                if (current_byte_not_ok & (1<<CBNO_TCN_BIT)) printf ("** tcn too high\n");
                if (current_byte_not_ok & (1<<CBNO_CRD_BIT)) printf ("** card too high\n");
                if (current_byte_not_ok & (1<<CBNO_LVN_BIT)) printf ("** liveness too high\n");
            }
        }
        else {
            if (ddebug) printf ("retaining byte\n");
            // this byte is ok to retain.            
            // keep track of highest tcn, liveness, and card for any viable byte for this lval
            c_max_tcn = std::max(tq->tcn, c_max_tcn);
            c_max_card = std::max((uint32_t) ptr_to_set[tq->ptr].size(), c_max_card);
            c_max_liveness = std::max(current_byte_max_liveness, c_max_liveness);            
            // collect set of labels on all ok bytes for this extent
            // remember: labels are offsets into input file
            // NB: only do this for bytes that will actually be used in the dua
            Ptr p = tq->ptr;
            for ( uint32_t l : ptr_to_set[p] ) {
                labels.insert(l);
            }        
            if (debug) printf ("keeping byte @ offset %d\n", offset); 
            // add this byte to the list of ok bytes
            viable_byte[offset] = tq->ptr;
        }
        // we can stop examining query when we have enough viable bytes
        if (count_viable_bytes(viable_byte) >= LAVA_MAGIC_VALUE_SIZE) break;
    }
    uint32_t num_viable = count_viable_bytes(viable_byte);
    if (debug) {
        printf ("%d viable bytes in lval  %d labels\n",
                num_viable, (int) labels.size());
    }
    // we need # of unique labels to be at least 4 since
    // that's how big our 'lava' key is
    //    printf ("num_viable = %d\n", num_viable);
    if ((num_viable == LAVA_MAGIC_VALUE_SIZE) && (labels.size() == LAVA_MAGIC_VALUE_SIZE)) {
        assert (c_max_liveness <= max_liveness);
        // tainted lval we just considered was deemed viable
        std::vector<Ptr> viable_byte_vec;
        for (uint32_t i=0; i<=max_offset; i++) {
            viable_byte_vec.push_back(viable_byte[i]);
        }
        uint32_t x=0;
        for (uint32_t i=0; i<=max_offset; i++) {
            x += (viable_byte_vec[i] !=0);
        }
        assert (x == LAVA_MAGIC_VALUE_SIZE);
        Dua dua = {
            ind2str[si->filename], 
            si->linenum, 
            ind2str[si->astnodename],
            si->insertionpoint,
            labels,                 // file offsets
            viable_byte_vec,            
            inputfile,   
            c_max_tcn, c_max_card, c_max_liveness, 
            0,0,instr
        };
        if (debug) {
            printf ("OK DUA.\n");
            std::cout << dua.str() << "\n";
        }
        // keeping track of dead, uncomplicated data extents we have
        // encountered so far in the trace
        assert (si->has_insertionpoint);
        // this is set of lval offsets that will be used to construct the dua
        // and thus is part of what determines the precise src mods
        std::set<uint32_t> viable_offsets;
        for (auto kvp : viable_byte) {
            uint32_t i = kvp.first;
            Ptr p = kvp.second;
            if (p != 0) viable_offsets.insert(i);
        }
        //        printf ("viable_offsets size = %d\n", viable_offsets.size());
        assert (viable_offsets.size() == LAVA_MAGIC_VALUE_SIZE);
        /*
        // keep only the first MAX_TAINTED_LVAL_BYTES
        std::set<uint32_t> viable_offsets;
        uint32_t ni = 0;
        for (auto o : viable_offsets) {
            viable_offsets.insert(o);
            ni++;
            if (ni == MAX_TAINTED_LVAL_BYTES) break;
        }
        */
        
        // Maintain map from dua key (which represents a unique src modification @ dua site)
        // and the most recent incarnation of that dua that we have observed.
        
        
        DuaKey d_key = {si->filename, si->linenum, si->astnodename, si->insertionpoint, viable_offsets};        
        if (debug) {
            if (duas.count(d_key)==0) printf ("new dua key\n");
            else printf ("previously observed dua key\n");
        }
        duas[d_key] = dua;
    }
    else {
        if (debug) {
            std::cout << "discarded " << num_viable << " viable bytes "
                      << labels.size() << " labels "
                      << ind2str[si->filename] << " "
                      << si->linenum << " "
                      << ind2str[si->astnodename] << " "
                      << si->insertionpoint << "\n";
        }
    }
}


// update liveness measure for each of taint labels (file bytes) associated with a byte in lval that was queried
void update_liveness(Panda__LogEntry *ple,    
                     std::map<Ptr,std::set<uint32_t>> &ptr_to_set,
                     std::map <uint32_t, float> &liveness,
                     uint32_t max_card,
                     PGconn *conn) {
    assert (ple != NULL);
    Panda__TaintedBranch *tb = ple->tainted_branch;
    assert (tb != NULL);
    if (debug) printf ("TAINTED BRANCH\n");
    for (uint32_t i=0; i<tb->n_taint_query; i++) {
        Panda__TaintQuery *tq = tb->taint_query[i];
        assert (tq);
        if (tq->unique_label_set) {
            // keep track of unique taint label sets
            update_unique_taint_sets(conn, tq->unique_label_set, max_card, ptr_to_set);
        }
        if (debug) {
            spit_tq(tq);
            printf ("\n");
        }
        // this tells us what byte in the extent this query was for
        for ( uint32_t l : ptr_to_set[tq->ptr] ) {
            liveness[l] ++;
        }
    }
}


// determine if this dua is viable
bool is_dua_viable (Dua &dua, std::map <uint32_t,float> &liveness,
                    std::map<Ptr,std::set<uint32_t>> &ptr_to_set,
                    float max_liveness) {                         
    if (debug)
        printf ("checking viability of dua: currently %d viable bytes\n",
                count_viable_bytes2(dua.lval_taint));

    std::vector<Ptr> new_viable_byte;
    // NB: we have already checked dua for viability wrt tcn & card at induction
    // these do not need re-checking as they are to be captured at dua siphon point
    // Note, also, that we are only checking the 4 or so bytes that were previously deemed viable
    uint32_t num_viable = 0;
    for (uint32_t off=0; off<dua.lval_taint.size(); off++) {
        Ptr ts = dua.lval_taint[off];
        bool viable = true;
        if (ts == 0) viable = false;
        if (viable) {
            // determine if liveness for this offset is still low enough
            for (auto l : ptr_to_set[ts]) {
                if (liveness[l] > max_liveness) {
                    if (debug)
                        printf ("byte offset=%d is nonviable b/c label %d has liveness %.3f\n",
                                off, l, liveness[l]);
                    viable = false;
                    break;
                }
            }
        }
        // NB: 0 indicates untainted & nonviable
        if (viable) {
            new_viable_byte.push_back(ts);
            num_viable ++;
        }
        else
            new_viable_byte.push_back(0);
        if (num_viable == LAVA_MAGIC_VALUE_SIZE) 
            break;
    }
    dua.lval_taint = new_viable_byte;    
    if (debug) {
        std::cout << dua.str() << "\n";
        printf ("dua has %d viable bytes\n", num_viable);
    }
    // dua is viable iff it has more than one viable byte
    return (num_viable == LAVA_MAGIC_VALUE_SIZE);
}



uint32_t num_bugs = 0;


std::set<BugKey> bugs;

uint64_t num_bugs_local = 0;
uint64_t num_bugs_added_to_db = 0;
uint64_t num_bugs_attempted = 0;

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
        if (debug) printf ("no duas yet -- discarding attack point\n");
        return;
    }
    std::vector <DuaKey> non_viable_duas;
    if (debug)  printf ("checking viability of %d duas\n", (int) duas.size());
    // collect list of nonviable duas
    for (auto kvp : duas) {
        DuaKey dk = kvp.first;
        Dua dua = kvp.second;
        // is this dua still viable?
        if (!(is_dua_viable(dua, liveness, ptr_to_set, max_liveness))) {
            if (debug) {
                std::cout << dua.str() << "\n";
                printf (" ** DUA not viable\n");
            }
            non_viable_duas.push_back(dk);
        }
    }
    if (debug) printf ("%d non-viable duas \n", (int) non_viable_duas.size());
    // discard non-viable duas
    for (auto dk : non_viable_duas) {
        duas.erase(dk);
    }
    if (debug) printf ("%d viable duas remain\n", (int) duas.size());
    AttackPoint atp = {ind2str[si->filename], si->linenum, ind2str[pleatp->info]};      
    AttackPointKey atpk = {si->filename, si->linenum, pleatp->info};
    if (debug) {
        std::cout << "@ ATP: " << atp.str() << "\n";
    }
    // every still viable dua is a bug inj opportunity at this point in trace
    for ( auto kvp : duas ) {
        DuaKey dk = kvp.first;
        Dua dua = kvp.second;
        BugKey b = {dk, atpk};
        if (bugs.count(b) == 0) {
            // this is a new bug (new src mods for both dua and atp)
            bugs.insert(b);

            assert (dua.max_liveness < max_liveness);

            bool newb = add_bug_to_db(conn, dua, atp, b);
            if (newb) {
                uint64_t i1 = duas[dk].instr ;
                uint64_t i2 = instr ;
                float rdf_frac = ((float)i1) / ((float)i2);
                std::cout << "i1=" << i1 << " i2=" << i2 << " rdf_frac=" << rdf_frac << "\n";
                num_bugs_added_to_db ++;
            }                                  
            num_bugs_local ++;
        }
        else {
            if (debug) {
                printf ("not a new bug\n");
            }
        }
        num_bugs_attempted ++;
    }
}


int main (int argc, char **argv) {
    if (argc != 5) {
        printf ("usage: fbi project.json src_pfx pandalog inputfile\n");
        printf("    src_pfx: Prefix of source tree from lavaTool queries, so we can strip it\n");
        printf("    JSON file should have properties:\n");
        printf("        max_liveness: Maximum liveness for DUAs\n");
        printf("        max_cardinality: Maximum cardinality for labelsets on DUAs\n");
        printf("        max_tcn: Maximum taint compute number for DUAs\n");
        printf("        max_lval_size: Maximum bytewise size for \n");
        printf("    pandalog: Pandalog. Should be like queries-file-5.22-bash.iso.plog\n");
        printf("    inputfile: Input file basename, like malware.pcap");
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
    printf ("%d strings in lavadb\n", (int) ind2str.size());
    float max_liveness = root["max_liveness"].asFloat();
    printf ("maximum liveness score of %.2f\n", max_liveness);
    uint32_t max_card = root["max_cardinality"].asUInt();
    printf ("max card of taint set returned by query = %d\n", max_card);
    uint32_t max_tcn = root["max_tcn"].asUInt();
    printf ("max tcn for addr = %d\n", max_tcn);
    uint32_t max_lval = root["max_lval_size"].asUInt();
    printf ("max lval size = %d\n", max_lval);
    inputfile = std::string(argv[4]);
    src_pfx = std::string(argv[2]);
    std::map <uint32_t, float> liveness;
    PGconn *conn = pg_connect(root["dbhost"].asString(), root["db"].asString());
    inputfile_id = addstr(conn, "inputfile", inputfile);
    /*
     re-read pandalog, this time focusing on taint queries.  Look for
     dead available data, attack points, and thus bug injection oppotunities
    */
    pandalog_open(plf, "r");
    std::map <Ptr, std::set<uint32_t>> ptr_to_set;
    uint64_t ii=0;
    // currently believed to be viable duas, keyed by unique src mod
    std::map <DuaKey,Dua> duas;
    while (1) {
        // collect log entries that have same instr count (and pc).
        // these are to be considered together.
        Panda__LogEntry *ple = pandalog_read_entry();
        if (ple == NULL)  break;
        ii ++;
        if ((ii % 10000) == 0) {
            printf ("processed %lu pandalog entries \n", ii);
            std::cout << num_bugs_added_to_db << " added to db " << num_bugs_local << " local bugs " << num_bugs_attempted << " total attempted. " << (duas.size()) << " duas\n";
        }
        if (ple->taint_query_hypercall) {
            taint_query_hypercall(ple, ptr_to_set, liveness, duas, max_liveness,
                                  max_tcn, max_card, max_lval, conn);
        }
        if (ple->tainted_branch) {
            update_liveness(ple, ptr_to_set, liveness, max_card, conn);
        }
        if (ple->attack_point) {
            find_bug_inj_opportunities(ple, duas, ptr_to_set,
                                       liveness, max_liveness, conn);
        }
        pandalog_free_entry(ple);
    }
    std::cout << num_bugs_added_to_db << " added to db " << num_bugs_local << " local bugs " << num_bugs_attempted << " total attempted\n";
    pandalog_close();
}




