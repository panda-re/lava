/*
  NB: env variable PANDA points to git/panda
  
  g++ -g -o fbi   find_bug_inj.cpp ../src_clang/lavaDB.cpp ../../panda/qemu/panda/pandalog.c  ../../panda/qemu/panda/pandalog.pb-c.c  -L/usr/local/lib -lprotobuf-c  -I ../../panda/qemu -I ../../panda/qemu/panda  -lz -D PANDALOG_READER  -std=c++11  -O2
  

  ml = 0.5 means max liveness of any byte on extent is 0.5
  mtcn = 10 means max taint compute number of any byte on extent is 10
  mc =4 means max card of a taint labelset on any byte on extent is 4
  min maxl  = 1 1000 means extents must be between 1 and 1000 bytes long
  
  ./fbi pandalog lavadb ml mtcn mc minl maxl

*/

#define __STDC_FORMAT_MACROS


extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "/usr/include/postgresql/libpq-fe.h"

}

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <sstream>

#include "pandalog.h"
#include "../src_clang/lavaDB.h"

std::string input_file;
int input_file_id;
std::map<uint32_t,std::string> ind2str;


typedef std::pair < Dua, AttackPoint > Bug;


Instr last_instr_count;

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
    printf ("%" PRIu64 "is last instr\n", last_instr_count);
    pandalog_close();
}
    




std::map <uint32_t, float> read_dead_data(char *pandalog_filename) {
    printf ("Reading Dead data\n");
    pandalog_open(pandalog_filename, "r");
    std::map <uint32_t, float> dd;
    while (1) {
        Panda__LogEntry *ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        if (ple->n_dead_data > 0) {
            printf ("\n");
            for (Label i=0; i<ple->n_dead_data; i++) {
                dd[i] = ple->dead_data[i];
            }
        }
        panda__log_entry__free_unpacked(ple, NULL);
    }
    pandalog_close();
    return dd;
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


static void
exit_nicely(PGconn *conn)
{
    PQfinish(conn);
    exit(1);
}




PGresult *pq_exec(PGconn *conn, std::string comm) {
    const char * cmd = (const char *) comm.c_str();
    //    printf ("sql comm=[%s]\n", cmd);
    PGresult *res = PQexec(conn, cmd);
    //    printf ("res = %d\n", PQresultStatus(res));
    return res;
}

PGresult *pq_exec_ss(PGconn *conn, std::stringstream &comm) {
    std::string comms = comm.str();
    return pq_exec(conn, comms);
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


int get_num_rows(PGconn *conn, std::string table) {
    std::string sql = "select count(*) from " + table + ";";
    PGresult *res = pq_exec(conn, (const char *) sql.c_str());
    assert (PQresultStatus(res) == PGRES_TUPLES_OK);
    uint32_t n = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return n;
}



// add this string to this table and retrieve 
// the id it got (serial row #)
// column name is "nm"
int addstr(PGconn *conn, std::string table, std::string str) {
    std::stringstream sql;
    // is str already there?
    sql << "SELECT * FROM " << table << " where nm='" << str << "';";
    PGresult *res = pq_exec_ss(conn, sql);
    if (PQntuples(res) > 0 ) {
        PQclear(res);
        //        printf ("its already there\n");
    }
    else {
        PQclear(res);
        // it isnt here.  first get number of rows in that table. that's the id
        int num_rows = get_num_rows(conn, table);
        //        printf ("num_rows = %d\n", num_rows);
        // now add id,str
        std::stringstream sql;
        sql << "INSERT INTO " << table << " (id,nm) VALUES (" << num_rows << ",'" << str << "');";                                                        
        //        printf ("sql = [%s]\n", (char *) sql.str().c_str());        
        res = pq_exec_ss(conn, sql);
        //        printf ("status = %d\n", PQresultStatus(res));
    }
    // return id assigned to str
    sql.str("");
    sql << "SELECT * FROM " << table << " where nm='" << str << "';";
    //    printf ("sql = [%s]\n", (char *) sql.str().c_str());
    res = pq_exec_ss(conn, sql);
    //    printf ("status = %d\n", PQresultStatus(res));
    uint32_t n = atoi(PQgetvalue(res, 0, 0));        
    PQclear(res);
    return n;
}



std::map<Dua,int> dua_id;
std::map<AttackPoint,int> ap_id;

void postgresql_dump_duas(PGconn *conn, std::set<Dua> &duas) {
    printf ("dumping duas to postgres\n");
    for ( auto dua : duas ) {
        PGresult *res;
        // add source filename to sourcefile table
        std::string filename = ind2str[dua.filename];
        int filename_id = addstr(conn, "sourcefile", filename);
        std::string lvalname = ind2str[dua.lvalname];
        int lval_id = addstr(conn, "lval", lvalname);
        int num_rows = get_num_rows(conn, "dua");
        std::stringstream sql;
        sql << "INSERT INTO dua (id,filename,line,lval,bytes,offsets,input_file,max_liveness,max_tcn,max_card,icount,scount) VALUES ("
            << num_rows << "," 
            << filename_id << ","
            << dua.line << ","  
            << lval_id << ","
            // offsets within the input file that taint dua
             << "'{" << iset_str(dua.labels) << "}'" << ","
            // offsets within the lval that are duas
            << "'{"  << iset_str(dua.bytes) << "}'" << ","
            << input_file_id << ","
            << dua.max_liveness << "," << dua.max_tcn << "," << dua.max_card 
            << ",0,0);";
        res = pq_exec_ss(conn,sql);
        dua_id[dua] = num_rows;
        assert (PQresultStatus(res) == PGRES_COMMAND_OK);
        PQclear(res);
    }
}
   

void postgresql_dump_aps(PGconn *conn, std::set<AttackPoint> &aps) {
    printf ("dumping aps to postgres\n");
    for ( auto ap : aps ) {
        PGresult *res;
        // add source filename to sourcefile table
        std::string filename = ind2str[ap.filename];
        int filename_id = addstr(conn, "sourcefile", filename);
        std::string info = ind2str[ap.info];
        int typ_id = addstr(conn, "atptype", info);
        int num_rows = get_num_rows(conn, "atp");
        std::stringstream sql;
        sql << "INSERT INTO atp (id,filename,line,typ,input_file,icount,scount) VALUES ("
            << num_rows << ","
            << filename_id << ","
            << ap.line << ","
            << typ_id << ","
            << input_file_id << ","
            << "0,0);";
        res = pq_exec_ss(conn,sql);
        ap_id[ap] = num_rows;
        assert (PQresultStatus(res) == PGRES_COMMAND_OK);
        PQclear(res);
    }
    
}

void postgresql_dump_bugs(PGconn *conn, std::set<std::pair<Dua,AttackPoint>> &injectable_bugs) {
    printf ("dumping bugs to postgres\n");
    for ( auto bug : injectable_bugs ) {
        Dua dua = bug.first;
        AttackPoint ap = bug.second;
        std::stringstream sql;
        int num_rows = get_num_rows(conn, "bug");
        sql << "INSERT INTO bug (id,dua,ap) VALUES (" << num_rows << "," << dua_id[dua] << "," << ap_id[ap] << ");";
        PGresult *res = pq_exec_ss(conn,sql);
        assert (PQresultStatus(res) == PGRES_COMMAND_OK);
        PQclear(res);
    }
}


int main (int argc, char **argv) {

    if (argc != 7) {
        printf ("usage: fbi plog lavadb max_liveness max_card max_tcn input_file\n");
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

    uint32_t max_card = atoi(argv[4]);
    printf ("max card of taint set returned by query = %d\n", max_card);

    uint32_t max_tcn = atoi(argv[5]);
    printf ("max tcn for addr = %d\n", max_tcn);

    input_file = std::string(argv[6]);

    // read in dead data (dd[label_num])
    std::map <Label, float> dd = read_dead_data(plf);
    printf ("done reading in dead data\n");

    /*
     re-read pandalog, this time focusing on taint queries.  Look for
     dead available data, attack points, and thus bug injection oppotunities
    */

    pandalog_open(plf, "r");
    Panda__LogEntry *ple;
    std::map <Ptr, std::set<Label> > ptr_to_set;
    uint64_t ii=0;
    Panda__SrcInfo current_si;
    Panda__TaintQueryHypercall current_tqh;
    bool in_hc = false;
    Instr hc_instr_count;
    bool in_ap = false;
    Instr ap_instr_count;
    bool current_ext_ok = false;
    bool current_si_ok = false; 
    uint32_t num_ext_ok = 0;
    std::set<Label> labels;
    std::set <Offset> ok_bytes;
    bool seen_first_tq = false;
    std::set < Dua > u_dua;
    std::set < AttackPoint > u_ap;
    std::set < std::pair < Dua, AttackPoint > > injectable_bugs;
    std::map < AttackPoint, uint32_t > last_num_dua;
    uint32_t ap_info;
    float c_max_liveness;
    uint32_t c_max_tcn, c_max_card;

    uint32_t num_queried_extents = 0;

    while (1) {
        ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        ii ++;
        if ((ii % 10000) == 0) {
            printf ("processed %lu of taint queries log.  %u dua.  %u ap.  %u injectable bugs\n", 
                    ii, (uint32_t) u_dua.size(), (uint32_t) u_ap.size(), (uint32_t) injectable_bugs.size());
        }
        if (ple->taint_query_unique_label_set) {
            // this just maintains mapping from ptr (uint64_t) to actual set of taint labels 
            uint32_t i;
            Ptr p = ple->taint_query_unique_label_set->ptr;
            for (i=0; i<ple->taint_query_unique_label_set->n_label; i++) {
                Label l = ple->taint_query_unique_label_set->label[i];
                ptr_to_set[p].insert(l);
            }
        }        
        if (ple->src_info) {
            // save this for later.
            current_si = *(ple->src_info);
        }
        if (!in_hc) {
            if (ple->taint_query_hypercall) {
                // hypercall taint query on some exent
                // -- save buf / len / num tainted 
                // subsequent ple->taint_query entries will 
                // be details
                in_hc = true;
                num_queried_extents ++;
                current_tqh = *(ple->taint_query_hypercall);
                hc_instr_count = ple->instr;
                ok_bytes.clear();
                labels.clear();
                c_max_liveness = 0.0;
                c_max_tcn = c_max_card = 0;
                //                printf ("query %d bytes -- \n", current_tqh.len);
            }
        }
        if (ple->taint_query) {
            Panda__TaintQuery *tq = ple->taint_query;
            // this tells us what byte in the extent this query was for
            uint32_t offset = tq->offset;
            /*
              this taint query is for a byte on the current extent under consideration
              We will decide that this byte is useable iff
              1. tcn is low enough (indicating that this byte is not too computationally distant from input)
              2. cardinality is low enough (indicating this byte not too compilcated a fn of inpu?)
              3. none of the labels in this byte's taint label set has a liveness score that is too high
            */            
            // flag to track *why* we discarded a byte
            uint32_t current_byte_not_ok = 0;
            current_byte_not_ok |= 
                ((tq->tcn > max_tcn) 
                 | ((ptr_to_set[tq->ptr].size() > max_card) << 1));
            if (current_byte_not_ok == 0) {
                // potentially, this byte is ok
                Ptr p = ple->taint_query->ptr;
                assert (ptr_to_set.count(p) != 0);
                assert (ptr_to_set[p].size() != 0);
                // check for too-live data on any label this byte derives form
                for ( Label l : ptr_to_set[p] ) {
                    // if liveness too high, discard this byte
                    current_byte_not_ok |= ((dd[l] > max_liveness) << 2);
                    if (current_byte_not_ok != 0) break;
                    // collect set of labels on ok bytes for the entire extent
                    if (dd[l] > c_max_liveness) c_max_liveness = dd[l];
                    labels.insert(l);       
                }
            }
            if (current_byte_not_ok) {
                // we are discarding this byte
                //                printf ("discarding byte -- flag=0x%x\n", current_byte_not_ok);
            }
            else {
                // byte is ok to retain.
                // keep track of highest tcn and card for ok bytes
                if (tq->tcn > c_max_tcn) c_max_tcn = tq->tcn;
                if (ptr_to_set[tq->ptr].size() > c_max_card) c_max_card = ptr_to_set[tq->ptr].size();
                // add this byte to the list of ok bytes
                ok_bytes.insert(offset);
            }
        }
        if (in_hc && ple->instr != hc_instr_count) {
            // done with current hypercall.  
            if ((ok_bytes.size() >= 1) && (labels.size() >= 1)) {
                //                printf ("%d ok\n", (int) ok_bytes.size());
                // at least one byte on this extent is ok
                seen_first_tq = true;
                // great -- extent we just looked at was deemed acceptable
                num_ext_ok ++;
                Dua dua = { 
                    ind2str[current_si.filename], 
                    current_si.linenum, 
                    ind2str[current_si.astnodename], // lval name
                    labels,        // that is, byte offsets within input file that taint the dua parts of this lval
                    ok_bytes,      // that is, offsets within this lval that are dua
                    input_file,    // file name that was the input
                    c_max_liveness, c_max_tcn, c_max_card, 
                    0, 0           // counts (used later by LAVA
                };
                // keeping track of dead, uncomplicated data extents we have
                // encountered so far in the trace
                u_dua.insert(dua);
            }
            else {
                //                printf ("discarded %d ok bytes  %d labels\n", (int) ok_bytes.size(), (int) labels.size());
            }
            in_hc = false;
        }
        if (in_ap && ple->instr != ap_instr_count) {
            in_ap = false;
            if (seen_first_tq) {
                // done with current attack point
                AttackPoint ap = { current_si.filename, current_si.linenum, ap_info };
                if ((u_ap.count(ap) == 0)
                    || (last_num_dua[ap] != u_dua.size())) {
                    // new attack point 
                    // OR number of dua has changed since last time we were here
                    // ok, this attack point can pair with *any* of the dead uncomplicated extents seen previously
                    for ( auto dua : u_dua ) {
                        Bug bug = std::make_pair(dua, ap);
                        injectable_bugs.insert(bug);
                    }
                    u_ap.insert(ap);
                    last_num_dua[ap] = u_dua.size();
                }
            }
        }
        if (!in_ap && ple->attack_point) {
            in_ap = true;
            ap_instr_count = ple->instr;
            ap_info = ple->attack_point->info;
        }                    
        
    }
    pandalog_close();


    printf ("%u queried extents\n", num_queried_extents);

    printf ("%u dead-uncomplicated-available-data.  %u attack-points\n",
            (uint32_t) u_dua.size(), (uint32_t) u_ap.size());

    printf ("%u injectable bugs\n", (uint32_t) injectable_bugs.size());

    std::string dbhostaddr = "18.126.0.46";
    std::string dbname = "tshark";

    // write duas to postgres
    std::string conninfo = "hostaddr=" + dbhostaddr + " dbname=" + dbname + " user=lava password=lava";
    PGresult   *res;

    PGconn *conn = PQconnectdb ((const char *) conninfo.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection to database failed: %s",
                PQerrorMessage(conn));
        exit_nicely(conn);
    }
    input_file_id = addstr(conn, "inputfile", input_file);


    postgresql_dump_duas(conn,u_dua);
    postgresql_dump_aps(conn,u_ap);
    postgresql_dump_bugs(conn,injectable_bugs);
    PQfinish(conn);
}




