
extern "C" {
#include <assert.h>
}

#include <iostream>
#include <set>
#include <string>

#include "../include/lava_bugs.h"





std::string iset_str(std::set<uint32_t> &iset) {
    std::stringstream ss;
    uint32_t n = iset.size();
    uint32_t i=0;
    for (auto el : iset) {
        i++;
        ss << el;
        if (i != n) ss << ",";
    }
    return ss.str();
}


void pg_exit_nicely(PGconn *conn) {
    PQfinish(conn);
    exit(1);
}



PGconn *pg_connect(void) {
    std::string dbhostaddr = "18.126.0.46";
    std::string dbname = "tshark";    
    std::string conninfo = "hostaddr=" + dbhostaddr + " dbname=" + dbname + " user=lava password=lava";
    PGresult   *res;
    PGconn *conn = PQconnectdb ((const char *) conninfo.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection to database failed: %s",
                PQerrorMessage(conn));
        pg_exit_nicely(conn);
    }
    return conn;
}




PGresult *pg_exec(PGconn *conn, std::string comm) {
    const char * cmd = (const char *) comm.c_str();
    //    printf ("sql comm=[%s]\n", cmd);
    PGresult *res = PQexec(conn, cmd);
    //    printf ("res = %d\n", PQresultStatus(res));
    return res;
}


PGresult *pg_exec_ss(PGconn *conn, std::stringstream &comm) {
    std::string comms = comm.str();
    return pg_exec(conn, comms);
}


typedef std::map<uint32_t,std::string> Ism;


Ism pg_get_string_map(PGconn *conn, std::string tablename) {
    std::cout << "Reading string map " << tablename << "\n";
    PGresult *res = pg_exec(conn, "SELECT * FROM " + tablename + ";");
    assert (PQresultStatus(res) == PGRES_TUPLES_OK);
    // iterate over table rows
    Ism sidm;
    for (int row=0; row<PQntuples(res); row++) {
        uint32_t id = atoi(PQgetvalue(res, row, 0));
        char *str = PQgetvalue(res, row, 1);
        sidm[id] = std::string(str);
    }
    return sidm;
}



/*
  Read *all* of the attack points out of the Atp table in the db
  Table: atp_id | filename | line | typ | inputfile | atp_icount | atp_scount 
  and return as a map from atp_id to attack point
*/
std::map<uint32_t,AttackPoint> pg_get_attack_points(PGconn *conn, Ism &sourcefile, Ism &atptype, Ism &inputfile) {
    std::cout << "Reading AttackPoints from postgres\n";
    PGresult *res = pg_exec(conn, "SELECT * FROM atp;");
    assert (PQresultStatus(res) == PGRES_TUPLES_OK);
    std::map<uint32_t,AttackPoint> atps;
    // iterate over rows in the table
    for (int row=0; row<PQntuples(res); row++) {
        uint32_t id = atoi(PQgetvalue(res, row, 0));             // atp_id
        std::string src_filename = sourcefile[atoi(PQgetvalue(res, row, 1))];
        uint32_t src_line = atoi(PQgetvalue(res, row, 2));
        std::string typ = atptype[atoi(PQgetvalue(res, row, 3))];
        std::string input_file = inputfile[atoi(PQgetvalue(res, row, 4))];
        uint32_t icount = atoi(PQgetvalue(res, row, 5));
        uint32_t scount = atoi(PQgetvalue(res, row, 6));
        atps[id] = {src_filename,src_line,typ,input_file,icount,scount};
    }
    return atps;
}



// parse {44,55} into a set of uint32
std::set<uint32_t> parse_offsets(std::string offs_str) {
    uint32_t l = offs_str.size();
    // discard { } 
    std::string offs_str1 = offs_str.substr(1, l-2);
    // split on ,    
    std::stringstream offs_str1_ss(offs_str1);
    std::set<uint32_t> offs;
    std::string token;
    while (std::getline(offs_str1_ss, token, ',')) {
        offs.insert(atoi(token.c_str()));
    }
    return offs;
}
    
    


/* 
   Read *all* of the duas out of the Dua table in the db

   Table: dua_id | filename | line | lval | file_offsets | lval_offsets | inputfile | max_tcn | max_card | max_liveness | dua_icount | dua_scount 
              50 |        2 | 4791 |    8 | {586,587}    | {0,1}        |         0 |       2 |        2 |     0.409256 |          3 |          0

Note: 
"bytes" are bytes in the input file that taint this dua
"offsets" are byte offsets within the dua 
   and return as a map from dua_id to dua
*/
std::map<uint32_t,Dua> pg_get_duas(PGconn *conn, Ism &sourcefile, Ism &lval, Ism &inputfile) {
    std::cout << "Reading Duas from postgres\n";
    PGresult *res = pg_exec(conn, "SELECT * FROM dua;");
    assert (PQresultStatus(res) == PGRES_TUPLES_OK);
    std::map<uint32_t,Dua> duas;
    // iterate over rows in the table
    for (int row=0; row<PQntuples(res); row++) {
        uint32_t id = atoi(PQgetvalue(res, row, 0));
        std::string src_filename = sourcefile[atoi(PQgetvalue(res, row, 1))];
        uint32_t src_line = atoi(PQgetvalue(res, row, 2));
        std::string lvalname = lval[atoi(PQgetvalue(res, row, 3))];
        std::set<uint32_t> file_offsets = parse_offsets(PQgetvalue(res, row, 4));      
        std::set<uint32_t> lval_offsets = parse_offsets(PQgetvalue(res, row, 5));      
        std::string input_file = inputfile[atoi(PQgetvalue(res, row, 6))];
        float max_liveness = atof(PQgetvalue(res, row, 7));
        uint32_t max_tcn = atoi(PQgetvalue(res, row, 8));
        uint32_t max_card = atoi(PQgetvalue(res, row, 9));
        uint32_t icount = atoi(PQgetvalue(res, row, 10));
        uint32_t scount = atoi(PQgetvalue(res, row, 11));        
        duas[id] = {src_filename,src_line,lvalname,file_offsets,lval_offsets,input_file,max_liveness,max_tcn,max_card,icount,scount};
    }
    return duas;
}


//  bug_id | dua | atp | inj 

std::map<uint32_t,Bug> pg_get_bugs(PGconn *conn, std::map<uint32_t,Dua> &duas, std::map<uint32_t,AttackPoint> &atps) {
    std::cout << "Reading Bugs from postgres\n";
    PGresult *res = pg_exec(conn, "SELECT * FROM bug;");
    assert (PQresultStatus(res) == PGRES_TUPLES_OK);
    std::map<uint32_t,Bug> bugs;
    // iterate over rows in the table                                                                                                                                                                                                 
    for (int row=0; row<PQntuples(res); row++) {        
        uint32_t id = atoi(PQgetvalue(res, row, 0));
        uint32_t dua_id = atoi(PQgetvalue(res, row, 1));
        uint32_t atp_id = atoi(PQgetvalue(res, row, 2));
        bugs[id] = {duas[dua_id],atps[atp_id]};
    }   
    return bugs;
}       
    



#if TESTING

/*
  g++ -DTESTING -o lava_sql lava_sql.cpp  -std=c++11  -O2 -lpq 
 */

int main () {
    PGconn *conn = pg_connect();

    Ism sourcefile = pg_get_string_map(conn, "sourcefile");
    Ism atptype = pg_get_string_map(conn, "atptype");
    Ism inputfile = pg_get_string_map(conn, "inputfile");    
    Ism lval = pg_get_string_map(conn, "lval");

    std::map<uint32_t,Dua> duas = pg_get_duas(conn,sourcefile,lval,inputfile);
    std::map<uint32_t,AttackPoint> atps = pg_get_attack_points(conn,sourcefile,atptype,inputfile);
    std::map<uint32_t,Bug> bugs = pg_get_bugs(conn, duas, atps);

    for ( auto &p : bugs) {
        uint32_t id = p.first;
        Bug bug = p.second;
        std::cout << id << " : " << bug.str() << "\n";
    }

    /*
    
    for ( auto p : duas ) {
        uint32_t id = p.first;
        Dua dua = duas[id];
        std::cout << id << " : " << dua.str() << "\n";
    }

    for ( auto &p : atps ) {
        uint32_t id = p.first;
        AttackPoint atp = atps[id];
        std::cout << id << " : " << atp.str() << "\n";
    }                
    */
    
}        


#endif
