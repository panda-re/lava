

import psycopg2



db_host = "18.126.0.46"
db = "tshark"
db_user = "lava"
db_password = "llaavvaa"
               

sourcefile = {}
inputfile = {}
lval = {}
atptype = {}


def get_conn():
    conn = psycopg2.connect(host=db_host, database=db, user=db_user, password=db_password)
    return conn;


def read_i2s(tablename):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from %s;" % tablename)
    i2s = {}
    for row in cur:
        i2s[int(row[0])] = row[1]
    return i2s


def next_bug():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from next_bug();")
    bug = cur.fetchone()
    # need to do all three of these in order for the writes to db to actually happen
    cur.close()
    conn.commit()
    conn.close()
    return bug


def remaining_inj():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from bug where inj=false;")
    return cur.rowcount


def get_dua(dua_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from dua where dua_id=%d" % dua_id)
    (dua_id,sourcefile_id,line,lval_id,bytess,offsets,inputfile_id,max_tcn,max_card,max_liveness,dua_icount,dua_scount) = cur.fetchone()
    return (sourcefile[sourcefile_id],
            line,
            lval[lval_id],
            bytess,
            offsets,
            inputfile[inputfile_id],
            max_tcn,
            max_card,
            max_liveness,
            dua_icount,
            dua_scount)


def get_atp(atp_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from atp where atp_id=%d" % atp_id)
    (atp_id,sourcefile_id,line,typ_id,inputfile_id,atp_icount,atp_scount) = cur.fetchone()
    return (sourcefile[sourcefile_id],
            line,
            atptype[typ_id],
            inputfile[inputfile_id],
            atp_icount,
            atp_scount)

    




sourcefile = read_i2s("sourcefile")
inputfile = read_i2s("inputfile")
lval = read_i2s("lval")
atptype = read_i2s("atptype")


while True:
    print remaining_inj()
    (score, bug_id, dua_id, atp_id) = next_bug()
    dua = get_dua(dua_id)
    atp = get_atp(atp_id)
    print "------------\n"
    print "BUG score=%d " % score,
    print "(%d,%d)" % (dua_id, atp_id)
    print "DUA:"
    print dua
    print "\nATP:"
    print atp
    
