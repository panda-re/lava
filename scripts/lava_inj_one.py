

import psycopg2



db_host = "18.126.0.46"
db = "tshark"
db_user = "lava"
db_password = "llaavvaa"
               

#conn = psycopg2.connect(host=db_host, database=db, user=db_user, password=db_password)
#conn = psycopg2.connect(database=db, user=db_user, password=db_password)

conn = psycopg2.connect("dbname=tshark, user=lava, password=llaavvaa")

cur = conn.cursor()

cur.execute("select * from next_bug();")

print cur.fetchone()


