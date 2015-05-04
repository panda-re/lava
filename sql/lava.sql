/*

Create all the tables and data bases for a run
 
fbi will populate all of these tables.
lavaTool will consult them to figure out which bug to inject next, 
preferring bugs with lower icount for dua / ap, and updating the icount for those selected.
something else will update the scount field when a real bug gets found

*/


DROP TABLE IF EXISTS sourcefile;
DROP TABLE IF EXISTS inputfile;
DROP TABLE IF EXISTS lval;
DROP TABLE IF EXISTS atptype;
DROP TABLE IF EXISTS dua;
DROP TABLE IF EXISTS atp;
DROP TABLE IF EXISTS bug;
DROP TABLE IF EXISTS build;
DROP TABLE IF EXISTS run;
-- DROP TABLE IF EXISTS lava_lock;

-- drop database if exists tshark;
drop role if exists lava;


CREATE USER lava WITH PASSWORD 'llaavvaa';
-- create DATABASE tshark;
	
-- Table of source file names
CREATE TABLE sourcefile (
       sourcefile_id  int,
       sourcefile_nm  text  -- file name, full path
);
-- ALTER TABLE sourcefile ADD UNIQUE (nm);


-- Table of input file names
CREATE TABLE inputfile (
       inputfile_id  int,
       inputfile_nm  text  -- file name, full path
);
-- ALTER TABLE inputfile ADD UNIQUE (nm);


-- Table of lvals
CREATE TABLE lval (
       lval_id  int,
       lval_nm  text  -- how the lval appears in src, e.g., foo->bar or meh[i].fez
);
-- ALTER TABLE lval ADD UNIQUE (nm);


-- Table of AttackPoint types
CREATE TABLE atptype (    
       atptype_id  int,
       atptype_nm  text  -- memcpy, malloc, etc
);
-- ALTER TABLE atptype ADD UNIQUE (nm);


/*
-- Table to allow lava to lock the db
-- if there are zero rows, then 
CREATE TABLE lava_lock (
       curru name,         -- current_user in postgres
       suser name,         -- session_user in postgres
       ip inet,            -- ip addr of inet_client_addr()
       reason text,         -- reason for taking the lock
       whentaken timestamp   -- when this locak was taken 
);
*/

/*

-- find a bug that we haven't tried to inject / build
create or replace function next_bug() returns void as $$
BEGIN
    -- choose rows from bug whos id is not in the the bugs field
    -- of any row in build
    select * from bug
END;
$$ LANGUAGE plpgsql;                                                                                        
*/



/*


drop function if exists num_rows(name);

CREATE OR REPLACE FUNCTION num_rows(name) RETURNS integer AS $$
BEGIN
    return (COUNT (*) FROM $1);
END;
$$ LANGUAGE plpgsql;



-- returns true if lock is taken 
CREATE OR REPLACE FUNCTION check_lava_lock(table_name text) return boolean AS $$
   LOCK TABLE lava_lock;
   SELECT CASE
     WHEN (SELECT COUNT(*)) return true;
     ELSE return false
     END;
$$ LANGUAGE SQL;



-- returns true if we were able to take lock
CREATE OR REPLACE FUNCTION take_lava_lock(reason text) RETURNS boolean AS $$
    LOCK TABLE lava_lock;      
    if (num_rows("lava_lock") == 0):
      

    SELECT COUNT(*) 
    CASE when 
    FROM lava_lock


    DELETE FROM lava_lock; -- remove all rows
    -- create a single row describing this lock taking
    INSERT INTO lava_lock (curru,suser,ip,reason,whentaken) VALUES (current_user, session_user, inet_client_addr(), $1, now());
$$ LANGUAGE SQL;
*/

 
-- CREATE OR REPLACE FUNCTION take_lock ( h text, r text, w datetime ) 
--    if (select (*) from 

-- Table of dead uncomplicated and available data
-- A dua is one or more bytes of an lval at a particular source location
-- that is directly controllable by some input bytes, but not a complicated
-- function of those bytes, but is also dead in the sense that it does not
-- taint many branches
CREATE TABLE dua (
       dua_id    	    int, 
       filename	    int,   -- source file containing this dua (see SourceFile table)
       line	        int,   -- line in source file
       lval	        int,   -- name of the lval, at least some bytes of which are dua 
       bytes  	    int[], -- bytes in the input file that taint this dua
       offsets	    int[], -- offsets within the lval that are the dua
       inputfile    int,   -- input file that gave us this dua
       max_tcn      real,      -- max taint compute number across bytes in this dua
       max_card	    int,   -- max cardinality of a taint label set for any byte in the dua
       max_liveness float,   -- max liveness of any label in any taint label set for any byte in the dua       
       dua_icount       int,   -- number of times used to inject a bug
       dua_scount       int    -- number of times used to inject a bug that was successful
);





-- Table of attack points
-- An attack point is a 
CREATE TABLE atp (
       atp_id    	  int, 
       filename	  int,   -- source file containing this ap (see SourceFile table)
       line	      int,   -- line in source file
       typ	      int,   -- type of attack point (see AttackPoint table)
       inputfile int,   -- input file that gave us this dua
       atp_icount     int,   -- number of times used to inject a bug
       atp_scount     int    -- number of times used to inject a bug that was successful
);


-- Table of bug possible injections
-- A bug consists of a dua and an attack point
CREATE TABLE bug (
       bug_id        int,
       dua	     int,     -- id of dua
       atp       int,     -- id of attack point
       inj       boolean  -- true iff we have attempted to inj & build at least once
);


-- Table of inject / build attempts
CREATE TABLE build (
       build_id        int,        -- this can be used to refer to a git branch or a patchfile name
       bugs      int[],      -- list of bug ids that were injected into the source
       compile   boolean,    -- true if the build compiled
       binpath   text        -- path to executable built
);


-- Table of runs. 
CREATE TABLE run (
       run_id          int,
       build       int,   -- the build used to generate this exe
       inputfile   text,      -- filename of input with dua fuzzed
       success     boolean    -- true iff this input and this build crashed
);



GRANT SELECT, INSERT, UPDATE, DELETE ON sourcefile TO lava;
GRANT SELECT, INSERT, UPDATE, DELETE ON inputfile TO lava;
GRANT SELECT, INSERT, UPDATE, DELETE ON lval TO lava;
GRANT SELECT, INSERT, UPDATE, DELETE ON atptype TO lava;
GRANT SELECT, INSERT, UPDATE, DELETE ON dua TO lava;
GRANT SELECT, INSERT, UPDATE, DELETE ON atp TO lava;
GRANT SELECT, INSERT, UPDATE, DELETE ON bug TO lava;
GRANT SELECT, INSERT, UPDATE, DELETE ON build TO lava;
GRANT SELECT, INSERT, UPDATE, DELETE ON run TO lava;

-- grant all privileges on all tables in schema public to lava;










drop function if exists  next_bug();
drop function if exists  num_rows(text);
drop function if exists  one();
drop function if exists  set_count(text);
drop function if exists  set_to_inj(real);
drop function if exists  take_lava_lock(text);



-- count rows in table
create or replace function num_rows(tablename text) returns integer 
as $$ 
  cmd = "select count (*) from " + tablename + ";"
  rv = plpy.execute(cmd, 1)
  return rv[0]["count"]
$$ LANGUAGE plpythonu;




-- update a random set of rows in bug table to be injected
-- NB: This is for testing purposes
create or replace function set_to_inj(prob real) returns integer
as $$
  res = plpy.execute("select num_rows('bug')")
  n = res[0]['num_rows']
  ni = 0
  for i in range(n):
    import random
    if (random.random() < prob):
      cmd = "update bug set inj=true where bug_id=%d;" % i
      rv = plpy.execute(cmd, 1)
      ni += 1
  return ni
$$ LANGUAGE plpythonu;


-- sets count for table
create or replace function set_count(tablename text) returns void
as $$
  res = plpy.execute("select num_rows('%s')" % tablename)
  n = res[0]['num_rows']
  for i in range(n):
    import random
    cmd = "update %s set %s_icount=%d where %s_id=%d;" % (tablename, tablename, random.randint(0,1000), tablename, i)
    rv = plpy.execute(cmd, 1)
$$ LANGUAGE plpythonu;
  


drop type if exists bug_info;

create type bug_info as (
  score  int,
  bug    int,
  dua    int,
  atp    int
);                                                                                                                                                                   

  

/*
  next_bug()

 returns next bug to work on
 first, get set of bugs that have not been injected
 consider each, and for each compute a score that is the sum of the 
 counts for the dua and atp.  
 The bug that gets retured is the one for which that score is minimized.
 update count for dua and atp in bug that was chosen.
 and set the inj field to true for the chosen bug.

*/ 


/*
 tshark=# select * from next_bug();
  bug  | dua | atp 
-------+-----+-----
 13838 | 478 |  30
*/
create or replace function next_bug() returns bug_info
as $$
  reses = plpy.execute("select * from bug,dua,atp where bug.inj=false and dua.dua_id=bug.dua and atp.atp_id=bug.atp;")
  # find bug for which count
  b_min = 10000000
  b_argmin = ""
  d_argmin = ""
  a_argmin = ""
  for res in reses:
    n = res["dua_icount"] + res["atp_icount"]
    if (n < b_min):
      b_min = n
      b_argmin = res["bug_id"]
      d_argmin = res["dua_id"]
      a_argmin = res["atp_id"]
  #  best_bug_id = b_argmin["bug_id"]
  # grab it by setting the inj field
  res = plpy.execute("update bug set inj=true where bug_id=%d" % b_argmin)
  # update counts for dua and atp
  res = plpy.execute("update dua set dua_icount=dua_icount+1 where dua_id=%d;" % d_argmin)
  res = plpy.execute("update atp set atp_icount=atp_icount+1 where atp_id=%d;" % a_argmin)
  #  return best_bug_id
  #  res = plpy.execute("select * from bug,dua,atp where dua_id=%d and atp_id=%d and bug_id=%d;" % (d_argmin, a_argmin, b_argmin))
  return { "score": b_min, "bug": b_argmin, "dua" : d_argmin, "atp": a_argmin }
$$ LANGUAGE plpythonu;



