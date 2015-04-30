/*

Create all the tables and data bases for a run
 
fbi will populate all of these tables.
lavaTool will consult them to figure out which bug to inject next, 
preferring bugs with lower icount for dua / ap, and updating the icount for those selected.
something else will update the scount field when a real bug gets found

*/


DROP TABLE sourcefile;
DROP TABLE inputfile;
DROP TABLE lval;
DROP TABLE atptype;
DROP TABLE dua;
DROP TABLE atp;
DROP TABLE bug;
DROP TABLE build;
DROP TABLE run;



	
-- Table of source file names
CREATE TABLE sourcefile (
       id  SERIAL,
       nm  text  -- file name, full path
);


-- Table of input file names
CREATE TABLE inputfile (
       id  SERIAL,
       nm  text  -- file name, full path
);


-- Table of lvals
CREATE TABLE lval (
       id  SERIAL,
       nm  text  -- how the lval appears in src, e.g., foo->bar or meh[i].fez
);


-- Table of AttackPoint types
CREATE TABLE atptype (
       id  SERIAL,
       nm  text  -- memcpy, malloc, etc
);



-- Table of dead uncomplicated and available data
-- A dua is one or more bytes of an lval at a particular source location
-- that is directly controllable by some input bytes, but not a complicated
-- function of those bytes, but is also dead in the sense that it does not
-- taint many branches
CREATE TABLE dua (
       id    	    SERIAL, 
       filename	    integer,   -- source file containing this dua (see SourceFile table)
       line	    integer,   -- line in source file
       lval	    integer,   -- name of the lval, at least some bytes of which are dua 
       bytes  	    integer[], -- bytes in the input file that taint this dua
       offsets	    integer[], -- offsets within the lval that are the dua
       input_file   integer,   -- input file that gave us this dua
       max_tcn      real,      -- max taint compute number across bytes in this dua
       max_card	    integer,   -- max cardinality of a taint label set for any byte in the dua
       max_liveness float,   -- max liveness of any label in any taint label set for any byte in the dua       
       icount       integer,   -- number of times used to inject a bug
       scount       integer    -- number of times used to inject a bug that was successful
);


-- Table of attack points
-- An attack point is a 
CREATE TABLE atp (
       id    	  SERIAL, 
       filename	  integer,   -- source file containing this ap (see SourceFile table)
       line	  integer,   -- line in source file
       typ	  integer,   -- type of attack point (see AttackPoint table)
       input_file integer,   -- input file that gave us this dua
       icount     integer,   -- number of times used to inject a bug
       scount     integer    -- number of times used to inject a bug that was successful
);


-- Table of bug possible injections
-- A bug consists of a dua and an attack point
CREATE TABLE bug (
       id        SERIAL,
       dua	     integer,  
       ap        integer
);


-- Table of build attempts
CREATE TABLE build (
       id        SERIAL,  -- this can be used to refer to a git branch or a patchfile name
       bugs      integer[],  -- list of bug ids that were injected into the source
       compile   boolean,    -- true if the build compiled
       binpath   text        -- path to executable built
);


-- Table of runs. 
CREATE TABLE run (
       id        SERIAL,
       build     integer,   -- the build used to generate this exe
       inputf    text,      -- filename of input with dua fuzzed
       success   boolean    -- true iff this input and this build crashed
);



