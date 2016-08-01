
import struct
import sys
import random
import psycopg2
import shutil
import subprocess32
import argparse
import json
import os
import shlex
import lockfile
import signal
import atexit
from os.path import basename, dirname, join, abspath

import threading
import signal
import subprocess32
import random

from sqlalchemy import Table, Column, ForeignKey, create_engine
from sqlalchemy.types import Integer, Text, Float, BigInteger, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship, sessionmaker

Base = declarative_base()

db_user = "postgres"
db_password = "postgrespostgres"

debugging = True

class SourceLval(Base):
    __tablename__ = 'sourcelval'

    id = Column(Integer, primary_key=True)
    file = Column(Text)
    line = Column(Integer)
    ast_name = Column(Text)
    timing = Column(Integer)

    selected_bytes = Column(postgresql.ARRAY(Integer))

    NULL_TIMING = 0
    BEFORE_OCCURRENCE = 1
    AFTER_OCCURRENCE = 2

    def __str__(self):
        timing_strs = ["NULL", "BEFORE", "AFTER"]
        return 'Lval[{}](loc={}:{}, ast="{}", timing={})'.format(
            self.id, self.file, self.line, self.ast_name,
            timing_strs[self.timing]
        )

dua_viable_bytes = \
    Table('dua_viable_bytes', Base.metadata,
          Column('object_id', BigInteger),
          Column('index', BigInteger, ForeignKey('dua.id')),
          Column('value', BigInteger, ForeignKey('labelset.id')))

class Dua(Base):
    __tablename__ = 'dua'

    id = Column(BigInteger, primary_key=True)
    lval_id = Column('lval', BigInteger, ForeignKey('sourcelval.id'))
    labels = Column(postgresql.ARRAY(Integer))
    inputfile = Column(Text)
    max_tcn = Column(Integer)
    max_cardinality = Column(Integer)
    max_liveness = Column(Float)
    instr = Column(BigInteger)

    lval = relationship("SourceLval")
    viable_bytes = relationship("LabelSet", secondary=dua_viable_bytes)

    def __str__(self):
        return 'DUA[{}](lval={}, labels={}, viable={}, input={}, instr={})'.format(
            self.id, self.lval, self.labels, self.viable_bytes, self.inputfile,
            self.instr
        )

class AttackPoint(Base):
    __tablename__ = 'attackpoint'

    id = Column(BigInteger, primary_key=True)
    file = Column(Text)
    line = Column(Integer)
    typ = Column('type', Integer)

    # enum Type {
    ATP_FUNCTION_CALL = 0
    ATP_POINTER_RW = 1
    # } type;

    def __str__(self):
        type_strs = ["ATP_FUNCTION_CALL", "ATP_POINTER_RW"]
        return 'ATP[{}](loc={}:{}, type={})'.format(
            self.id, self.file, self.line, type_strs[self.typ]
        )

build_bugs = \
    Table('build_bugs', Base.metadata,
          Column('object_id', BigInteger),
          Column('index', BigInteger, ForeignKey('build.id')),
          Column('value', BigInteger, ForeignKey('bug.id')))

class Bug(Base):
    __tablename__ = 'bug'

    id = Column(BigInteger, primary_key=True)
    dua_id = Column('dua', BigInteger, ForeignKey('dua.id'))
    atp_id = Column('atp', BigInteger, ForeignKey('attackpoint.id'))

    dua = relationship("Dua")
    atp = relationship("AttackPoint")

    builds = relationship("Build", secondary=build_bugs,
                          back_populates="bugs")

    def __str__(self):
        return 'Bug[{}](dua={}, atp={})'.format(self.id, self.dua, self.atp)

class LabelSet(Base):
    __tablename__ = 'labelset'

    id = Column(BigInteger, primary_key=True)
    ptr = Column(BigInteger)
    inputfile = Column(Text)
    labels = Column(postgresql.ARRAY(Integer))

class Build(Base):
    __tablename__ = 'build'

    id = Column(BigInteger, primary_key=True)
    compile = Column(Boolean)
    output = Column(Text)

    bugs = relationship("Bug", secondary=build_bugs,
                        back_populates="builds")

class Run(Base):
    __tablename__ = 'run'

    id = Column(BigInteger, primary_key=True)
    build_id = Column('build', BigInteger, ForeignKey('build.id'))
    fuzzed_id = Column('fuzzed', BigInteger, ForeignKey('bug.id'))
    exitcode = Column(Integer)
    output = Column(Text)
    success = Column(Boolean)

    build = relationship("Build")
    fuzzed = relationship("Bug")

class LavaDatabase(object):
    def __init__(self, project):
        self.project = project
        self.engine = create_engine(
            "postgresql+psycopg2://{}:{}@{}/{}".format(
                "postgres", project['dbpassword'], project['dbhost'],
                project['db']
            )
        )
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    def uninjected(self):
        # No builds for a bug (~Bug.builds.any()) means uninjected.
        return self.session.query(Bug).filter(~Bug.builds.any())

    def next_bug(self):
        return self.uninjected().order_by(Bug.id).first()

    def next_bug_random(self):
        count = self.uninjected().count()
        return self.uninjected()[random.randrange(0, count)]

class Command(object):
    def __init__(self, cmd, cwd, envv): #  **popen_kwargs):
        self.cmd = cmd
        self.cwd = cwd
        self.envv = envv
        self.process = None
        self.output = "no output"
#        self.popen_kwargs = popen_kwargs

    def run(self, timeout):
        def target():
#            print "Thread started"
            self.process = subprocess32.Popen(self.cmd.split(), cwd=self.cwd, env=self.envv, \
                                                stdout=subprocess32.PIPE, \
                                                stderr=subprocess32.PIPE, \
                                                preexec_fn=os.setsid) # , **popen_kwargs)
            self.output = self.process.communicate()
#            print 'Thread finished'
        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            if debugging:
                print 'Terminating process cmd=[%s] due to timeout' % self.cmd
            self.process.terminate()
            os.killpg(self.process.pid, signal.SIGTERM)
            self.process.kill()
            print "terminated"
            thread.join(1)
            self.returncode = -9
        else:
            self.returncode = self.process.returncode



def run_cmd(cmd, cw_dir, envv, timeout):
    p = Command(cmd, cw_dir, envv)
    p.run(timeout)
#    p = subprocess32.Popen(cmd.split(), cwd=cw_dir, env=envv, stdout=subprocess32.PIPE, stderr=subprocess32.PIPE)
    output = p.output
    exitcode = p.returncode
    if debugging:
        print "run_cmd(" + cmd + ")"
#        print "exitcode = " + str(exitcode)
#        for line in output:
#            print "output = [" + line + "]"
    return (exitcode, output)

def run_cmd_nto(cmd, cw_dir, envv):
    return run_cmd(cmd, cw_dir, envv, 1000000)


lava = 0x6c617661


# fuzz_offsets is a list of tainted byte offsets within file filename.
# replace those bytes with random in a new file named new_filename
def mutfile(filename, fuzz_offsets, new_filename, bug_id):
    magic_val = struct.pack("<I", lava - bug_id)
    # collect set of tainted offsets in file.
    file_bytes = bytearray(open(filename).read())
    # change first 4 bytes in dua to magic value
    for (i, offset) in zip(range(4), fuzz_offsets):
#        print "i=%d offset=%d len(file_bytes)=%d" % (i,offset,len(file_bytes))
        file_bytes[offset] = magic_val[i]
    with open(new_filename, 'w') as fuzzed_f:
        fuzzed_f.write(file_bytes)
