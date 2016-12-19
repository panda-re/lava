
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

from .composite import Composite

Base = declarative_base()

debugging = False

class Loc(Composite):
    column = Integer
    line = Integer

class ASTLoc(Composite):
    filename = Text
    begin = Loc
    end = Loc

class SourceLval(Base):
    __tablename__ = 'sourcelval'

    id = Column(Integer, primary_key=True)
    loc = ASTLoc.composite('loc')
    ast_name = Column(Text)
    timing = Column(Integer)

    NULL_TIMING = 0
    BEFORE_OCCURRENCE = 1
    AFTER_OCCURRENCE = 2


    def __str__(self):
        timing_strs = ["NULL", "BEFORE", "AFTER"]
        return 'Lval[{}](loc={}:{}, ast="{}", timing={})'.format(
            self.id, self.loc.filename, self.loc.begin.line, self.ast_name,
            timing_strs[self.timing]
        )

class LabelSet(Base):
    __tablename__ = 'labelset'

    id = Column(BigInteger, primary_key=True)
    ptr = Column(BigInteger)
    inputfile = Column(Text)
    labels = Column(postgresql.ARRAY(Integer))

    def __repr__(self):
        return str(self.labels)

dua_viable_bytes = \
    Table('dua_viable_bytes', Base.metadata,
          Column('object_id', BigInteger, ForeignKey('dua.id')),
          Column('index', BigInteger),
          Column('value', BigInteger, ForeignKey('labelset.id')))

class Dua(Base):
    __tablename__ = 'dua'

    id = Column(BigInteger, primary_key=True)
    lval_id = Column('lval', BigInteger, ForeignKey('sourcelval.id'))
    all_labels = Column(postgresql.ARRAY(Integer))
    inputfile = Column(Text)
    max_tcn = Column(Integer)
    max_cardinality = Column(Integer)
    instr = Column(BigInteger)
    fake_dua = Column(Boolean)

    lval = relationship("SourceLval")
    viable_bytes = relationship("LabelSet", secondary=dua_viable_bytes)

    def __str__(self):
        return 'DUA[{}](lval={}, labels={}, viable={}, input={}, instr={}, fake_dua={})'.format(
            self.id, self.lval, self.all_labels, self.viable_bytes, self.inputfile,
            self.instr, self.fake_dua
            )

class AttackPoint(Base):
    __tablename__ = 'attackpoint'

    id = Column(BigInteger, primary_key=True)
    loc = ASTLoc.composite('loc')
    typ = Column('type', Integer)

    # enum Type {
    ATP_FUNCTION_CALL = 0
    ATP_POINTER_RW = 1
    ATP_LARGE_BUFFER_AVAIL = 2
    # } type;

    def __str__(self):
        type_strs = ["ATP_FUNCTION_CALL", "ATP_POINTER_RW", "ATP_LARGE_BUFFER_AVAIL"]
        return 'ATP[{}](loc={}:{}, type={})'.format(
            self.id, self.loc_filename, self.loc_begin_line, type_strs[self.typ]
        )

build_bugs = \
    Table('build_bugs', Base.metadata,
          Column('object_id', BigInteger, ForeignKey('build.id')),
          Column('index', BigInteger),
          Column('value', BigInteger, ForeignKey('bug.id')))

class Bug(Base):
    __tablename__ = 'bug'

    id = Column(BigInteger, primary_key=True)
    dua_id = Column('dua', BigInteger, ForeignKey('dua.id'))
    atp_id = Column('atp', BigInteger, ForeignKey('attackpoint.id'))

    dua = relationship("Dua")
    atp = relationship("AttackPoint")

    selected_bytes = Column(postgresql.ARRAY(Integer))
    max_liveness = Column(Float)

    builds = relationship("Build", secondary=build_bugs,
                          back_populates="bugs")

    def __str__(self):
        return 'Bug[{}](dua={}, atp={})'.format(self.id, self.dua, self.atp)

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
            "postgresql+psycopg2://{}@/{}".format(
                "postgres", project['db']
            )
        )
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    def uninjected(self):
        return self.session.query(Bug).filter(~Bug.builds.any()).join(Bug.atp).filter(
            AttackPoint.typ == AttackPoint.ATP_POINTER_RW or
            AttackPoint.typ == AttackPoint.ATP_FUNCTION_CALL)

    # returns uninjected (not yet in the build table) possibly fake bugs
    def uninjected2(self, fake):
        return self.uninjected().join(Bug.dua).join(Dua.lval).filter(Dua.fake_dua == fake)

    def next_bug_random(self, fake):
        count = self.uninjected2(fake).count()
        return self.uninjected2(fake)[random.randrange(0, count)]

    # collect num bugs AND num non-bugs
    # with some hairy constraints
    # we need no two bugs or non-bugs to have same file/line attack point
    # that allows us to easily evaluate systems which say there is a bug at file/line.
    # further, we require that no two bugs or non-bugs have same file/line dua
    # because otherwise the db might give us all the same dua
    def competition_bugs_and_non_bugs(self, num):
        bugs_and_non_bugs = []
        fileline = set()
        bugs = self.uninjected2(False)
        def get_bugs_non_bugs(fake, limit):
            items = self.uninjected2(fake)
            for item in items:
                dfl = (item.dua.lval.loc_filename, item.dua.lval.loc_begin_line)
                afl = (item.atp.loc_filename, item.atp.loc_begin_line)
                if (dfl in fileline) or (afl in fileline):
                    continue
                if fake:
                    print "non-bug",
                else:
                    print "bug    ",
                print ' dua_fl={} atp_fl={}'.format(str(dfl), str(afl))
                fileline.add(dfl)
                fileline.add(afl)
                bugs_and_non_bugs.append(item)
                if (len(bugs_and_non_bugs) == limit):
                    break
        get_bugs_non_bugs(False, num)
        get_bugs_non_bugs(True, 2*num)
        return bugs_and_non_bugs

class Command(object):
    def __init__(self, cmd, cwd, envv, rr=False): #  **popen_kwargs):
        self.cmd = cmd
        self.cwd = cwd
        self.envv = envv
        self.process = None
        self.output = "no output"
        self.rr = rr
#        self.popen_kwargs = popen_kwargs

    def run(self, timeout):
        def target():
#            print "Thread started"
            self.process = subprocess32.Popen(shlex.split(self.cmd), cwd=self.cwd, env=self.envv, \
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
            if not self.rr:
                self.process.terminate()
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.kill()
            else:
                self.process.send_signal(signal.SIGINT)
                os.killpg(self.process.pid, signal.SIGINT)
            print "terminated"
            thread.join(1)
            self.returncode = -9
        else:
            self.returncode = self.process.returncode



def run_cmd(cmd, cw_dir, envv, timeout, rr=False):
    p = Command(cmd, cw_dir, envv, rr=rr)
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

def run_cmd_notimeout(cmd, cw_dir, envv):
    return run_cmd(cmd, cw_dir, envv, 1000000)


lava = 0x6c617661


# fuzz_offsets is a list of tainted byte offsets within file filename.
# replace those bytes with random in a new file named new_filename
def mutfile(filename, fuzz_offsets, new_filename, bug_id, kt=False, knob=0):
    if kt:
        assert (knob < 2**16-1)
        lava_lower = lava & 0xffff
        bug_trigger = ((lava_lower - bug_id) % 0x10000)
        magic_val = struct.pack("<I", (knob << 16) | bug_trigger)
    else:
        magic_val = struct.pack("<I", lava - bug_id)
    # collect set of tainted offsets in file.
    file_bytes = bytearray(open(filename).read())
    # change first 4 bytes in dua to magic value
    for (i, offset) in zip(range(4), fuzz_offsets):
#        print "i=%d offset=%d len(file_bytes)=%d" % (i,offset,len(file_bytes))
        file_bytes[offset] = magic_val[i]
    with open(new_filename, 'w') as fuzzed_f:
        fuzzed_f.write(file_bytes)
