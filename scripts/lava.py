from __future__ import print_function

import random
import shlex
import struct
import subprocess32

from sqlalchemy import Table, Column, ForeignKey, create_engine
from sqlalchemy.types import Integer, Text, Float, BigInteger, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql.expression import func

from subprocess32 import PIPE

from composite import Composite

Base = declarative_base()

debugging = True

class Loc(Composite):
    column = Integer
    line = Integer

class ASTLoc(Composite):
    filename = Text
    begin = Loc
    end = Loc

class Range(Composite):
    low = Integer
    high = Integer

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

class DuaBytes(Base):
    __tablename__ = 'duabytes'

    id = Column(BigInteger, primary_key=True)
    dua_id = Column('dua', BigInteger, ForeignKey('dua.id'))
    selected = Range.composite('selected')
    all_labels = Column(postgresql.ARRAY(Integer))

    dua = relationship("Dua")
    def __str__(self):
        return 'DUABytes[DUA[{}:{}, {}, {}]][{}:{}](labels={})'.format(
            self.dua.lval.loc.filename, self.dua.lval.loc.begin.line,
            self.dua.lval.ast_name, 'fake' if self.dua.fake_dua else 'real',
            self.selected.low, self.selected.high, self.all_labels)

class AttackPoint(Base):
    __tablename__ = 'attackpoint'

    id = Column(BigInteger, primary_key=True)
    loc = ASTLoc.composite('loc')
    typ = Column('type', Integer)

    # enum Type {
    FUNCTION_CALL = 0
    POINTER_READ = 1
    POINTER_WRITE = 2
    QUERY_POINT = 3
    # } type;

    def __str__(self):
        type_strs = [
            "ATP_FUNCTION_CALL",
            "ATP_POINTER_READ",
            "ATP_POINTER_WRITE",
            "ATP_QUERY_POINT"
        ]
        return 'ATP[{}](loc={}:{}, type={})'.format(
            self.id, self.loc.filename, self.loc.begin.line, type_strs[self.typ]
        )

build_bugs = \
    Table('build_bugs', Base.metadata,
          Column('object_id', BigInteger, ForeignKey('build.id')),
          Column('index', BigInteger),
          Column('value', BigInteger, ForeignKey('bug.id')))

class Bug(Base):
    __tablename__ = 'bug'

    # enum Type {
    PTR_ADD = 0
    RET_BUFFER = 1
    REL_WRITE = 2
    # };
    type_strings = ['BUG_PTR_ADD', 'BUG_RET_BUFFER', 'BUG_REL_WRITE']

    id = Column(BigInteger, primary_key=True)
    type = Column(Integer)
    trigger_id = Column('trigger', BigInteger, ForeignKey('duabytes.id'))
    trigger_lval_id = Column('trigger_lval', BigInteger, ForeignKey('sourcelval.id'))
    atp_id = Column('atp', BigInteger, ForeignKey('attackpoint.id'))

    trigger = relationship("DuaBytes")
    trigger_lval = relationship("SourceLval")

    max_liveness = Column(Float)

    atp = relationship("AttackPoint")

    extra_duas = Column(postgresql.ARRAY(BigInteger))

    builds = relationship("Build", secondary=build_bugs,
                          back_populates="bugs")

    def __str__(self):
        return 'Bug[{}](type={}, trigger={}, atp={})'.format(
            self.id, Bug.type_strings[self.type], self.trigger, self.atp)

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
        return self.session.query(Bug).filter(~Bug.builds.any()).join(Bug.atp)

    # returns uninjected (not yet in the build table) possibly fake bugs
    def uninjected2(self, fake):
        return self.uninjected()\
            .join(Bug.trigger)\
            .join(DuaBytes.dua)\
            .filter(Dua.fake_dua == fake)

    def uninjected_random(self, fake):
        return self.uninjected2(fake).order_by(func.random())

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
        def get_bugs_non_bugs(fake, limit):
            items = self.uninjected_random(limit)
            for item in items:
                dfl = (item.trigger_lval.loc_filename, item.trigger_lval.loc_begin_line)
                afl = (item.atp.loc_filename, item.atp.loc_begin_line)
                if (dfl in fileline) or (afl in fileline):
                    continue
                if fake:
                    print("non-bug", end="")
                else:
                    print("bug    ", end="")
                print(' dua_fl={} atp_fl={}'.format(str(dfl), str(afl)))
                fileline.add(dfl)
                fileline.add(afl)
                bugs_and_non_bugs.append(item)
                if (len(bugs_and_non_bugs) == limit):
                    break
        get_bugs_non_bugs(False, num)
        get_bugs_non_bugs(True, 2*num)
        return bugs_and_non_bugs

def run_cmd(cmd, cw_dir, envv, timeout, rr=False):
    if type(cmd) in [str, unicode]:
        cmd = shlex.split(cmd)
    if debugging:
        print("run_cmd(" + subprocess32.list2cmdline(cmd) + ")")
    p = subprocess32.Popen(cmd, cwd=cw_dir, env=envv, stdout=PIPE, stderr=PIPE)
    try:
        output = p.communicate(timeout) # returns tuple (stdout, stderr)
    except subprocess32.TimeoutExpired:
        print("Killing process due to timeout expiration.")
        p.terminate()
        return (-9, "timeout expired")
    return (p.returncode, output)

def run_cmd_notimeout(cmd, cw_dir, envv):
    return run_cmd(cmd, cw_dir, envv, 1000000)

lava = 0x6c617661

# fuzz_labels_list is a list of listof tainted byte offsets within file filename.
# replace those bytes with random in a new file named new_filename
def mutfile(filename, fuzz_labels_list, new_filename, bug_id, kt=False, knob=0):
    if kt:
        assert (knob < 2**16-1)
        lava_lower = lava & 0xffff
        bug_trigger = ((lava_lower - bug_id) & 0xffff)
        magic_val = struct.pack("<I", (knob << 16) | bug_trigger)
    else:
        magic_val = struct.pack("<I", lava - bug_id)
    # collect set of tainted offsets in file.
    file_bytes = bytearray(open(filename).read())
    # change first 4 bytes in dua to magic value
    for fuzz_labels in fuzz_labels_list:
        for (i, offset) in zip(range(4), fuzz_labels):
            print("i=%d offset=%d len(file_bytes)=%d" % (i,offset,len(file_bytes)))
            file_bytes[offset] = magic_val[i]
    with open(new_filename, 'w') as fuzzed_f:
        fuzzed_f.write(file_bytes)
