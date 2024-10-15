import math
import os
import random
import shlex
import struct
import subprocess
import sys
from os.path import abspath
from os.path import basename
from os.path import dirname
from os.path import join
from subprocess import PIPE
from subprocess import check_call

from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import Table
from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import load_only
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.expression import func
from sqlalchemy.types import BigInteger
from sqlalchemy.types import Boolean
from sqlalchemy.types import Float
from sqlalchemy.types import Integer
from sqlalchemy.types import Text

from composite import Composite
from process_compile_commands import get_c_files
from process_compile_commands import process_compile_commands
from test_crash import process_crash

# from multiprocessing import cpu_count
# from multiprocessing.pool import ThreadPool

Base = declarative_base()

debugging = False
NUM_BUGTYPES = 3  # Make sure this matches what's in lavaTool


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

    def __str__(self):
        return 'Lval[{}](loc={}:{}, ast="{}")'.format(
            self.id, self.loc.filename, self.loc.begin.line, self.ast_name
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
        return 'DUA[{}](lval={}, labels={}, viable={}, \
                input={}, instr={}, fake_dua={})'.format(
            self.id, self.lval, self.all_labels, self.viable_bytes,
            self.inputfile, self.instr, self.fake_dua
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
    PRINTF_LEAK = 4

    # } type;

    def __str__(self):
        type_strs = [
            "ATP_FUNCTION_CALL",
            "ATP_POINTER_READ",
            "ATP_POINTER_WRITE",
            "ATP_QUERY_POINT",
            "ATP_PRINTF_LEAK",
            "ATP_MALLOC_OFF_BY_ONE"
        ]
        return 'ATP[{}](loc={}:{}, type={})'.format(
            self.id, self.loc.filename, self.loc.begin.line, type_strs[self.typ]
        )


build_bugs = \
    Table('build_bugs', Base.metadata,
          Column('object_id', BigInteger, ForeignKey('build.id')),
          Column('index', BigInteger, default=0),
          Column('value', BigInteger, ForeignKey('bug.id')))


class Bug(Base):
    __tablename__ = 'bug'

    # enum Type {
    PTR_ADD = 0
    RET_BUFFER = 1
    REL_WRITE = 2
    PRINTF_LEAK = 3
    MALLOC_OFF_BY_ONE = 4
    # };
    type_strings = ['BUG_PTR_ADD', 'BUG_RET_BUFFER',
                    'BUG_REL_WRITE', 'BUG_PRINTF_LEAK', 'MALLOC_OFF_BY_ONE']

    id = Column(BigInteger, primary_key=True)
    type = Column(Integer)
    trigger_id = Column('trigger', BigInteger, ForeignKey('duabytes.id'))
    trigger_lval_id = Column('trigger_lval', BigInteger,
                             ForeignKey('sourcelval.id'))
    atp_id = Column('atp', BigInteger, ForeignKey('attackpoint.id'))

    trigger = relationship("DuaBytes")
    trigger_lval = relationship("SourceLval")

    max_liveness = Column(Float)
    magic = Column(Integer)

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
    validated = Column(Boolean)

    build = relationship("Build")
    fuzzed = relationship("Bug")


class LavaDatabase(object):
    def __init__(self, project):
        self.project = project
        self.engine = create_engine(
            "postgresql+psycopg2://{}@database:5432/{}".format(
                "postgres", project['db']
            )
        )
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    # If we have over a million bugs, don't bother counting things
    def huge(self):
        return self.session.query(Bug.id).count() > 1000000

    def uninjected(self):
        return self.session.query(Bug).filter(~Bug.builds.any())

    # returns uninjected (not yet in the build table) possibly fake bugs
    def uninjected2(self, fake, allowed_bugtypes=None):
        ret = self.uninjected() \
            .join(Bug.atp) \
            .join(Bug.trigger) \
            .join(DuaBytes.dua) \
            .filter(Dua.fake_dua == fake)
        if allowed_bugtypes:
            ret.filter(Bug.type.in_(allowed_bugtypes))
        return ret

    def uninjected_random(self, fake, allowed_bugtypes=None):
        return self.uninjected2(fake, allowed_bugtypes).order_by(func.random())

    def uninjected_random_by_atp_bugtype(self, fake, atp_types=None, allowed_bugtypes=None, atp_lim=10):
        # For each ATP find X possible bugs,
        # Returns dict list of lists:
        #   {bugtype1:[[atp0_bug0, atp0_bug1,..], [atp1_bug0, atp1_bug1,..]],
        #    bugtype2:[[atp0_bug0, atp0_bug1,..], [atp1_bug0, atp1_bug1,..]]}
        # Where sublists are randomly sorted
        if atp_types:
            _atps = self.session.query(AttackPoint.id).filter(AttackPoint.typ.in_(atp_types)).all()
        else:
            _atps = self.session.query(AttackPoint.id).all()

        atps = [r.id for r in _atps]
        # print(atps)
        print("Found {} distinct ATPs".format(len(atps)))

        results = {}
        assert (len(allowed_bugtypes)), "Requires bugtypes"

        for bugtype in allowed_bugtypes:
            results[bugtype] = []
            for atp in atps:
                q = self.session.query(Bug).filter(Bug.atp_id == atp).filter(~Bug.builds.any()) \
                    .filter(Bug.type == bugtype) \
                    .join(Bug.atp) \
                    .join(Bug.trigger) \
                    .join(DuaBytes.dua) \
                    .filter(Dua.fake_dua == fake)

                results[bugtype].append(q.order_by(func.random()).limit(atp_lim).all())
        return results

    def uninjected_random_by_atp(self, fake, atp_types=None,
                                 allowed_bugtypes=None, atp_lim=10):
        # For each ATP find X possible bugs,
        # Returns list of lists: [[atp0_bug0, atp0_bug1,..],
        # [atp1_bug0, atp1_bug1,..]]
        # Where sublists are randomly sorted
        if atp_types:
            _atps = self.session.query(AttackPoint.id) \
                .filter(AttackPoint.typ.in_(atp_types)).all()
        else:
            _atps = self.session.query(AttackPoint.id).all()

        atps = [r.id for r in _atps]
        # print(atps)
        print("Found {} distinct ATPs".format(len(atps)))

        results = []
        for atp in atps:
            q = self.session.query(Bug).filter(Bug.atp_id == atp) \
                .filter(~Bug.builds.any()) \
                .join(Bug.atp) \
                .join(Bug.trigger) \
                .join(DuaBytes.dua) \
                .filter(Dua.fake_dua == fake)
            if allowed_bugtypes:
                q = q.filter(Bug.type.in_(allowed_bugtypes))

            results.append(q.order_by(func.random()).limit(atp_lim).all())
        return results

    def uninjected_random_limit(self, allowed_bugtypes=None, count=100):
        # Fast, doesn't support fake bugs, only return IDs of allowed bugtypes
        ret = self.session.query(Bug) \
            .filter(~Bug.builds.any()) \
            .options(load_only("id"))
        if allowed_bugtypes:
            ret = ret.filter(Bug.type.in_(allowed_bugtypes))
        return ret.order_by(func.random()).limit(count).all()

    def uninjected_random_y(self, fake, allowed_bugtypes=None, yield_count=100):
        # Same as above but yield results
        ret = self.session.query(Bug) \
            .filter(~Bug.builds.any()).yield_per(yield_count) \
            .join(Bug.atp) \
            .join(Bug.trigger) \
            .join(DuaBytes.dua) \
            .filter(Dua.fake_dua == fake)
        if allowed_bugtypes:
            ret = ret.filter(Bug.type.in_(allowed_bugtypes))
        yield ret.all()  # TODO randomize- or is it ranomized already?

    def uninjected_random_balance(self, fake, num_required, bug_types):
        bugs = []
        types_present = self.session.query(Bug.type) \
            .filter(~Bug.builds.any()) \
            .group_by(Bug.type)
        num_avail = 0
        for (i,) in types_present:
            if i in bug_types:
                num_avail += 1
        print("%d bugs available of allowed types" % num_avail)
        assert (num_avail > 0)
        num_per = num_required / num_avail
        for (i,) in types_present:
            if (i in bug_types):
                bug_query = self.uninjected_random(fake).filter(Bug.type == i)
                print("found %d bugs of type %d" % (bug_query.count(), i))
                bugs.extend(bug_query[:num_per])
        return bugs

    def next_bug_random(self, fake):
        count = self.uninjected2(fake).count()
        return self.uninjected2(fake)[random.randrange(0, count)]


def run_cmd(cmd, envv=None, timeout=30, cwd=None, rr=False, shell=False):
    if type(cmd) in [str] and not shell:
        cmd = shlex.split(cmd)

    if debugging:
        env_string = ""
        if envv:
            env_string = " ".join(["{}='{}'".format(k, v)
                                   for k, v in envv.items()])
        if type(cmd) == list:
            print("run_cmd(" + env_string + " " +
                  subprocess.list2cmdline(cmd) + ")")
        else:
            print("run_cmd(" + env_string + " " +
                  cmd + ")")
    # Merge current environ with passed envv
    merged_env = os.environ.copy()
    if envv:
        for k, v in envv.items():
            merged_env[k] = v

    p = subprocess.Popen(cmd, cwd=cwd, env=merged_env, stdout=PIPE,
                         stderr=PIPE, shell=shell)
    try:
        # returns tuple (stdout, stderr)
        output = p.communicate(timeout=timeout)
        if debugging:
            print("Run_cmd output: {}".format(repr(output[1])))
    except subprocess.TimeoutExpired:
        print("Killing process due to timeout expiration.")
        p.terminate()
        return (-9, ("", "timeout expired"))

    return (p.returncode, output)


def run_cmd_notimeout(cmd, **kwargs):
    return run_cmd(cmd, None, None, **kwargs)


# fuzz_labels_list is a list of listof tainted
# byte offsets within file filename.
# replace those bytes with random in a new
# file named new_filename


def mutfile(filename, fuzz_labels_list, new_filename, bug,
            kt=False, knob=0, solution=None):
    # Open filename, mutate it and store in new_filename such that
    # it hopefully triggers the passed bug
    if kt:
        assert (knob < 2 ** 16 - 1)
        bug_trigger = bug.magic & 0xffff
        magic_val = struct.pack("<I", (knob << 16) | bug_trigger)
    else:
        magic_val = struct.pack("<I", bug.magic)
    # collect set of tainted offsets in file.
    file_bytes = bytearray(open(filename).read())
    # change first 4 bytes in dua to magic value

    if bug.type == Bug.REL_WRITE:
        assert (len(fuzz_labels_list) == 3)  # Must have 3 sets of labels

        m = bug.magic
        a, b, c = 0, 0, 0

        if solution:
            a_val = solution[0]
            b_val = solution[1]
            c_val = solution[2]
        else:
            # If we don't have solutions from lavaTool, hope this code matches
            # lavaTool and generate non-ascii solutions here
            if m % NUM_BUGTYPES == 0:  # A + B = M * C
                b = m
                c = 1
                a = 0

            if m % NUM_BUGTYPES == 1:  # B = A*(C+M)
                a = 1
                c = 0
                b = m
            # C % M == M - A*2 NOT USING B, just a 2-dua
            if m % NUM_BUGTYPES == 2:
                a = 5
                c = m - 10
            # Intentional chaff bug - don't even bother
            if m % NUM_BUGTYPES == 3:
                pass

            a_val = struct.pack("<I", a)
            b_val = struct.pack("<I", b)
            c_val = struct.pack("<I", c)

        for (i, offset) in zip(range(4), fuzz_labels_list[0]):
            file_bytes[offset] = a_val[i]

        for (i, offset) in zip(range(4), fuzz_labels_list[1]):
            file_bytes[offset] = b_val[i]

        for (i, offset) in zip(range(4), fuzz_labels_list[2]):
            file_bytes[offset] = c_val[i]

    else:
        for fuzz_labels in fuzz_labels_list:
            for (i, offset) in zip(range(4), fuzz_labels):
                file_bytes[offset] = magic_val[i]

    with open(new_filename, 'wb') as fuzzed_f:
        fuzzed_f.write(file_bytes)


# run lavatool on this file to inject any parts of this list of bugs
def run_lavatool(bug_list, lp, host_file, project, llvm_src, filename,
                 knobTrigger=False, dataflow=False, competition=False,
                 randseed=0):
    print("Running lavaTool on [{}]...".format(filename))
    lt_debug = False
    if (len(bug_list)) == 0:
        print("\nWARNING: Running lavaTool but no bugs \
              selected for injection\n")
        print("Running with -debug to just inject data_flow")
        lt_debug = True

    db_name = project["db"]
    bug_list_str = ','.join([str(bug.id) for bug in bug_list])
    main_files = ','.join([join(lp.bugs_build, f)
                           for f in project['main_file']])

    cmd = [
        lp.lava_tool, '-action=inject', '-bug-list=' + bug_list_str,
                                        '-src-prefix=' + lp.bugs_build, '-db=' + db_name,
                                        '-main-files=' + main_files, join(lp.bugs_build, filename)]

    # Todo either paramaterize here or hardcode everywhere else
    # For now, lavaTool will only work if it has a whitelist, so we always pass this
    fninstr = join(join(project['directory'], project['name']), "fninstr")
    cmd.append('-lava-wl=' + fninstr)

    if lt_debug:
        cmd.append("-debug")
    if dataflow:
        cmd.append('-arg_dataflow')
    if knobTrigger > 0:
        cmd.append('-kt')
    if competition:
        cmd.append('-competition')
    if randseed:
        cmd.append('-randseed={}'.format(randseed))
    print("lavaTool command: {}".format(' '.join(cmd)))

    ret = run_cmd_notimeout(cmd)
    log_dir = join(project["output_dir"], "logs")

    safe_fname = filename.replace("/", "_").replace(".", "-")

    with open(join(log_dir, "lavaTool-{}-stdout.log"
            .format(safe_fname)), "w") as f:
        f.write(ret[1][0])

    with open(join(log_dir, "lavaTool-{}-stderr.log"
            .format(safe_fname)), "w") as f:
        f.write(ret[1][1])

    if ret[0] != 0:
        print("ERROR: " + "=" * 20)
        print(ret[1][0].replace("\\n", "\n"))
        print("=" * 20)
        print(ret[1][1].replace("\\n", "\n"))
        print("\nFatal error: LavaTool crashed\n")
        assert (False)  # LavaTool failed

    # Get solutions back from lavaTool, parse and return
    solutions = {}
    for line in ret[1][0].split("\n"):
        if line.startswith("SOL") and " == " in line:
            bugid = line.split("0x")[1].split(" ")[0]
            bugid = int(bugid, 16)
            solutions[bugid] = []
            vals = line.split("0x")[2:]  # Skip bugid
            for val in vals:
                for idx, c in enumerate(val):
                    if c not in "0123456789abcdef":
                        val = val[:idx]
                        break
                if not len(val):
                    continue
                solutions[bugid].append(struct.pack("<I", int(val, 16)))
    return solutions


class LavaPaths(object):

    def __init__(self, project):
        self.top_dir = project['output_dir']
        self.lavadb = join(self.top_dir, 'lavadb')
        self.lava_dir = dirname(dirname(abspath(sys.argv[0])))
        self.lava_tool = join(self.lava_dir, 'tools', 'install', 'bin', 'lavaTool')
        if 'source_root' in project:
            self.source_root = project['source_root']
        else:
            tar_files = subprocess.check_output(['tar', 'tf',
                                                 project['tarfile']],
                                                stderr=sys.stderr)
            self.source_root = tar_files.decode().splitlines()[0].split(os.path.sep)[0]
        self.queries_build = join(self.top_dir, self.source_root)
        self.bugs_top_dir = join(self.top_dir, 'bugs')

    def __str__(self):
        rets = ""
        rets += "top_dir =       %s\n" % self.top_dir
        rets += "lavadb =        %s\n" % self.lavadb
        rets += "lava_dir =      %s\n" % self.lava_dir
        rets += "lava_tool =     %s\n" % self.lava_tool
        rets += "source_root =   %s\n" % self.source_root
        rets += "queries_build = %s\n" % self.queries_build
        rets += "bugs_top_dir =  %s\n" % self.bugs_top_dir
        rets += "bugs_parent =   %s\n" % self.bugs_parent
        rets += "bugs_build =    %s\n" % self.bugs_build
        rets += "bugs_install =  %s\n" % self.bugs_install
        return rets

    def set_bugs_parent(self, bugs_parent):
        assert self.bugs_top_dir == dirname(bugs_parent)
        self.bugs_parent = bugs_parent
        self.bugs_build = join(self.bugs_parent, self.source_root)
        self.bugs_install = join(self.bugs_build, 'lava-install')


# Given a list of bugs, return the IDs for a subset of bugs with
# `max_per_line` bugs on each line of source
def limit_atp_reuse(bugs, max_per_line=1):
    uniq_bugs = []
    seen = {}
    for bug in bugs:
        tloc = (bug.atp.loc_filename, bug.atp.loc_begin_line)
        if tloc not in seen.keys():
            seen[tloc] = 0
        seen[tloc] += 1
        if seen[tloc] <= max_per_line:
            uniq_bugs.append(bug.id)
    print("Limited ATP reuse: Had {} bugs, now have {} with a "
          "max of {} per source line".format(len(bugs), len(uniq_bugs), max_per_line))
    return uniq_bugs


# Build a set of src/input files that we need to modify to inject these bugs
def collect_src_and_print(bugs_to_inject, db):
    src_files = set()
    input_files = set()

    for bug_index, bug in enumerate(bugs_to_inject):
        print("------------\n")
        print("SELECTED ")
        if bug.trigger.dua.fake_dua:
            print("NON-BUG")
        else:
            print("BUG {} id={}".format(bug_index, bug.id))
        print("    ATP file: ", bug.atp.loc_filename)
        print("        line: ", bug.atp.loc_begin_line)
        print("DUA:")
        print("   ", bug.trigger.dua)
        print("      Src_file: ", bug.trigger_lval.loc_filename)
        print("      Filename: ", bug.trigger.dua.inputfile)

        if len(bug.extra_duas):
            print("EXTRA DUAS:")
            for extra_id in bug.extra_duas:
                dua_bytes = db.session.query(DuaBytes).filter(DuaBytes.id == extra_id).first()
                if (dua_bytes is None):
                    raise RuntimeError("Bug {} references DuaBytes {} which does not exist" \
                                       .format(bug.id, extra_id))
                print("  ", extra_id, "   @   ", dua_bytes.dua)
                print("     Src_file: ", dua_bytes.dua.lval.loc_filename)

                # Add filesnames for extra_duas into src_files and input_files
                # Note this is the file _name_ not the path
                file_name = dua_bytes.dua.lval.loc_filename
                if "/" in file_name:
                    file_name = file_name.split("/")[1]
                src_files.add(file_name)
                # input_files.add(lval.inputfile)

        print("ATP:")
        print("   ", bug.atp)
        print("max_tcn={}  max_liveness={}".format(
            bug.trigger.dua.max_tcn, bug.max_liveness))
        src_files.add(bug.trigger_lval.loc_filename)
        src_files.add(bug.atp.loc_filename)
        input_files.add(bug.trigger.dua.inputfile)
    sys.stdout.flush()
    return (src_files, input_files)


# inject this set of bugs into the source place the resulting bugged-up
# version of the program in bug_dir
def inject_bugs(bug_list, db, lp, host_file, project, args,
                update_db, dataflow=False, competition=False,
                validated=False, lavatoolseed=0):
    # TODO: don't pass args, just pass the data we need to run
    # TODO: split into multiple functions, this is huge

    if not os.path.exists(lp.bugs_parent):
        os.makedirs(lp.bugs_parent)

    print("source_root = " + lp.source_root + "\n")

    # Make sure directories and btrace is ready for bug injection.
    def run(args, **kwargs):
        print("run(", subprocess.list2cmdline(args), ")")
        check_call(args, cwd=lp.bugs_build, **kwargs)

    if not os.path.isdir(lp.bugs_build):
        print("Untarring...")
        check_call(['tar', '--no-same-owner', '-xf', project['tarfile']],
                   cwd=lp.bugs_parent)
    if not os.path.exists(join(lp.bugs_build, '.git')):
        print("Initializing git repo...")
        run(['git', 'init'])
        run(['git', 'config', 'user.name', 'LAVA'])
        run(['git', 'config', 'user.email', 'nobody@nowhere'])
        run(['git', 'add', '-f', '-A', '.'])
        run(['git', 'commit', '-m', 'Unmodified source.'])
    if not os.path.exists(join(lp.bugs_build, 'config.log')) \
            and 'configure' in project.keys():
        print('Re-configuring...')
        run(shlex.split(project['configure']) + ['--prefix=' + lp.bugs_install])
        envv = {'CC': '/usr/lib/llvm-11/bin/clang',
                'CXX': '/usr/lib/llvm-11/bin/clang++',
                'CFLAGS': '-O0 -m32 -DHAVE_CONFIG_H -g -gdwarf-2 -fno-stack-protector -D_FORTIFY_SOURCE=0 -I. -I.. -I../include -I./src/'}
        if project['configure']:
            run_cmd(' '.join(shlex.split(project['configure']) + ['--prefix=' + lp.bugs_install]),
                    envv, 30, cwd=lp.bugs_build, shell=True)
    if not os.path.exists(join(lp.bugs_build, 'btrace.log')):
        print("Making with btrace...")

        # Do we need to configure here? I don't think so...
        # run(shlex.split(project['configure']) +
        # ['--prefix=' + lp.bugs_install])

        # Silence warnings related to adding integers to pointers since we already
        # know that it's unsafe.
        envv = {'CC': '/usr/lib/llvm-11/bin/clang',
                'CXX': '/usr/lib/llvm-11/bin/clang++',
                'CFLAGS': '-Wno-int-conversion -O0 -m32 -DHAVE_CONFIG_H -g -gdwarf-2 -fno-stack-protector -D_FORTIFY_SOURCE=0 -I. -I.. -I../include -I./src/'}
        if competition:
            envv["CFLAGS"] += " -DLAVA_LOGGING"
        envv = {}
        btrace = join(lp.lava_dir, 'tools', 'btrace', 'sw-btrace')
        print("Running btrace make command: {} {} with env: {} in {}"
              .format(btrace, project['make'], envv, lp.bugs_build))

        (rv, outp) = run_cmd(btrace + " " + project['make'], envv, 30,
                             cwd=lp.bugs_build, shell=True)
        assert (rv == 0), "Make with btrace failed"

    sys.stdout.flush()
    sys.stderr.flush()
    dataflow = dataflow
    try:
        dataflow |= args.arg_dataflow
    except Exception:  # arg_dataflow missing from args which is okay
        pass

    
    if not os.path.exists(join(lp.bugs_build, 'compile_commands.json')):
        run([join(lp.lava_dir, 'tools', 'btrace', 'sw-btrace-to-compiledb'),
             "/usr/lib/llvm-11/lib/clang/11/include"])
        # also insert instr for main() fn in all files that need it

        process_compile_commands(
            join(lp.bugs_build, 'compile_commands.json'),
            join(lp.bugs_top_dir, '../extra_compile_commands.json')
        )

        run(['git', 'add', '-f', 'compile_commands.json'])
        run(['git', 'commit', '-m', 'Add compile_commands.json.'])
        # for make_cmd in project['make'].split('&&'):
        #    run(shlex.split(make_cmd))
        run(shlex.split(project['make']))
        try:
            run(['find', '.', '-name', '*.[ch]', '-exec',
                 'git', 'add', '-f', '{}', ';'])
            run(['git', 'commit', '-m', 'Adding source files'])
        except subprocess.CalledProcessError:
            pass

        # Here we run make install, but it may also run again later
        if not os.path.exists(lp.bugs_install):
            check_call(project['install'].format(install_dir="lava-install"),
                       cwd=lp.bugs_build, shell=True)

        # for make_cmd in project['make'].split('&&'):
        #    run(shlex.split(make_cmd))
        run(shlex.split(project['make']))
        run(['find', '.', '-name', '*.[ch]', '-exec', 'git', 'add', '{}', ';'])
        try:
            run(['git', 'commit', '-m',
                 'Adding any make-generated source files'])
        except subprocess.CalledProcessError:
            pass

    bugs_to_inject = db.session.query(Bug).filter(Bug.id.in_(bug_list)).all()

    # TODO: We used to have code that would reduce duplicate ATPs at this point
    # see b6627fc05f4a78c7b14d03ade45c344c7747cd4b for the last time it was here
    if validated:
        pass

    # collect set of src files into which we must inject code
    (src_files, input_files) = collect_src_and_print(bugs_to_inject, db)

    # cleanup
    print("------------\n")
    print("CLEAN UP SRC")
    run_cmd_notimeout("git checkout -f", cwd=lp.bugs_build)

    print("------------\n")
    print("INJECTING BUGS INTO SOURCE")
    print("%d source files: " % (len(src_files)))
    print(src_files)

    all_files = src_files | set(project['main_file'])

    if dataflow:
        # if we're injecting with dataflow, we must modify all files in src
        compile_commands = join(lp.bugs_build, 'compile_commands.json')
        print('compile commands is here: {}'.format(compile_commands))
        all_c_files = get_c_files(lp.bugs_build, compile_commands)
        # print('all_c_files: {}'.format(all_c_files))
        # print('all_files: {}'.format(all_files))
        all_files = all_files.union(all_c_files)

    # try:
    # pool = ThreadPool(max(cpu_count(), 1))
    # except Exception as e:
    # print("Warning: could not create ThreadPool, \
    # running with single-thread. {}".format(e))
    # pool = None

    def modify_source(dirname):
        return run_lavatool(bugs_to_inject, lp, host_file, project,
                            '/usr/lib/llvm-11', dirname, knobTrigger=args.knobTrigger,
                            dataflow=dataflow, competition=competition, randseed=lavatoolseed)

    bug_solutions = {}  # Returned by lavaTool

    for filename in all_files:
        # TODO call on directories instead of each file,
        # but still store results in bug_solutions
        bug_solutions.update(modify_source(filename))

    # TODO: Use our ThreadPool for modifying source and update bug_solutions
    # with results instead of single-thread
    # if pool:
    # pool.map(modify_source, all_files)
    clang_apply = join('/usr/lib/llvm-11', 'bin',
                       'clang-apply-replacements')

    src_dirs = set()
    src_dirs.add("")  # Empty path for root
    for filename in all_files:
        src_dir = dirname(filename)
        if len(src_dir):
            src_dirs.add(src_dir.encode("ascii", "ignore"))

    # TODO use pool here as well

    # Here we need to apply replacements. Unfortunately it can be a little complicated
    # compile_commands.json will be in lp.bugs_build. But then it contains data like:
    # directory: "[lp.bugs_build]/" file: src/foo.c" OR
    # directory: "[lp.bugs_build]/src" file: foo.c"
    # depending on how the makefile works

    # In theory, we should be able to run clang-apply-replacements
    # from the lp.bugs_build directory and it should _just work_ but that doesn't
    # always happen. Instead, we'll run it inside each unique src directory

    one_replacement_success = False
    for src_dir in src_dirs:
        clang_cmd = [clang_apply, '.', '-remove-change-desc-files']
        if debugging:  # Don't remove desc files
            clang_cmd = [clang_apply, '.']
        print("Apply replacements in {} with {}"
              .format(join(lp.bugs_build, src_dir), clang_cmd))
        (rv, outp) = run_cmd_notimeout(clang_cmd, cwd=join(lp.bugs_build, src_dir))

        if rv == 0:
            print("Success in {}".format(src_dir))
            one_replacement_success = True

    assert (one_replacement_success), "clang-apply-replacements failed in all possible directories"

    # Ugh.  Lavatool very hard to get right
    # Permit automated fixups via script after bugs inject
    # but before make. TODO: consolidate these arguments into project.keys
    if "injfixupsscript" in project.keys():
        print("Running injfixupsscript: {}"
              .format(project["injfixupsscript"]
                      .format(bug_build=lp.bugs_build), cwd=lp.bugs_build))
        run_cmd(project["injfixupsscript"]
                .format(bug_build=lp.bugs_build), cwd=lp.bugs_build)

    if hasattr(args, "fixupscript"):
        print("Running fixupscript: {}"
              .format(args.fixupscript.format(bug_build=lp.bugs_build),
                      cwd=lp.bugs_build))
        run_cmd(args.fixupsscript.format(bug_build=lp.bugs_build),
                cwd=lp.bugs_build)

    # paranoid clean -- some build systems need this
    if 'clean' in project.keys():
        check_call(project['clean'], cwd=lp.bugs_build, shell=True)

    # compile
    print("------------\n")
    print("ATTEMPTING BUILD OF INJECTED BUG(S)")
    print("build_dir = " + lp.bugs_build)

    # Silence warnings related to adding integers to pointers since we already
    # know that it's unsafe.
    make_cmd = project["make"]
    envv = {'CC': '/usr/lib/llvm-11/bin/clang',
            'CXX': '/usr/lib/llvm-11/bin/clang++',
            'CFLAGS': '-Wno-int-conversion -O0 -m32 -DHAVE_CONFIG_H -g -gdwarf-2 -fno-stack-protector -D_FORTIFY_SOURCE=0 -I. -I.. -I../include -I./src/'}
    if competition:
        envv["CFLAGS"] += " -DLAVA_LOGGING"
    (rv, outp) = run_cmd(make_cmd, envv, None, cwd=lp.bugs_build)

    if rv != 0:
        print("Lava tool returned {}! Error log below:".format(rv))
        print(outp[1])
        print()
        print("===================================")
        print("build of injected bug failed!!!!!!!")
        print("LAVA TOOL FAILED")
        print("===================================")
        print()
        print(outp[0].replace("\\n", "\n"))
        print(outp[1].replace("\\n", "\n"))

        print("Build of injected bugs failed")
        return (None, input_files, bug_solutions)

    # build success
    print("build succeeded")
    check_call(project['install'].format(install_dir="lava-install"),
               cwd=lp.bugs_build, shell=True)
    if 'post_install' in project.keys():
        check_call(project['post_install'], cwd=lp.bugs_build, shell=True)

    build = Build(compile=(rv == 0), output=(outp[0] + ";" + outp[1]),
                  bugs=bugs_to_inject)

    # add a row to the build table in the db
    if update_db:
        db.session.add(build)
        db.session.commit()
        assert build.id is not None
        try:
            run(['git', 'commit', '-am', 'Bugs for build {}.'.format(build.id)])
        except Exception:
            print("\nFatal error: git commit failed! \
                  This may be caused by lavaTool not modifying anything")
            raise

        run(['git', 'branch', 'build' + str(build.id), 'master'])
        run(['git', 'reset', 'HEAD~', '--hard'])

    return (build, input_files, bug_solutions)


def get_suffix(fn):
    split = basename(fn).split(".")
    if len(split) == 1:
        return ""
    else:
        return "." + split[-1]


# run the bugged-up program
def run_modified_program(project, install_dir, input_file,
                         timeout, shell=False):
    cmd = project['command'].format(install_dir=install_dir,
                                    input_file=input_file)
    # cmd = "{}".format(cmd) # ... this is a nop?
    # cmd = '/bin/bash -c '+ pipes.quote(cmd)
    envv = {}

    # If library path specified, set env var
    lib_path = project.get('library_path', '')
    if len(lib_path):
        lib_path = lib_path.format(install_dir=install_dir)
        envv["LD_LIBRARY_PATH"] = join(install_dir, lib_path)

        print("Run modified program: LD_LIBRARY_PATH={} {}"
              .format(join(install_dir, lib_path), cmd))
    else:
        print("Run modified program: {}".format(cmd))

    # Command might be redirecting input file in so we need shell=True
    return run_cmd(cmd, envv, timeout, cwd=install_dir, shell=shell)


# Find actual line number of attack point for this bug in source
def get_trigger_line(lp, bug):
    # TODO the triggers aren't a simple mapping from trigger of 0xlava - bug_id
    # But are the lava_get's still corelated to triggers?
    with open(join(lp.bugs_build, bug.atp.loc_filename), "r") as f:
        # TODO: should really check for lava_get(bug_id), but bug_id in db
        # isn't matching source for now, we'll just look for "(0x[magic]" since
        # that seems to always be there, at least for old bug types
        lava_get = "(0x{:x}".format(bug.magic)
        atp_lines = [line_num + 1 for line_num, line in enumerate(f) if
                     lava_get in line]  # and "lava_get" in line]
        # return closest to original begin line.
        distances = [
            (abs(line - bug.atp.loc_begin_line), line) for line in atp_lines
        ]
        if not distances:
            return None
        return min(distances)[1]


def check_competition_bug(rv, outp):
    assert (len(outp) == 2)
    (out, err) = outp

    if (rv % 256) <= 128:
        print("Clean exit (code {})".format(rv))
        return []  # No bugs unless you crash it

    # LAVALOG writes out to stderr
    return process_crash(err)


# use gdb to get a stacktrace for this bug
def check_stacktrace_bug(lp, project, bug, fuzzed_input):
    gdb_py_script = join(lp.lava_dir, "scripts/stacktrace_gdb.py")
    lib_path = project.get('library_path', '{install_dir}/lib')
    lib_path = lib_path.format(install_dir=lp.bugs_install)
    envv = {"LD_LIBRARY_PATH": lib_path}
    cmd = project['command'] \
        .format(install_dir=lp.bugs_install, input_file=fuzzed_input)
    gdb_cmd = "gdb --batch --silent -x {} --args {}".format(gdb_py_script, cmd)
    (rc, (out, err)) = run_cmd(gdb_cmd, cwd=lp.bugs_install, envv=envv)
    if debugging:
        for line in out.splitlines():
            print(line)
        for line in err.splitlines():
            print(line)
    prediction = " at {}:{}".format(basename(bug.atp.loc_filename),
                                    get_trigger_line(lp, bug))
    print("Prediction {}".format(prediction))
    for line in out.splitlines():
        if bug.type == Bug.RET_BUFFER:
            # These should go into garbage code if they trigger.
            if line.startswith("#0") and line.endswith(" in ?? ()"):
                return True
        elif bug.type == Bug.PRINTF_LEAK:
            # FIXME: Validate this!
            return True
        else:  # PTR_ADD or REL_WRITE for now.
            if line.startswith("#0") or \
                    bug.atp.typ == AttackPoint.FUNCTION_CALL:
                # Function call bugs are valid if they happen anywhere in
                # call stack.
                if line.endswith(prediction):
                    return True

    return False


def unfuzzed_input_for_bug(project, bug):
    return join(project["output_dir"], 'inputs',
                basename(bug.trigger.dua.inputfile))


def fuzzed_input_for_bug(project, bug):
    unfuzzed_input = unfuzzed_input_for_bug(project, bug)
    suff = get_suffix(unfuzzed_input)
    pref = unfuzzed_input[:-len(suff)] if suff != "" else unfuzzed_input
    return "{}-fuzzed-{}{}".format(pref, bug.id, suff)


def validate_bug(db, lp, project, bug, bug_index, build, args, update_db,
                 unfuzzed_outputs=None, competition=False, solution=None):
    unfuzzed_input = unfuzzed_input_for_bug(project, bug)
    fuzzed_input = fuzzed_input_for_bug(project, bug)
    print(str(bug))
    print("fuzzed = [%s]" % fuzzed_input)
    mutfile_kwargs = {}
    if args.knobTrigger:
        print("Knob size: {}".format(args.knobTrigger))
        mutfile_kwargs = {'kt': True, 'knob': args.knobTrigger}

    fuzz_labels_list = [bug.trigger.all_labels]
    if len(bug.extra_duas) > 0:
        extra_query = db.session.query(DuaBytes) \
            .filter(DuaBytes.id.in_(bug.extra_duas))
        fuzz_labels_list.extend([d.all_labels for d in extra_query])
    mutfile(unfuzzed_input, fuzz_labels_list, fuzzed_input, bug,
            solution=solution, **mutfile_kwargs)
    timeout = project.get('timeout', 5)
    (rv, outp) = run_modified_program(project, lp.bugs_install,
                                      fuzzed_input, timeout, shell=True)
    print("retval = %d" % rv)
    validated = False
    if bug.trigger.dua.fake_dua is False:
        print("bug type is " + Bug.type_strings[bug.type])
        if bug.type == Bug.PRINTF_LEAK:
            if outp != unfuzzed_outputs[bug.trigger.dua.inputfile]:
                print("printf bug -- outputs disagree\n")
                validated = True
        else:
            # this really is supposed to be a bug
            # we should see a seg fault or something
            # NB: Wrapping programs in bash transforms rv -> 128 - rv,
            # so we do the mod
            if (rv % 256) > 128 and rv != -9:  # check and ignoring timeouts
                print("RV indicates memory corruption")
                # Default: not checking that bug manifests at same line as
                # trigger point or is found by competition grading
                # infrastructure
                validated = True
                if competition:
                    found_bugs = check_competition_bug(rv, outp)
                    if set(found_bugs) == set([bug.id]):
                        print("... and competition infrastructure agrees")
                        validated &= True
                    else:
                        validated &= False
                        print("... but competition infrastructure"
                              " misidentified it ({} vs {})".format(found_bugs, bug.id))
                if args.checkStacktrace:
                    if check_stacktrace_bug(lp, project, bug, fuzzed_input):
                        print("... and stacktrace agrees with trigger line")
                        validated &= True
                    else:
                        print("... but stacktrace disagrees with trigger line")
                        validated &= False
            else:
                print("RV does not indicate memory corruption")
                validated = False
    else:
        # this really is supposed to be a non-bug
        # we should see a 0
        print("RV is zero which is good b/c this used a fake dua")
        assert rv == 0
        validated = False

    if update_db:
        db.session.add(Run(build=build, fuzzed=bug, exitcode=rv,
                           output=(outp[0] + '\n' + outp[1])
                           .decode('ascii', 'ignore'),
                           success=True, validated=validated))

    return validated


# validate this set of bugs
def validate_bugs(bug_list, db, lp, project, input_files, build,
                  args, update_db, competition=False, bug_solutions=None):
    timeout = project.get('timeout', 5)

    print("------------\n")
    # first, try the original files
    print("TESTING -- ORIG INPUT")
    print(bug_list)
    print("------------\n")
    unfuzzed_outputs = {}
    for input_file in input_files:
        unfuzzed_input = join(project["output_dir"],
                              'inputs', basename(input_file))
        (rv, outp) = run_modified_program(project, lp.bugs_install,
                                          unfuzzed_input, timeout, shell=True)
        unfuzzed_outputs[basename(input_file)] = outp
        if rv != args.exitCode:
            print("***** buggy program fails on original input - \
                  Exit code {} does not match expected {}"
                  .format(rv, args.exitCode))
            print(outp[0])
            print()
            print(outp[1])
            assert False  # Fails on original input
        else:
            print("buggy program succeeds on original input {}"
                  "with exit code {}".format(input_file, rv))
        print("output:")
        lines = outp[0] + " ; " + outp[1]
        if update_db:
            db.session.add(Run(build=build, fuzzed=None, exitcode=rv,
                               output=lines.decode('ascii', 'ignore'),
                               success=True, validated=False))
    print("ORIG INPUT STILL WORKS\n")

    # second, try each of the fuzzed inputs and validate
    print("TESTING -- FUZZED INPUTS")
    real_bugs = []
    bugs_to_inject = db.session.query(Bug).filter(Bug.id.in_(bug_list)).all()
    for bug_index, bug in enumerate(bugs_to_inject):
        print("=" * 60)
        print("Validating bug {} of {} ".format(
            bug_index + 1, len(bugs_to_inject)))

        # We should always have solutions for multidua bugs
        if bug_solutions and bug.id in bug_solutions.keys():
            validated = validate_bug(db, lp, project, bug, bug_index, build,
                                     args, update_db, unfuzzed_outputs,
                                     competition=competition,
                                     solution=bug_solutions[bug.id])
        else:
            print("No known solution for bug with id={}".format(bug.id))
            validated = validate_bug(db, lp, project, bug, bug_index, build,
                                     args, update_db, unfuzzed_outputs,
                                     competition=competition)
        if validated:
            real_bugs.append(bug.id)
        print()
    if len(bugs_to_inject) > 0:
        f = float(len(real_bugs)) / len(bugs_to_inject)
        print(u"yield {:.2f} ({} out of {}) real bugs (95% CI +/- {:.2f}) "
              .format(f, len(real_bugs), len(bugs_to_inject),
                      1.96 * math.sqrt(f * (1 - f) / len(bugs_to_inject))))
        print("A BOUNTIFUL CROP OF BUGS: %s" % (",".join(map(str, real_bugs))))
    else:
        print("yield to me")
    print("TESTING COMPLETE")

    if update_db:
        db.session.commit()

    return real_bugs


def get_bugs(db, bug_id_list):
    bugs = []
    for bug_id in bug_id_list:
        bugs.append(db.session.query(Bug).filter(Bug.id == bug_id).all()[0])
    return bugs


def get_allowed_bugtype_num(args):
    allowed_bugtype_nums = []
    for bugtype_name in args.bugtypes.split(","):
        if not len(bugtype_name):
            continue
        btnl = bugtype_name.lower()
        bugtype_num = None
        for i in range(len(Bug.type_strings)):
            btsl = Bug.type_strings[i].lower()
            if btnl in btsl:
                bugtype_num = i
        if bugtype_num is None:
            raise RuntimeError("I dont have a bug type [%s]" % bugtype_name)
        allowed_bugtype_nums.append(bugtype_num)

    return allowed_bugtype_nums
