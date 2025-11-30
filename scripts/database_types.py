from typing import List

from sqlalchemy.types import TypeEngine
from sqlalchemy import Column, ForeignKey, Table, create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import load_only, relationship, sessionmaker, composite
from sqlalchemy.sql.expression import func
from sqlalchemy.types import BigInteger, Boolean, Float, Integer, Text
import random
from dataclasses import dataclass
from sqlalchemy.engine.url import URL

Base = declarative_base()

dua_viable_bytes = \
    Table('dua_viable_bytes', Base.metadata,
          Column('object_id', BigInteger, ForeignKey('dua.id')),
          Column('index', BigInteger),
          Column('value', BigInteger, ForeignKey('labelset.id')))




build_bugs = \
    Table('build_bugs', Base.metadata,
          Column('object_id', BigInteger, ForeignKey('build.id')),
          Column('index', BigInteger, default=0),
          Column('value', BigInteger, ForeignKey('bug.id')))



class LavaDatabase(object):
    def __init__(self, project):
        self.project = project
        db_url = URL.create(
            drivername="postgresql+psycopg2",
            username=project['database_user'],
            password=project.get('database_password'),  # Assuming you have a password
            host=project['database'],  # Assuming this maps to host
            port=project['database_port'],
            database=project['db']
        )
        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    def close(self):
        """Closes the session and releases the connection to the pool."""
        if self.session:
            self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

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
            .options(load_only(Bug.id))
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
        yield ret.all()  # TODO randomize- or is it randomized already?

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
            if i in bug_types:
                bug_query = self.uninjected_random(fake).filter(Bug.type == i)
                print("found %d bugs of type %d" % (bug_query.count(), i))
                bugs.extend(bug_query[:num_per])
        return bugs

    def next_bug_random(self, fake):
        count = self.uninjected2(fake).count()
        return self.uninjected2(fake)[random.randrange(0, count)]

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

    required_extra_duas_for_type = {
        'PTR_ADD' : 0,
        'RET_BUFFER' : 1,
        'REL_WRITE' : 2,
        'PRINTF_LEAK' : 0,
        'MALLOC_OFF_BY_ONE' : 0
    }

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

class Composite(object):
    def __init__(self, *args):
        arg_idx = 0
        for name, column_type in self._columns():
            if issubclass(column_type, TypeEngine):
                setattr(self, name, args[arg_idx])
                arg_idx += 1
            elif issubclass(column_type, Composite):
                count = len(column_type._columns())
                setattr(self, name,
                        column_type(*args[arg_idx:arg_idx+count]))
                arg_idx += count
            else: assert False

    def _all_values(self, prefix):
        result = []
        for name, column_type in self._columns():
            if issubclass(column_type, TypeEngine):
                result.append(getattr(self, name))
            elif issubclass(column_type, Composite):
                result.extend(getattr(self, name)._all(name + '_'))
            else: assert False
        return result

    def __composite_values__(self):
        return tuple(self._all_values(''))

    def __eq__(self, other):
        return type(self) == type(other) and \
            self.__composite_values__() == \
            other.__composite_values__()

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def _columns(cls):
        return [(v, getattr(cls, v)) for v in vars(cls) if not v.startswith('__')]

    @classmethod
    def inner_columns(cls, prefix):
        result = []
        for column_name, column_type in cls._columns():
            if issubclass(column_type, TypeEngine):
                result.append(Column(prefix + '_' + column_name, column_type))
            elif issubclass(column_type, Composite):
                result.extend(
                    column_type.inner_columns(prefix + '_' + column_name))
        return result

    @classmethod
    def composite(cls, name):
        return composite(cls, *cls.inner_columns(name))


@dataclass(frozen=True, order=True)
class Loc:
    line: int
    column: int

    def __str__(self):
        return f"{self.line}:{self.column}"


@dataclass(frozen=True, order=True)
class ASTLoc(Composite):
    filename: str = Text
    begin = Loc
    end = Loc

    @classmethod
    def from_serialized(cls, serialized_str: str):
        """
        Parses string format: filename:start_line:start_col:end_line:end_col
        Example: "src/main.c:10:5:10:20"
        Args:
            serialized_str: The serialized ASTLoc string.
        Returns:
            An ASTLoc instance.
        """
        parts = serialized_str.split(':')

        # Safety check: ensure we have at least 5 parts
        # (Filename might contain colons, so we handle that below)
        if len(parts) < 5:
            raise ValueError(f"Invalid serialized ASTLoc: {serialized_str}")

        # The last 4 parts are always numbers.
        # Everything before them is the filename (re-join in case filename has ':')
        filename = ":".join(parts[:-4])

        # Parse the coordinates
        begin_line, begin_col = int(parts[-4]), int(parts[-3])
        end_line, end_col = int(parts[-2]), int(parts[-1])

        return ASTLoc(
            filename=filename,
            begin=Loc(begin_line, begin_col),
            end=Loc(end_line, end_col)
        )

@dataclass(frozen=True)
class BugParam(Composite):
    atp_id: int = BigInteger
    type: int = Integer

    def __lt__(self, other) -> bool:
        return (self.atp_id, self.type) < (other.atp_id, other.type)

    def __repr__(self) -> str:
        return f"BugParam(atp_id={self.atp_id}, type={self.type})"

class Range(Composite):
    low: int = Integer
    high: int = Integer

    def size(self) -> int:
        return self.high - self.low

    def empty(self) -> bool:
        return self.high <= self.low

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

    id : int = Column(BigInteger, primary_key=True)
    ptr : int = Column(BigInteger)
    inputfile : str = Column(Text)
    labels : List[int] = Column(postgresql.ARRAY(Integer))

    def __repr__(self):
        return str(self.labels)

class Dua(Base):
    __tablename__ = 'dua'
    id: int = Column(BigInteger, primary_key=True)
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
    MALLOC_OFF_BY_ONE = 5

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
