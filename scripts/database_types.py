from typing import List

from sqlalchemy.types import TypeEngine
from sqlalchemy import Column, ForeignKey, Table, create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import load_only, relationship, sessionmaker, composite, Mapped, mapped_column
from sqlalchemy.sql.expression import func
from sqlalchemy.types import BigInteger, Boolean, Float, Integer, Text
import random
from dataclasses import dataclass
from sqlalchemy.engine.url import URL
from sqlalchemy.types import TypeDecorator
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from enum import IntEnum

Base = declarative_base()

def create_range(l, h):
    return Range(l, h)

def create_ast_loc(f, bl, bc, el, ec):
    return ASTLoc(f, Loc(bl, bc), Loc(el, ec))

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


class SortedIntArray(TypeDecorator):
    """
    Automatically sorts a list of integers before sending it to the database.
    This ensures that [2, 1] and [1, 2] are treated as the exact same set.
    """
    impl = ARRAY(Integer) # The underlying DB type is still INT[]

    def process_bind_param(self, value, dialect):
        # This runs BEFORE the data goes to SQL (both INSERT and SELECT)
        if value is not None:
            return sorted(value)
        return value

    def process_result_value(self, value, dialect):
        # This runs when data comes BACK from the database
        # (Postgres usually keeps arrays in order, but good to be safe)
        if value is not None:
            return sorted(value)
        return value


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

class BugKind(IntEnum):
    BUG_PTR_ADD = 0
    BUG_RET_BUFFER = 1
    BUG_REL_WRITE = 2
    BUG_PRINTF_LEAK = 3
    BUG_MALLOC_OFF_BY_ONE = 4

    def __str__(self):
        return self.name


class Bug(Base):
    __tablename__ = 'bug'

    # 1. Primary Key
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    # 2. Foreign Keys (Use Mapped[int])
    # Note: We name the Python attribute 'trigger_id', but map it to DB column 'trigger'
    trigger_id: Mapped[int] = mapped_column('trigger', BigInteger, ForeignKey('duabytes.id'))
    trigger_lval_id: Mapped[int] = mapped_column('trigger_lval', BigInteger, ForeignKey('sourcelval.id'))
    atp_id: Mapped[int] = mapped_column('atp', BigInteger, ForeignKey('attackpoint.id'))

    # 3. Rename 'type' to 'typ' to avoid Python keyword collision
    # It still maps to the database column named "type"
    type: Mapped[BugKind] = mapped_column("type", Integer, nullable=False)

    # 4. Relationships (CRITICAL FIX FOR IDE WARNINGS)
    # Using Mapped["ClassName"] tells the IDE these are valid constructor args
    trigger: Mapped["DuaBytes"] = relationship("DuaBytes")
    trigger_lval: Mapped["SourceLval"] = relationship("SourceLval")
    atp: Mapped["AttackPoint"] = relationship("AttackPoint")

    # 5. Other Columns
    max_liveness: Mapped[float] = mapped_column(Float, nullable=True)
    magic: Mapped[int] = mapped_column(Integer, nullable=True)

    # 6. Postgres Array
    # Mapped[List[int]] makes usage clear
    extra_duas: Mapped[List[int]] = mapped_column(postgresql.ARRAY(BigInteger), nullable=True)

    # 7. Many-to-Many
    builds: Mapped[List["Build"]] = relationship("Build", secondary="build_bugs", back_populates="bugs")

    required_extra_duas_for_type = {
        BugKind.BUG_PTR_ADD: 0,
        BugKind.BUG_RET_BUFFER: 1,
        BugKind.BUG_REL_WRITE: 2,
        BugKind.BUG_PRINTF_LEAK: 0,
        BugKind.BUG_MALLOC_OFF_BY_ONE: 0
    }

    @classmethod
    def num_extra_duas(cls, bug_type: BugKind):
        return cls.required_extra_duas_for_type[bug_type]

    def __str__(self):
        return 'Bug[{}](type={}, trigger={}, atp={})'.format(
            self.id, self.typ.name, self.trigger, self.atp)


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
    line: int = Integer
    column: int = Integer

    def __str__(self):
        return f"{self.line}:{self.column}"


@dataclass(frozen=True, order=True)
class ASTLoc(Composite):
    filename: str = Text
    begin : Loc = Loc
    end : Loc = Loc

    def __composite_values__(self):
        return (
            self.filename,
            self.begin.line,
            self.begin.column,
            self.end.line,
            self.end.column
        )

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

class Range(Composite):
    low: int = Integer
    high: int = Integer

    def size(self) -> int:
        return self.high - self.low

    def empty(self) -> bool:
        return self.high <= self.low

    def __composite_values__(self):
        return self.low, self.high

class SourceLval(Base):
    __tablename__ = 'sourcelval'

    # 1. Primary Key
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    # 2. Explicitly Define the Composite Columns
    # This mirrors exactly what we did for AttackPoint.
    # We prefix columns with "loc_" to keep the DB clean.
    _f:  Mapped[str] = mapped_column("loc_filename", Text, nullable=False)
    _bl: Mapped[int] = mapped_column("loc_begin_line", Integer, nullable=False)
    _bc: Mapped[int] = mapped_column("loc_begin_col", Integer, nullable=False)
    _el: Mapped[int] = mapped_column("loc_end_line", Integer, nullable=False)
    _ec: Mapped[int] = mapped_column("loc_end_col", Integer, nullable=False)

    # 3. Map them to the ASTLoc Object
    # Using the same helper function 'create_ast_loc' from before
    loc: Mapped[ASTLoc] = composite(create_ast_loc, _f, _bl, _bc, _el, _ec)

    # 4. Other Columns
    ast_name: Mapped[str] = mapped_column(Text, nullable=False)
    len: Mapped[int] = mapped_column(Integer, nullable=False)

    def __str__(self):
        return f"LVAL[{self.id}](loc={self.loc}, node={self.ast_name}, len={self.len})"

    def __repr__(self):
        return self.__str__()


class LabelSet(Base):
    __tablename__ = 'labelset'

    id : int = Column(BigInteger, primary_key=True)
    ptr : int = Column(BigInteger)
    inputfile : str = Column(Text)
    labels : List[int] = Column(SortedIntArray)

    def __repr__(self):
        return str(self.labels)


class Dua(Base):
    __tablename__ = 'dua'

    # 1. Primary Key
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    # 2. Foreign Key (Column name is 'lval' to match C++ ODB default)
    lval_id: Mapped[int] = mapped_column('lval', BigInteger, ForeignKey('sourcelval.id'))

    # 3. Vectors / Arrays
    # Note: 'secondary' requires the association table 'dua_viable_bytes' to be defined!
    viable_bytes: Mapped[List["LabelSet"]] = relationship("LabelSet", secondary="dua_viable_bytes")

    # The missing column from C++ std::vector<uint32_t> byte_tcn
    byte_tcn: Mapped[List[int]] = mapped_column(postgresql.ARRAY(Integer))

    # C++ std::vector<uint32_t> all_labels
    all_labels: Mapped[List[int]] = mapped_column(postgresql.ARRAY(Integer))

    # 4. Standard Metadata
    inputfile: Mapped[str] = mapped_column(Text)
    max_tcn: Mapped[int] = mapped_column(Integer)
    max_cardinality: Mapped[int] = mapped_column(Integer)
    instr: Mapped[int] = mapped_column(BigInteger)
    fake_dua: Mapped[bool] = mapped_column(Boolean)

    # 5. Relationship Backref
    lval: Mapped["SourceLval"] = relationship("SourceLval")

    # 6. Unique Constraint (Matches #pragma db index("DuaUniq")...)
    __table_args__ = (
        UniqueConstraint(
            'lval',  # Refers to the column name defined in lval_id
            'inputfile',
            'instr',
            'fake_dua',
            name='DuaUniq'
        ),
    )

    def __str__(self):
        # Mirrors the C++ operator<< logic fairly closely
        return 'DUA[{}][{}, viable_len={}, labels={}, tcn_len={}, {}, {}, instr={}, {}]'.format(
            self.inputfile,
            self.lval,
            len(self.viable_bytes) if self.viable_bytes else 0,
            self.all_labels,
            len(self.byte_tcn) if self.byte_tcn else 0,
            self.max_tcn,
            self.max_cardinality,
            self.instr,
            'fake' if self.fake_dua else 'real'
        )


class DuaBytes(Base):
    __tablename__ = 'duabytes'

    # 1. Primary Key
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    # 2. Foreign Key
    dua_id: Mapped[int] = mapped_column('dua', BigInteger, ForeignKey('dua.id'))

    # 3. Explicit Composite Columns
    # We map the DB columns 'selected_low' and 'selected_high'
    _low: Mapped[int] = mapped_column("selected_low", Integer, nullable=False)
    _high: Mapped[int] = mapped_column("selected_high", Integer, nullable=False)

    # 4. The Composite Property
    # Usage: my_duabytes.selected.size
    selected: Mapped[Range] = composite(create_range, _low, _high)

    # 5. Other Columns
    all_labels: Mapped[List[int]] = mapped_column(postgresql.ARRAY(Integer))

    # 6. Relationship
    dua: Mapped["Dua"] = relationship("Dua")

    def __str__(self):
        # Note: Updated 'ast_name' to 'ast_node_name' to match your SourceLval definition
        return 'DUABytes[DUA[{}:{}, {}, {}]][{}:{}](labels={})'.format(
            self.dua.lval.loc.filename,
            self.dua.lval.loc.begin.line,
            self.dua.lval.ast_node_name,
            'fake' if self.dua.fake_dua else 'real',
            self.selected.low,
            self.selected.high,
            self.all_labels
        )


class AtpKind(IntEnum):
    FUNCTION_CALL = 0
    POINTER_READ = 1
    POINTER_WRITE = 2
    QUERY_POINT = 3
    PRINTF_LEAK = 4
    MALLOC_OFF_BY_ONE = 5

    def __str__(self):
        return f"ATP_{self.name}"

class AttackPoint(Base):
    __tablename__ = 'attackpoint'

    id: int = Column(BigInteger, primary_key=True)

    # --- 1. Define the ACTUAL Database Columns ---
    # These hold the raw data. We prefix them with "loc_" to namespace them.
    _f: Mapped[str] = mapped_column("loc_filename", Text)
    _bl: Mapped[int] = mapped_column("loc_begin_line", Integer, nullable=False)
    _bc: Mapped[int] = mapped_column("loc_begin_col", Integer, nullable=False)
    _el: Mapped[int] = mapped_column("loc_end_line", Integer, nullable=False)
    _ec: Mapped[int] = mapped_column("loc_end_col", Integer, nullable=False)

    # --- 2. Define the Composite Bridge ---
    # This maps the 5 columns above into your ASTLoc class.
    loc: Mapped[ASTLoc] = composite(create_ast_loc, _f, _bl, _bc, _el, _ec)
    typ: Mapped[AtpKind] = mapped_column("type", Integer, nullable=False)

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

    #  Enforce Uniqueness at the Database Level
    # This is critical once we start passing lots of files via concolic execution, expect lots of duplicates.
    __table_args__ = (
        UniqueConstraint(
            'loc_filename', 'loc_begin_line', 'loc_begin_col',
            'loc_end_line', 'loc_end_col', 'type',
            name='_atp_unique_constraint'
        ),
    )