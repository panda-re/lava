from typing import List, Union, Any, cast
import random
from dataclasses import dataclass
from enum import IntEnum
import os
from sqlalchemy import Column, ForeignKey, Table, create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import load_only, relationship, sessionmaker, composite, Mapped, mapped_column
from sqlalchemy.sql.expression import func
from sqlalchemy.types import BigInteger, Boolean, Integer, Text
from sqlalchemy.engine.url import URL
from sqlalchemy.types import TypeDecorator
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy.ext.associationproxy import association_proxy

Base = declarative_base()

build_bugs = Table(
    'build_bugs', Base.metadata,
    Column('object_id', BigInteger, ForeignKey('build.id'), primary_key=True),
    Column('index', Integer, default=0), # ODB often uses an index for vectors
    Column('value', BigInteger, ForeignKey('bug.id'), primary_key=True)
)

def create_range(l, h):
    return Range(l, h)

def create_ast_loc(f, bl, bc, el, ec):
    return ASTLoc(f, Loc(bl, bc), Loc(el, ec))


class DuaViableByte(Base):
    __tablename__ = 'dua_viable_bytes'

    # 1. Foreign Keys
    # 'object_id' matches ODB's name for the pointer to Dua
    object_id: Mapped[int] = mapped_column(BigInteger, ForeignKey('dua.id'), primary_key=True)

    # 'value' matches ODB's name for the pointer to LabelSet
    labelset_id: Mapped[int] = mapped_column('value', BigInteger,
                                             ForeignKey('labelset.id'),
                                             primary_key=True)

    # 2. The Index Column (This is what caused your crash!)
    # We make it a primary key component or just a column.
    # ODB usually relies on the order, but let's make it a column.
    index: Mapped[int] = mapped_column(Integer, nullable=False)

    # 3. Relationships
    # We don't need a relationship back to Dua here necessarily, but we need one to LabelSet
    labelset: Mapped["LabelSet"] = relationship("LabelSet")

    def __repr__(self):
        return f"<DuaViableByte index={self.index} ls={self.labelset_id}>"


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
    def __init__(self, project: dict[str, Any]):
        self.project = project
        db_url = URL.create(
            drivername="postgresql+psycopg2",
            username=project['database_user'],
            password=os.getenv("POSTGRES_PASSWORD", ""),  # Assuming you have a password
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

    def uninjected_random_limit(self, allowed_bugtypes=None, count=100):
        # Fast, doesn't support fake bugs, only return IDs of allowed bugtypes
        ret = self.session.query(Bug) \
            .filter(~Bug.builds.any()) \
            .options(load_only(Bug.id))
        if allowed_bugtypes:
            ret = ret.filter(Bug.type.in_(allowed_bugtypes))
        return ret.order_by(func.random()).limit(count).all()

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
        assert num_avail > 0
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
    BUG_CHAFF_STACK_UNUSED = 5,
    BUG_CHAFF_STACK_CONST = 6,
    BUG_CHAFF_HEAP_CONST = 7,
    BUG_CHAFF_DIVZERO = 8

    def __str__(self):
        return self.name


class Bug(Base):
    __tablename__ = 'bug'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    # Mapped directly to columns
    trigger: Mapped[int] = mapped_column('trigger', BigInteger, ForeignKey('duabytes.id'), nullable=False)
    trigger_lval: Mapped[int] = mapped_column('trigger_lval', BigInteger, ForeignKey('sourcelval.id'), nullable=False)
    atp: Mapped[int] = mapped_column('atp', BigInteger, ForeignKey('attackpoint.id'), nullable=False)
    type: Mapped[BugKind] = mapped_column("type", Integer, nullable=False)

    max_liveness: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    magic: Mapped[int] = mapped_column(Integer, nullable=False)
    extra_duas: Mapped[List[int]] = mapped_column(postgresql.ARRAY(BigInteger), nullable=False)

    # --- Added for Chaff Bugs ---
    # uint32_t stackoff;
    stackoff: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    trigger_relationship: Mapped["DuaBytes"] = relationship("DuaBytes", foreign_keys=[trigger],
                                                            overlaps="trigger", viewonly=True)
    atp_relationship: Mapped["AttackPoint"] = relationship("AttackPoint", foreign_keys=[atp],
                                                           overlaps="atp", viewonly=True)
    lval_relationship: Mapped["SourceLval"] = relationship("SourceLval", foreign_keys=[trigger_lval],
                                                           viewonly=True, overlaps="trigger_lval")

    builds: Mapped[List["Build"]] = relationship(
        "Build",
        secondary=build_bugs,
        back_populates="bugs"
    )

    # --- Structural Constraint Updates ---
    __table_args__ = (
        # #pragma db index("BugUniq") unique members(type, atp, trigger, extra_duas)
        UniqueConstraint('type', 'atp', 'trigger', 'extra_duas', name='BugUniq'),
    )

    # Mirroring num_extra_duas array
    required_extra_duas_for_type = {
        BugKind.BUG_PTR_ADD: 0,
        BugKind.BUG_RET_BUFFER: 1,
        BugKind.BUG_REL_WRITE: 2,
        BugKind.BUG_PRINTF_LEAK: 0,
        BugKind.BUG_MALLOC_OFF_BY_ONE: 0,
        BugKind.BUG_CHAFF_STACK_UNUSED: 0,
        BugKind.BUG_CHAFF_STACK_CONST: 1,
        BugKind.BUG_CHAFF_HEAP_CONST: 1,
        BugKind.BUG_CHAFF_DIVZERO: 1,
    }

    def __init__(self,
                 bug_type: BugKind,
                 trigger: Union[int, "DuaBytes"],
                 atp: Union[int, "AttackPoint"],
                 extra_duas: Union[List[int], List["DuaBytes"]],
                 stackoff: int = 0,
                 max_liveness: int = 0, **kwargs):

        t_id = trigger.id if hasattr(trigger, 'id') else trigger
        a_id = atp.id if hasattr(atp, 'id') else atp

        # Replicating C++ explicit tracking fallback for trigger_lval assignment
        resolved_lval_id: int = -1
        if hasattr(trigger, 'dua_relationship') and trigger.dua_relationship:
            resolved_lval_id = trigger.dua_relationship.lval
        elif hasattr(trigger, 'dua') and not isinstance(trigger.dua, int):
            resolved_lval_id = trigger.dua.lval

        final_extras = []
        if extra_duas:
            for item in extra_duas:
                if isinstance(item, int):
                    final_extras.append(item)
                elif hasattr(item, 'id'):
                    final_extras.append(item.id)
                else:
                    raise ValueError(f"Invalid item in extra_duas: {item}")

        # Replicating magic computation block
        c_magic = 0
        for _ in range(4):
            c_magic <<= 8
            val = (random.randint(0, 32767) % 26) + 0x60
            c_magic |= val
            if random.randint(0, 32767) & 0x20:
                c_magic ^= 0x20

        super().__init__(
            type=bug_type,
            trigger=t_id,
            trigger_lval=resolved_lval_id,
            atp=a_id,
            extra_duas=final_extras,
            stackoff=stackoff,  # Propagated to column mapping definition
            max_liveness=max_liveness,
            magic=c_magic,
            **kwargs
        )

    def magic_kt(self) -> int:
        """Mirrors inline uint16_t magic_kt() const"""
        return self.magic & 0xffff

    def __str__(self):
        return 'Bug[{}](type={}, trigger={}, atp={}, stackoff={})'.format(
            self.id, BugKind(self.type).name, self.trigger, self.atp, self.stackoff)


class Build(Base):
    __tablename__ = 'build'

    id : Mapped[int] = mapped_column('id', BigInteger, primary_key=True)
    compile : Mapped[bool] = mapped_column('compile', Boolean, nullable=False)
    output : Mapped[str] = mapped_column('output', Text, nullable=False)
    bugs: Mapped[List["Bug"]] = relationship(
        "Bug",
        secondary=build_bugs,
        back_populates="builds"
    )

class Run(Base):
    __tablename__ = 'run'

    id : Mapped[int] = mapped_column('id', BigInteger, primary_key=True)
    build : Mapped[int] = mapped_column('build', BigInteger, ForeignKey('build.id'), nullable=False)
    fuzzed : Mapped[int] = mapped_column('fuzzed', BigInteger, ForeignKey('bug.id'), nullable=True)
    exitcode : Mapped[int] = mapped_column('exitcode', Integer, nullable=False)
    output : Mapped[str] = mapped_column('output', Text, nullable=False)
    success : Mapped[bool] = mapped_column('success', Boolean, nullable=False)
    validated : Mapped[bool] = mapped_column('validated', Boolean, nullable=False)

    build_relationship : Mapped["Build"] = relationship("Build", overlaps="build")
    fuzzed_relationship : Mapped["Bug"] = relationship("Bug", overlaps="fuzzed")

@dataclass(frozen=True, order=True)
class Loc:
    line: int = Integer
    column: int = Integer

    def __str__(self):
        return f"{self.line}:{self.column}"


@dataclass(frozen=True, order=True)
class ASTLoc:
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

        # Parse the coordinates
        begin_line, begin_col = int(parts[0]), int(parts[1])
        end_line, end_col = int(parts[2]), int(parts[3])
        filename = parts[4]

        return ASTLoc(
            filename=filename,
            begin=Loc(begin_line, begin_col),
            end=Loc(end_line, end_col)
        )

@dataclass(frozen=True, order=True)
class Range:
    low: int
    high: int

    # Logic methods work fine here
    def size(self) -> int:
        return self.high - self.low

    def empty(self) -> bool:
        return self.high <= self.low

    # Required for SQLAlchemy to read the object back from the DB
    def __composite_values__(self):
        return self.low, self.high

    # Optional: Logic for comparing Ranges (useful for your bug finding)
    def __eq__(self, other):
        return isinstance(other, Range) and self.low == other.low and self.high == other.high


class SourceLval(Base):
    __tablename__ = 'sourcelval'

    # 1. Primary Key
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    # 2. Explicitly Define the Composite Columns
    # This mirrors exactly what we did for AttackPoint.
    # We prefix columns with "loc_" to keep the DB clean.
    _f:  Mapped[str] = mapped_column("loc_filename", Text, nullable=False)
    _bl: Mapped[int] = mapped_column("loc_begin_line", Integer, nullable=False)
    _bc: Mapped[int] = mapped_column("loc_begin_column", Integer, nullable=False)
    _el: Mapped[int] = mapped_column("loc_end_line", Integer, nullable=False)
    _ec: Mapped[int] = mapped_column("loc_end_column", Integer, nullable=False)

    # 3. Map them to the ASTLoc Object
    # Using the same helper function 'create_ast_loc' from before
    loc: Mapped[ASTLoc] = composite(create_ast_loc, _f, _bl, _bc, _el, _ec)

    # 4. Other Columns
    ast_name: Mapped[str] = mapped_column(Text, nullable=False)
    len_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    def __str__(self):
        return f"LVAL[{self.id}](loc={self.loc}, node={self.ast_name}, len={self.len_bytes})"

    def __repr__(self):
        return self.__str__()


class LabelSet(Base):
    __tablename__ = 'labelset'

    # 1. Primary Key
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    # 2. Data Columns
    ptr: Mapped[int] = mapped_column(BigInteger, nullable=False)
    inputfile: Mapped[str] = mapped_column(Text, nullable=False)

    # 3. Array Column (Using your SortedIntArray type)
    labels: Mapped[List[int]] = mapped_column(SortedIntArray, nullable=False)

    # 4. Unique Constraint (Matches C++ #pragma db index("LabelSetUniq"))
    __table_args__ = (
        UniqueConstraint('ptr', 'inputfile', name='LabelSetUniq'),
    )

    def __repr__(self):
        return f"LabelSet(ptr={self.ptr}, labels={self.labels})"

class Dua(Base):
    __tablename__ = 'dua'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    lval: Mapped[int] = mapped_column('lval', BigInteger, ForeignKey('sourcelval.id'), nullable=False)

    _viable_bytes_assoc: Mapped[List["DuaViableByte"]] = relationship(
        "DuaViableByte",
        order_by="DuaViableByte.index",
        collection_class=ordering_list("index"),
        cascade="all, delete-orphan"
    )

    viable_bytes = association_proxy(
        '_viable_bytes_assoc',
        'labelset',
        creator=lambda ls: DuaViableByte(labelset=ls)
    )

    byte_tcn: Mapped[List[int]] = mapped_column(postgresql.ARRAY(Integer), nullable=False)
    all_labels: Mapped[List[int]] = mapped_column(postgresql.ARRAY(Integer), nullable=False)

    inputfile: Mapped[str] = mapped_column(Text, nullable=False)
    max_tcn: Mapped[int] = mapped_column(Integer, nullable=False)
    max_cardinality: Mapped[int] = mapped_column(Integer, nullable=False)
    instr: Mapped[int] = mapped_column(BigInteger, nullable=False)
    fake_dua: Mapped[bool] = mapped_column(Boolean, nullable=False)

    # --- Added for Chaff Bugs ---
    # uint64_t trace_index;
    trace_index: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # OPTIONAL BOOTSTRAPPING FOR PYTHON:
    # This allows you to do `my_dua.source_trace` directly in Python to grab the
    # matched SourceTrace row, matching on `SourceTrace.index` instead of its primary key ID.
    source_trace_relationship: Mapped["SourceTrace"] = relationship(
        "SourceTrace",
        primaryjoin="Dua.trace_index == SourceTrace.index",
        foreign_keys=[trace_index],
        viewonly=True,  # viewonly ensures Python doesn't try to alter C++ tables automatically
    )

    __table_args__ = (
        UniqueConstraint(
            'lval',
            'inputfile',
            'instr',
            'fake_dua',
            name='DuaUniq'
        ),
    )

    def __str__(self):
        # Mirrors the C++ stream print: DUA [inputfile][lval_str,...viable_bytes...]
        return 'DUA [{}][{}, viable_len={}, labels={}, tcn_len={}, {}, {}, instr={}, {}, trace_idx={}]'.format(
            self.inputfile,
            self.lval,
            len(self.viable_bytes) if self.viable_bytes else 0,
            self.all_labels,
            len(self.byte_tcn) if self.byte_tcn else 0,
            self.max_tcn,
            self.max_cardinality,
            self.instr,
            'fake' if self.fake_dua else 'real',
            self.trace_index
        )

    def __lt__(self, other):
        if not isinstance(other, Dua):
            return NotImplemented
        return (self.lval, self.inputfile, self.instr, self.fake_dua) < \
            (other.lval, other.inputfile, other.instr, other.fake_dua)


class DuaBytes(Base):
    __tablename__ = 'duabytes'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    dua: Mapped[int] = mapped_column('dua', BigInteger, ForeignKey('dua.id'), nullable=False)

    # Composite Range Columns
    _low: Mapped[int] = mapped_column("selected_low", Integer, nullable=False)
    _high: Mapped[int] = mapped_column("selected_high", Integer, nullable=False)
    selected: Mapped[Range] = composite(create_range, _low, _high)

    all_labels: Mapped[List[int]] = mapped_column(
                                    postgresql.ARRAY(Integer),
                                    nullable=False,
                                    default=list,
                                    server_default='{}')

    # Relationship
    dua_relationship: Mapped[Dua] = relationship("Dua", viewonly=True, overlaps="dua")

    # Mirroring the C++ Index: unique members(dua, selected)
    __table_args__ = (
        UniqueConstraint('dua', 'selected_low', 'selected_high', name='DuaBytesUniq'),
    )

    def __init__(self, dua: Union[Dua, int] = None, selected : Range = None, **kwargs):
        """
        Mirroring the C++ Constructor:
        DuaBytes(const Dua *dua, Range selected)
        """
        if isinstance(dua, int):
            super().__init__(dua=dua, selected=selected, **kwargs)
            return

        # Standard initialization
        super().__init__(dua=dua, selected=selected, **kwargs)

        if dua and selected:
            # Mirror the C++ Asserts
            assert selected.low <= selected.high
            # In Python, we assume dua.viable_bytes is a list of LabelSet objects
            assert selected.high <= len(dua.viable_bytes)

            # Mirror the C++ loop and merge_into logic
            # We use a set for unique labels, then sort it to match 'SortedIntArray' expectations
            labels_set = set()
            for ls in dua.viable_bytes[selected.low:selected.high]:
                if ls and ls.labels:
                    labels_set.update(ls.labels)

            self.all_labels = sorted(list(labels_set))

    def __str__(self):
        # Using .getattr or checking if relationship is loaded to avoid LazyLoad errors in logs
        dua_info = f"DUA[{self.dua}]"
        if self.dua and self.dua_relationship.lval:
            dua_info = '{}:{}:{}'.format(
                self.dua_relationship.lval_relationship.loc.filename,
                self.dua_relationship.lval_relationship.loc.begin.line,
                self.dua_relationship.lval_relationship.loc.end.line,
            )

        return 'DUABytes[{}][{}:{}](labels={})'.format(
            dua_info, self.selected.low, self.selected.high, self.all_labels
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


class CallTrace(Base):
    __tablename__ = 'calltrace'
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    caller: Mapped[str] = mapped_column("caller", Text, nullable=False)
    file: Mapped[str] = mapped_column("file", Text, nullable=False)
    # Enforce Uniqueness at the Database Level
    # This is critical once we start passing lots of files via concolic execution, expect lots of duplicates.
    __table_args__ = (
        UniqueConstraint(
            'caller', 'file',
            name='_calltrace_unique_constraint'
        ),
    )

    def __lt__(self, other):
        """
        Mirrors C++ operator<:
        """
        if not isinstance(other, CallTrace):
            return NotImplemented

        # We use lval_id directly (the Foreign Key ID) as it is much faster
        # than triggering a lazy load for the full SourceLval object.
        return (self.caller, self.file ) < (other.caller, other.file)


class SourceTrace(Base):
    __tablename__ = 'sourcetrace'

    # #pragma db id auto
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # #pragma db not_null
    index: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # #pragma db not_null ASTLoc loc
    # Define the ACTUAL Database Columns for composite mapping
    _f: Mapped[str] = mapped_column("loc_filename", Text, nullable=False)
    _bl: Mapped[int] = mapped_column("loc_begin_line", Integer, nullable=False)
    _bc: Mapped[int] = mapped_column("loc_begin_column", Integer, nullable=False)
    _el: Mapped[int] = mapped_column("loc_end_line", Integer, nullable=False)
    _ec: Mapped[int] = mapped_column("loc_end_column", Integer, nullable=False)

    # Map them to the ASTLoc Object using your helper function
    loc: Mapped[ASTLoc] = composite(create_ast_loc, _f, _bl, _bc, _el, _ec)

    # #pragma db index("SourceTraceUniq") unique members(index)
    __table_args__ = (
        UniqueConstraint('index', name='SourceTraceUniq'),
    )

    def __lt__(self, other):
        if not isinstance(other, SourceTrace):
            return NotImplemented
        return self.index < other.index

    def __repr__(self):
        return f"<SourceTrace id={self.id} index={self.index} loc={self.loc}>"


class AttackPoint(Base):
    __tablename__ = 'attackpoint'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    # --- 1. Define the ACTUAL Database Columns ---
    # These hold the raw data. We prefix them with "loc_" to namespace them.
    _f: Mapped[str] = mapped_column("loc_filename", Text)
    _bl: Mapped[int] = mapped_column("loc_begin_line", Integer, nullable=False)
    _bc: Mapped[int] = mapped_column("loc_begin_column", Integer, nullable=False)
    _el: Mapped[int] = mapped_column("loc_end_line", Integer, nullable=False)
    _ec: Mapped[int] = mapped_column("loc_end_column", Integer, nullable=False)

    # --- 2. Define the Composite Bridge ---
    # This maps the 5 columns above into your ASTLoc class.
    loc: Mapped[ASTLoc] = composite(create_ast_loc, _f, _bl, _bc, _el, _ec)
    type: Mapped[AtpKind] = mapped_column("type", Integer, nullable=False)

    # --- 3. Chaff Bug Extensions ---
    # std::vector<uint64_t> calltrace;
    calltrace: Mapped[List[int]] = mapped_column(
        postgresql.ARRAY(BigInteger),
        nullable=False,
        default=list,
        server_default='{}'
    )

    # uint64_t trace_index; (Tracks context relationship to SourceTrace.index)
    trace_index: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    def __str__(self):
        return 'ATP[{}](loc={}:{}, type={}, trace_idx={})'.format(
            self.id, self.loc.filename, self.loc.begin.line, AtpKind(self.type).name, self.trace_index
        )

    # #pragma db index("AttackPointUniq") unique members(loc, type, trace_index)
    # Updated to reflect your new uniqueness constraints
    __table_args__ = (
        UniqueConstraint(
            'loc_filename', 'loc_begin_line', 'loc_begin_column',
            'loc_end_line', 'loc_end_column', 'type', 'trace_index',
            name='AttackPointUniq'
        ),
    )

class SourceFunction(Base):
    __tablename__ = 'sourcefunction'

    # Matches: uint64 id = 1
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    # Matches: ASTLoc loc = 2
    # --- 1. Define the ACTUAL Database Columns ---
    # These hold the raw data. We prefix them with "loc_" to namespace them.
    _f: Mapped[str] = mapped_column("loc_filename", Text, nullable=False)
    _bl: Mapped[int] = mapped_column("loc_begin_line", Integer, nullable=False)
    _bc: Mapped[int] = mapped_column("loc_begin_column", Integer, nullable=False)
    _el: Mapped[int] = mapped_column("loc_end_line", Integer, nullable=False)
    _ec: Mapped[int] = mapped_column("loc_end_column", Integer, nullable=False)

    # --- 2. Define the Composite Bridge ---
    # This maps the 5 columns above into your ASTLoc class.
    loc: Mapped[ASTLoc] = composite(create_ast_loc, _f, _bl, _bc, _el, _ec)

    # Matches: string name = 3
    name: Mapped[str] = mapped_column(Text, nullable=False)

    def __repr__(self):
        return f"<SourceFunction(name='{self.name}', loc={self.loc})>"


class Call(Base):
    __tablename__ = 'call'

    # Matches: uint64 id = 1
    id: Mapped[int] = mapped_column('id', BigInteger, primary_key=True)

    # Matches: uint64 call_instr = 2
    call_instr: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Matches: uint64 ret_instr = 3
    ret_instr: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Matches: SourceFunction called_function = 4
    # We name the column 'called_function' to satisfy the Auditor's field check
    called_function: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey('sourcefunction.id')
    )

    # Matches: string callsite_file = 5
    callsite_file: Mapped[str] = mapped_column(Text, nullable=False)

    # Matches: uint32 callsite_line = 6
    callsite_line: Mapped[int] = mapped_column(Integer, nullable=False)

    # ORM Relationship (Internal use, ignored by Auditor if it looks for the column name)
    called_function_obj: Mapped["SourceFunction"] = relationship("SourceFunction")

    def __repr__(self):
        return f"<Call(id={self.id}, file='{self.callsite_file}', line={self.callsite_line})>"