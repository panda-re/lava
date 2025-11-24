from sqlalchemy import Column
from sqlalchemy.types import TypeEngine
from sqlalchemy.orm import composite


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
