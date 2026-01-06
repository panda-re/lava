import unittest
import inspect
import lava_pb2
from pyroclastic.utils import database_types
from pyroclastic.utils.database_types import Base


class TestSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Build the maps once for all test methods in this class."""
        # This will reveal if your new tables are registered correctly
        cls.sql_mappers = {m.class_.__name__: m for m in Base.registry.mappers}
        cls.all_classes = dict(inspect.getmembers(database_types, inspect.isclass))

        print("\n" + "=" * 50)
        print("DEBUG: LAVA SCHEMA AUDITOR (unittest)")
        print(f"Total Mappers: {len(cls.sql_mappers)}")
        print(f"Mappers: {list(cls.sql_mappers.keys())}")
        print("=" * 50)

    def get_python_fields(self, cls_name):
        """
        Helper to extract field names from either a Mapper or a Composite/Dataclass
        """
        if cls_name in self.sql_mappers:
            mapper = self.sql_mappers[cls_name]
            # Columns + Relationships + Association Proxies
            return (set(mapper.all_orm_descriptors.keys()) |
                    set(mapper.columns.keys()) |
                    set(mapper.synonyms.keys()))
        elif cls_name in self.all_classes:
            target_cls = self.all_classes[cls_name]
            return set(getattr(target_cls, '__annotations__', {}).keys()) | set(target_cls.__dict__.keys())
        return set()

    def test_protobuf_coverage(self):
        """Ensure every Proto message has a corresponding Python class or table."""
        proto_messages = set(lava_pb2.DESCRIPTOR.message_types_by_name.keys())
        python_types = set(self.sql_mappers.keys()) | set(self.all_classes.keys())

        missing = proto_messages - python_types
        self.assertEqual(len(missing), 0, f"Protobuf defines messages missing in Python: {missing}")

    def test_field_synchronization(self):
        """Ensure every field in every Proto message exists in Python."""
        mismatches = []

        for msg_name, msg_descriptor in lava_pb2.DESCRIPTOR.message_types_by_name.items():
            # If the class itself is missing, test_protobuf_coverage will catch it.
            # We skip field checks for missing classes to avoid redundant errors.
            if msg_name not in self.sql_mappers and msg_name not in self.all_classes:
                continue

            proto_fields = set(msg_descriptor.fields_by_name.keys())
            py_fields = self.get_python_fields(msg_name)

            missing_in_python = proto_fields - py_fields
            if missing_in_python:
                mismatches.append(f"Type '{msg_name}' missing fields: {missing_in_python}")

        self.assertEqual(len(mismatches), 0, "\n" + "\n".join(mismatches))


if __name__ == "__main__":
    unittest.main()
