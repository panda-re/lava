import lava_pb2
from pyroclastic.utils.database_types import Base
import sys


def verify_all_tables():
    mismatches = []
    # Loop through every SQLAlchemy table you've defined
    for table_name, mapper in Base.registry.mappers.items():
        class_name = mapper.class_.__name__

        # Look for the matching message in the Protobuf file
        proto_msg = getattr(lava_pb2, class_name, None)
        if not proto_msg:
            # Maybe some tables are internal to Python, but usually they should match
            print(f"Warning: No Protobuf definition for table {class_name}")
            continue

        sql_columns = set(mapper.columns.keys())
        proto_fields = set(proto_msg.DESCRIPTOR.fields_by_name.keys())

        # Check for drift
        missing_in_sql = proto_fields - sql_columns
        if missing_in_sql:
            mismatches.append(f"Table '{class_name}' is missing columns defined in .proto: {missing_in_sql}")

    if mismatches:
        for m in mismatches: print(f"ERROR: {m}")
        sys.exit(1)  # Fail the CI build
    print("Schema synchronized perfectly.")


if __name__ == "__main__":
    verify_all_tables()