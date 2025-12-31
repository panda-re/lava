set(GENERATED ${CMAKE_CURRENT_SOURCE_DIR}/../generated)
set(PYTHON_DATA ${CMAKE_CURRENT_SOURCE_DIR}/../../../python/src/pyroclastic/data)
set(PYTHON_TEST ${CMAKE_CURRENT_SOURCE_DIR}/../../../python/tests)

# Ensure folders exist
file(MAKE_DIRECTORY ${GENERATED})

# --- STEP 1: PROTOBUF GENERATION ---
set(PROTO_HXX "${GENERATED}/lava.pb.h")
set(PROTO_CXX "${GENERATED}/lava.pb.cc")
set(PROTO_PY  "${PYTHON_TEST}/lava_pb2.py")

add_custom_command(
    OUTPUT ${PROTO_HXX} ${PROTO_CXX} ${PROTO_PY}
    COMMAND protoc -I=${CMAKE_CURRENT_SOURCE_DIR}
                   --cpp_out=${GENERATED}
                   --python_out=${PYTHON_TEST}
                   ${CMAKE_CURRENT_SOURCE_DIR}/lava.proto
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/lava.proto
    COMMENT "Building Protobuf: lava.proto"
)

# --- STEP 2: ODB GENERATION ---
set(ODB_HXX_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../include/lava.hxx)
set(ODB_GENERATED_FILES
    "${GENERATED}/lava-odb.cxx"
    "${GENERATED}/lava-odb.hxx"
    "${GENERATED}/lava-odb.ixx"
    "${GENERATED}/lava.sql")

# Note the -I${GENERATED} so ODB can find lava.pb.h
set(ODB_OPTS -d pgsql -o ${GENERATED} --std c++14
             -I${GENERATED} -I${CMAKE_CURRENT_SOURCE_DIR}/../include
             --generate-query --generate-schema --generate-prepared
             --cxx-prologue '\#include \"pgarray.hxx\"' --sql-name-case lower)

# --- STEP 2.5: TELL CMAKE THESE FILES ARE PRODUCED DURING BUILD ---
set_source_files_properties(
    ${PROTO_CXX}
    ${PROTO_HXX}
    "${GENERATED}/lava-odb.cxx"
    "${GENERATED}/lava-odb.hxx"
    PROPERTIES GENERATED TRUE
)

add_custom_command(
    OUTPUT ${ODB_GENERATED_FILES}
    COMMAND odb ${ODB_OPTS} ${ODB_HXX_SRC}
    COMMAND ${CMAKE_COMMAND} -E copy "${GENERATED}/lava.sql" ${PYTHON_DATA}/lava.sql
    DEPENDS ${PROTO_HXX} ${ODB_HXX_SRC}
    COMMENT "Building ODB mappings from lava.hxx (depends on lava.pb.h)"
)

# --- STEP 3: THE TARGETS ---
# Library needs BOTH Protobuf source and ODB source
add_library(lava-odb_x64 STATIC ${PROTO_CXX} ${GENERATED}/lava-odb.cxx)

set_property(TARGET lava-odb_x64 PROPERTY CXX_STANDARD 17)
target_link_libraries(lava-odb_x64 odb odb-pgsql protobuf) # Added protobuf link

target_include_directories(lava-odb_x64
    PUBLIC
    $<BUILD_INTERFACE:${GENERATED}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
)