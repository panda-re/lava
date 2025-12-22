include(GNUInstallDirs)
set (GENERATED ${CMAKE_CURRENT_SOURCE_DIR}/../generated)
set (SCRIPTS ${CMAKE_CURRENT_SOURCE_DIR}/../../../scripts)

if (NOT EXISTS ${GENERATED})
    file(MAKE_DIRECTORY ${GENERATED})
endif()

set(cxxFile "${GENERATED}/lava-odb.cxx")
set(hxxFile "${GENERATED}/lava-odb.hxx")
set(ixxFile "${GENERATED}/lava-odb.ixx")
set(sqlFile "${GENERATED}/lava.sql")

set(ODB_GENERATED_FILES ${cxxFile} ${hxxFile} ${ixxFile} ${sqlFile})

set(ODB_OPTS -d pgsql -o ${GENERATED} --std c++11 --generate-query --generate-schema --generate-prepared --cxx-prologue '\#include \"pgarray.hxx\"' --sql-name-case lower )
set(ODB_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set(ODB_HXX ${CMAKE_CURRENT_SOURCE_DIR}/../include/lava.hxx)

add_custom_command (
    OUTPUT ${ODB_GENERATED_FILES}
    COMMAND odb ${ODB_OPTS} ${ODB_HXX}
    COMMAND ${CMAKE_COMMAND} -E copy ${sqlFile} ${SCRIPTS}/lava.sql
    DEPENDS cleanup ${ODB_HXX}
    COMMENT "Generating ODB files and syncing SQL to scripts folder"
)

add_custom_target (cleanup
    rm -rf ${GENERATED}/*
    COMMENT "Cleaning up tools/lavaODB/generated folder"
)

# create liblava-odb_x64.a library used by lavaFnTool and lavaTool
add_library(lava-odb_x64 STATIC ${GENERATED}/lava-odb.cxx)
set_property(TARGET lava-odb_x64 PROPERTY CXX_STANDARD 17)
target_link_libraries(lava-odb_x64 odb odb-pgsql)
add_dependencies(lava-odb_x64 cleanup)
target_include_directories(lava-odb_x64 BEFORE
    PUBLIC
    ${GENERATED}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include)

install(TARGETS lava-odb_x64
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}  # For shared libraries
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}  # For executables (if applicable)
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}  # For static libraries (if applicable)
)