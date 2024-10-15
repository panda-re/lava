set (GENERATED ${CMAKE_CURRENT_SOURCE_DIR}/../generated)

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
    DEPENDS cleanup
)

add_custom_target (cleanup
    rm -rf ${GENERATED}/* #&& sleep 2
    COMMENT "Cleaning up tools/lavaODB/generated folder"
)

#add_library(lava-odb_x32 STATIC ${GENERATED}/lava-odb.cxx)
#set_property(TARGET lava-odb_x32 PROPERTY CXX_STANDARD 11)
#target_compile_options(lava-odb_x32 PRIVATE -D_GLIBCXX_USE_CXX11_ABI=0)
#set_target_properties(lava-odb_x32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
#target_link_libraries(lava-odb_x32 odb odb-pgsql)
#add_dependencies(lava-odb_x32 cleanup)
#target_include_directories(lava-odb_x32 BEFORE
#    PUBLIC
#    ${GENERATED}
#    ${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_library(lava-odb_x64 STATIC ${GENERATED}/lava-odb.cxx)
set_property(TARGET lava-odb_x64 PROPERTY CXX_STANDARD 17)
target_link_libraries(lava-odb_x64 odb odb-pgsql)
add_dependencies(lava-odb_x64 cleanup)
target_include_directories(lava-odb_x64 BEFORE
    PUBLIC
    ${GENERATED}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include)
