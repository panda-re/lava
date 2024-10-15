cmake_minimum_required(VERSION 3.15)
project (FBI LANGUAGES CXX)

# fbi target
add_executable(fbi find_bug_inj.cpp)
set_property(TARGET fbi PROPERTY CXX_STANDARD 17)

#if (${DEBUG})
    target_compile_options(fbi PRIVATE -fno-omit-frame-pointer -g -O0)
#else()
#    target_compile_options(fbi PRIVATE -flto -O3)
#    set_target_properties(fbi PROPERTIES LINK_FLAGS "-flto -fuse-ld=gold")
#endif()

target_include_directories(fbi BEFORE
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaDB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/generated
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
        /usr/lib/odb/x86_64-linux-gnu/include
        /usr/local/include 
        /usr/include/jsoncpp
)

add_dependencies(fbi lava-odb_x64)
set_target_properties(fbi PROPERTIES LINK_FLAGS "-L/usr/local/lib")
target_link_libraries(fbi
    lavaDB_x64
    lava-odb_x64
    protobuf-c
    z
    odb
    odb-pgsql
    protobuf
    jsoncpp
)

install (TARGETS fbi
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib
         ARCHIVE DESTINATION lib/static
         OPTIONAL
         )