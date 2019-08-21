project (FBI LANGUAGES CXX)

# Panda src, headers and build locations
set (PANDA_SRC_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../../panda/src)
set (PANDA_BUILD_DIR ${PANDA_SRC_PATH}/../build)
set (PANDA_HEADERS ${PANDA_SRC_PATH}/panda/include)

# fbilib target
add_library (fbilib
            ${PANDA_SRC_PATH}/panda/src/plog.c
            ${PANDA_SRC_PATH}/panda/src/plog-cc.cpp
)
target_include_directories(fbilib BEFORE
        PUBLIC
        ${PANDA_SRC_PATH}/panda/include
        ${PANDA_BUILD_DIR}/i386-softmmu
        /usr/lib/odb/x86_64-linux-gnu/include
)
target_compile_options(fbilib PRIVATE -DPLOG_READER)
set_property(TARGET fbilib PROPERTY CXX_STANDARD 14)

# fbi target
add_executable(fbi find_bug_inj.cpp)
set_property(TARGET fbi PROPERTY CXX_STANDARD 14)

target_compile_options(fbi PRIVATE -D_GLIBCXX_USE_CXX11_ABI=0)
if (${DEBUG})
    target_compile_options(fbi PRIVATE -fno-omit-frame-pointer -g -O0)
else()
    target_compile_options(fbi PRIVATE -flto -O3)
    set_target_properties(fbi PROPERTIES LINK_FLAGS "-flto -fuse-ld=gold")
endif()

target_include_directories(fbi BEFORE
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaDB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/generated
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
        ${PANDA_SRC_PATH}/panda/include
        ${PANDA_BUILD_DIR}/i386-softmmu
        /usr/lib/odb/x86_64-linux-gnu/include
    )
add_dependencies(fbi lava-odb_x64)
set_target_properties(fbi PROPERTIES LINK_FLAGS "-L/usr/local/lib")
target_link_libraries(fbi
    fbilib
    lavaDB_x64
    lava-odb_x64
    protobuf-c
    z
    odb
    odb-pgsql
    jsoncppoldabi
    pq
    protobuf
    ${PANDA_BUILD_DIR}/i386-softmmu/plog.pb.o
    ${PANDA_BUILD_DIR}/i386-softmmu/plog.pb-c.o
)
install (TARGETS fbi
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib
         ARCHIVE DESTINATION lib/static
         OPTIONAL
         )
