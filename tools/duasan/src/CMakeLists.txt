project (duasan VERSION 2.0.0 LANGUAGES CXX)
# LLVM variables to compile our clang tool
set (LLVM_LINK_COMPONENTS support)

set (CLANG_LIBS
    clangAST
    clangASTMatchers
    clangBasic
    clangFrontend
    clangLex
    clangToolingCore
    clangTooling
 )

set (LLVM_LIBS
    LLVMSupport
)

if(DEFINED ENV{LLVM_DIR})
    find_package(LLVM CONFIG)
endif()

set (LLVM_CLANG_LINK_LIBRARIES
    ${CLANG_LIBS}
    ${LLVM_LIBS}
)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

if(LLVM_BUILD_MAIN_SRC_DIR)
    include_directories(${LLVM_BUILD_MAIN_SRC_DIR}/tools/clang/include)
    include_directories(${LLVM_BUILD_BINARY_DIR}/tools/clang/include)
endif()

link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})

include_directories(${LLVM_INCLUDE_DIRS})


# duasan target compiled against llvm, /*omg*/, odb odb-pgsql and lava odb
add_executable(duasan duasan.cpp)
target_compile_options(duasan PRIVATE -fno-omit-frame-pointer -O3 -fexceptions -frtti)
set_target_properties(duasan PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32 -flto -fuse-ld=gold")
set_property(TARGET duasan PROPERTY CXX_STANDARD 14)
target_include_directories(duasan BEFORE
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaDB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/generated
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    )


# omg is pre-built in lavaTool, just link if needed
#target_link_libraries(duasan lavaDB_x32 omg odb odb-pgsql lava-odb_x32 ${LLVM_CLANG_LINK_LIBRARIES})
target_link_libraries(duasan lavaDB_x32 odb odb-pgsql lava-odb_x32 ${LLVM_CLANG_LINK_LIBRARIES})

install (TARGETS duasan
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib
         ARCHIVE DESTINATION lib/static
         OPTIONAL
         )
