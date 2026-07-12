project (duasan LANGUAGES CXX)
include(GNUInstallDirs)
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

# Duasan needs LLVM/Clang
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm")
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/clang")
find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

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


add_executable(duasan duasan.cpp)
set_property(TARGET duasan PROPERTY CXX_STANDARD 17)
target_compile_options(duasan PRIVATE -fno-omit-frame-pointer -O3 -fexceptions -frtti)
set_target_properties(duasan PROPERTIES LINK_FLAGS "-flto -fuse-ld=gold")
target_include_directories(duasan BEFORE
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaDB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/generated
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    )

target_link_libraries(duasan lavaDB_x64 odb odb-pgsql lava-odb_x64 ${LLVM_CLANG_LINK_LIBRARIES})

install (TARGETS duasan
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}         # For shared libraries
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}         # For executables (if applicable)
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}         # For static libraries (if applicable)
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}    # For header files (if applicable)
)

