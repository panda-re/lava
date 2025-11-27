cmake_minimum_required(VERSION 3.15)
project(lavaTool LANGUAGES CXX)
include(GNUInstallDirs)

# Set C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# LavaTool needs LLVM/Clang
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm")
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/clang")
find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

# Print the include directories for debugging
message(STATUS "LLVM include dirs: ${LLVM_INCLUDE_DIRS}")
message(STATUS "Clang include dirs: ${CLANG_INCLUDE_DIRS}")

# Add LLVM and Clang include directories
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
include_directories(/usr/include/jsoncpp)
link_directories(${LLVM_LIBRARY_DIRS})

# Define LLVM and Clang libraries
set(LLVM_CLANG_LINK_LIBRARIES
    clangAST
    clangASTMatchers
    clangBasic
    clangFrontend
    clangLex
    clangToolingCore
    clangTooling
)

include_directories(${PROJECT_SOURCE_DIR}/../include)
include_directories(${CMAKE_SOURCE_DIR}/include)

message(STATUS "PROJECT_SOURCE_DIR: ${PROJECT_SOURCE_DIR}")
message(STATUS "CMAKE_SOURCE_DIR: ${CMAKE_SOURCE_DIR}")
message(STATUS "LLVM_CLANG_LINK_LIBRARIES: ${LLVM_CLANG_LINK_LIBRARIES}")

# Create lavaTool executable
add_executable(lavaTool lavaTool.cpp)
target_compile_features(lavaTool PRIVATE cxx_std_17)
target_include_directories(lavaTool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaDB/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/generated
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
)
target_link_libraries(lavaTool PRIVATE lavaDB_x64 odb odb-pgsql lava-odb_x64 ${LLVM_CLANG_LINK_LIBRARIES})
set_target_properties(lavaTool PROPERTIES LINK_FLAGS "-flto -fuse-ld=gold")

# Create lavaFnTool executable
add_executable(lavaFnTool lavaFnTool.cpp)
target_compile_features(lavaFnTool PRIVATE cxx_std_17)
target_include_directories(lavaFnTool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaDB/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/generated
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
)
target_link_libraries(lavaFnTool PRIVATE lavaDB_x64 odb odb-pgsql lava-odb_x64 ${LLVM_CLANG_LINK_LIBRARIES})
set_target_properties(lavaFnTool PROPERTIES LINK_FLAGS "-flto -fuse-ld=gold")

# Create lavaInitTool executable
add_executable(lavaInitTool lavaInitTool.cpp)
target_compile_features(lavaInitTool PRIVATE cxx_std_17)
target_include_directories(lavaInitTool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
)
target_link_libraries(lavaInitTool PRIVATE ${LLVM_CLANG_LINK_LIBRARIES})
set_target_properties(lavaInitTool PROPERTIES LINK_FLAGS "-flto -fuse-ld=gold")

# Add dependencies
add_dependencies(lavaTool lavaFnTool)

# Install targets
install(TARGETS lavaTool lavaFnTool lavaInitTool
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}         # For shared libraries
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}         # For executables (if applicable)
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}         # For static libraries (if applicable)
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}    # For header files (if applicable)
)
