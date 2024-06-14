cmake_minimum_required(VERSION 3.15)
project(lavaTool VERSION 2.0.0 LANGUAGES CXX)

# Find LLVM and Clang
if(DEFINED ENV{LLVM_DIR})
    find_package(LLVM REQUIRED CONFIG)
    find_package(Clang REQUIRED CONFIG)
endif()

# Define LLVM and Clang libraries
set(LLVM_CLANG_LINK_LIBRARIES
    clangAST
    clangASTMatchers
    clangBasic
    clangFrontend
    clangLex
    clangToolingCore
    clangTooling
    LLVMSupport
)

# Add LLVM and Clang include directories
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})

# Create OMG static library
add_library(omg STATIC omg.cpp)
set_property(TARGET omg PROPERTY CXX_STANDARD 11)
target_compile_options(omg PRIVATE -D_GLIBCXX_USE_CXX11_ABI=0)
set_target_properties(omg PROPERTIES LINK_FLAGS "-flto -fuse-ld=gold")
target_include_directories(omg PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Create lavaTool executable
add_executable(lavaTool lavaTool.cpp)
target_compile_features(lavaTool PRIVATE cxx_std_14)
target_compile_options(lavaTool PRIVATE -D_GLIBCXX_USE_CXX11_ABI=0 -fno-omit-frame-pointer -O3 -fexceptions -frtti)
target_include_directories(lavaTool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaDB/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/generated
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)
target_link_libraries(lavaTool PRIVATE lavaDB_x64 omg odb odb-pgsql lava-odb_x64 ${LLVM_CLANG_LINK_LIBRARIES})
set_target_properties(lavaTool PROPERTIES LINK_FLAGS "-flto -fuse-ld=gold")

# Create lavaFnTool executable
add_executable(lavaFnTool lavaFnTool.cpp)
target_compile_features(lavaFnTool PRIVATE cxx_std_14)
target_compile_options(lavaFnTool PRIVATE -D_GLIBCXX_USE_CXX11_ABI=0 -fno-omit-frame-pointer -O3 -fexceptions -frtti)
target_include_directories(lavaFnTool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaDB/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/generated
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)
target_link_libraries(lavaFnTool PRIVATE lavaDB_x64 omg odb odb-pgsql lava-odb_x64 ${LLVM_CLANG_LINK_LIBRARIES})
set_target_properties(lavaFnTool PROPERTIES LINK_FLAGS "-flto -fuse-ld=gold")

# Create lavaInitTool executable
add_executable(lavaInitTool lavaInitTool.cpp)
target_compile_features(lavaInitTool PRIVATE cxx_std_14)
target_compile_options(lavaInitTool PRIVATE -D_GLIBCXX_USE_CXX11_ABI=0 -fno-omit-frame-pointer -O3 -fexceptions -frtti)
target_include_directories(lavaInitTool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)
target_link_libraries(lavaInitTool PRIVATE ${LLVM_CLANG_LINK_LIBRARIES})
set_target_properties(lavaInitTool PROPERTIES LINK_FLAGS "-flto -fuse-ld=gold")

# Add dependencies
add_dependencies(lavaTool lavaFnTool)

# Install targets
install(TARGETS lavaTool
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/static
)
install(TARGETS lavaFnTool
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/static
)
install(TARGETS lavaInitTool
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/static
)
