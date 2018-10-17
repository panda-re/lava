add_library (omg STATIC omg.cpp)
set_property(TARGET omg PROPERTY CXX_STANDARD 11)
set_target_properties(omg PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
target_include_directories(omg BEFORE
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )

add_executable(lavaTool lavaTool.cpp)
target_compile_options(lavaTool PRIVATE -fno-omit-frame-pointer -O2 -g -fexceptions -frtti)
set_target_properties(lavaTool PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
set_property(TARGET lavaTool PROPERTY CXX_STANDARD 14)
target_include_directories(lavaTool BEFORE
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaDB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/generated
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )

add_executable(lavaFnTool lavaFnTool.cpp)
target_compile_options(lavaFnTool PRIVATE -fno-omit-frame-pointer -O2 -g -fexceptions -frtti)
set_target_properties(lavaFnTool PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
set_property(TARGET lavaFnTool PROPERTY CXX_STANDARD 14)
target_include_directories(lavaFnTool BEFORE
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaDB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/generated
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lavaODB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )

add_dependencies(lavaTool lavaFnTool)

target_link_libraries(lavaTool lavaDB_x32 omg odb odb-pgsql lava-odb_x32 ${LLVM_CLANG_LINK_LIBRARIES})
target_link_libraries(lavaFnTool lavaDB_x32 omg odb odb-pgsql lava-odb_x32 ${LLVM_CLANG_LINK_LIBRARIES})

install (TARGETS lavaTool
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib
         ARCHIVE DESTINATION lib/static
         OPTIONAL)

install (TARGETS lavaFnTool
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib
         ARCHIVE DESTINATION lib/static
         OPTIONAL)



