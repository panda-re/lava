#add_library (lavaDB_x32 STATIC lavaDB.cpp)
#set_property(TARGET lavaDB_x32 PROPERTY CXX_STANDARD 11)
#set_target_properties(lavaDB_x32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

add_library (lavaDB_x64 STATIC lavaDB.cpp)
set_property(TARGET lavaDB_x64 PROPERTY CXX_STANDARD 17)
