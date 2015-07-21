LDFLAGS= -L/usr/local/lib -lprotobuf-c -lz -lpq 
CXXFLAGS= -I ../../panda/qemu -I ../../panda/qemu/panda -D PANDALOG_READER  -std=c++11 -O2 -g

all: fbi

fbi: find_bug_inj.cpp \
    ../sql/lava_sql.cpp \
    ../src_clang/lavaDB.cpp \
    ../../panda/qemu/panda/pandalog.c \
    ../../panda/qemu/panda/pandalog.pb-c.c \
    ../../panda/qemu/panda/pandalog_print.c
	g++ -o $@ $^ $(LDFLAGS) $(CXXFLAGS)
