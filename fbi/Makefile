include panda.mak

#DEBUG := true

VPATH=.:$(PANDA_SRC_PATH)/panda/src:$(PANDA_BUILD_DIR)/i386-softmmu:../common

CXX ?= clang++
CC ?= clang

PKGS=libodb libodb-pgsql jsoncpp

LDFLAGS= -L/usr/local/lib -lprotobuf-c -lz -lpq -ljsoncpp -lodb-pgsql -lodb -L/usr/lib -ggdb
CFLAGS= -I$(PANDA_SRC_PATH)/panda/include \
		-I$(PANDA_BUILD_DIR)/i386-softmmu \
		-I/usr/lib/odb/x86_64-linux-gnu/include \
		-I../include -D PLOG_READER
CFLAGS+= $(shell pkg-config $(PKGS) --cflags)

ifdef DEBUG
	CFLAGS += -O0 -g -fno-omit-frame-pointer
else
	CFLAGS += -flto -O3
	LDFLAGS += -flto -fuse-ld=gold
endif

CXXFLAGS=$(CFLAGS) -std=c++14

all: fbi

%.o: %.cpp Makefile
	$(CXX) -c -o $@ $< $(CXXFLAGS)

%.o: %.cxx Makefile
	$(CXX) -c -o $@ $< $(CXXFLAGS)

%.o: %.c Makefile
	$(CC) -c -o $@ $< $(CFLAGS)

fbi_sources=find_bug_inj.cpp lavaDB.cpp plog.c plog-cc.cpp plog.pb-c.c plog.pb.h plog.pb.cc lava-odb.cxx

%-odb.cxx %-odb.hxx: ../include/%.hxx Makefile
	LD_LIBRARY_PATH=/usr/local/lib odb -d pgsql --std c++11 -o . \
	--generate-query --generate-schema --generate-prepared \
	--cxx-prologue '#include "../include/pgarray.hxx"' \
	--sql-name-case lower $<

find_bug_inj.o: lava-odb.hxx ../include/lava.hxx

fbi_objs=$(addsuffix .o,$(basename $(fbi_sources)))

fbi: $(fbi_objs)
	$(CXX) -o $@ $^ $(LDFLAGS) -flto -fuse-ld=gold -lprotobuf

clean:
	rm -f $(fbi_objs) fbi
	rm -f ../include/lava-odb.*xx
