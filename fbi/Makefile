include panda.mak

VPATH=.:../src_clang:$(PANDA_SRC_PATH)/panda/src:$(PANDA_BUILD_DIR)/i386-softmmu

CXX ?= clang++
CC ?= clang

LDFLAGS= -L/usr/local/lib -lprotobuf-c -lz -lpq -ljsoncpp -lodb-pgsql -lodb
CFLAGS= -I$(PANDA_SRC_PATH)/panda/include \
		-I$(PANDA_BUILD_DIR)/i386-softmmu \
		-I../include \
		-D PLOG_READER -O2 -g \
		-I/usr/include/jsoncpp -D LAVA -D PANDA_LAVA \
		-I/usr/lib/odb/x86_64-linux-gnu/include
CXXFLAGS=$(CFLAGS) -std=c++14

all: fbi

%.o: %.cpp Makefile
	$(CXX) -c -o $@ $< $(CXXFLAGS)

%.o: %.cxx Makefile
	$(CXX) -c -o $@ $< $(CXXFLAGS)

%.o: %.c Makefile
	$(CC) -c -o $@ $< $(CFLAGS)

fbi_sources=find_bug_inj.cpp lavaDB.cpp plog.c plog.pb-c.c lava-odb.cxx

%-odb.cxx %-odb.hxx: ../include/%.hxx Makefile
	LD_LIBRARY_PATH=/usr/local/lib odb -d pgsql --std c++11 -o . \
	--generate-query --generate-schema --generate-prepared \
	--cxx-prologue '#include "../include/pgarray.hxx"' \
	--sql-name-case lower $<

find_bug_inj.o: lava-odb.hxx ../include/lava.hxx

fbi_objs=$(addsuffix .o,$(basename $(fbi_sources)))

fbi: $(fbi_objs)
	$(CXX) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(fbi_objs) fbi
	rm -f ../include/lava-odb.*xx
