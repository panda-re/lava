include panda.mak

CXX ?= clang++
CC ?= clang

LDFLAGS= -L/usr/local/lib -lprotobuf-c -lz -lpq -ljsoncpp -lodb-pgsql -lodb
CFLAGS= -I$(PANDA_SRC_PATH)/panda/include \
		-I$(PANDA_BUILD_DIR)/i386-softmmu \
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

find_bug_inj.o: ../include/lava-odb.cxx

fbi_sources=find_bug_inj.cpp \
			../src_clang/lavaDB.cpp \
			$(PANDA_SRC_PATH)/panda/src/plog.c \
			$(PANDA_BUILD_DIR)/i386-softmmu/plog.pb-c.c \
			../include/lava-odb.cxx

../include/%-odb.cxx ../include/%-odb.hxx: ../include/%.hxx Makefile
	LD_LIBRARY_PATH=/usr/local/lib odb -d pgsql --std c++11 -o ../include \
	--generate-query --generate-schema --generate-prepared \
	--cxx-prologue '#include "../include/pgarray.hxx"' \
	--sql-name-case lower $<

find_bug_inj.o: ../include/lava-odb.hxx ../include/lava.hxx

fbi_objs=$(addsuffix .o,$(basename $(fbi_sources)))

fbi: $(fbi_objs)
	$(CXX) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(fbi_objs) fbi
	rm -f ../include/lava-odb.*xx
