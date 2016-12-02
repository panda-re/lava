include panda.mak

LDFLAGS= -L/usr/local/lib -lprotobuf-c -lz -lpq -ljsoncpp -lodb-pgsql -lodb
CFLAGS= -I$(PANDA_SRC_PATH)/panda/include \
		-I$(PANDA_BUILD_DIR)/i386-softmmu \
		-D PLOG_READER -O2 -g \
		-I/usr/include/jsoncpp -D LAVA -D PANDA_LAVA \
		-I/usr/lib/odb/x86_64-linux-gnu/include
CXXFLAGS=$(CFLAGS) -std=c++14

all: fbi

%.o: %.cpp Makefile
	clang++ -c -o $@ $< $(CXXFLAGS)

%.o: %.cxx Makefile
	clang++ -c -o $@ $< $(CXXFLAGS)

%.o: %.c Makefile
	clang -c -o $@ $< $(CFLAGS)

fbi_sources=find_bug_inj.cpp \
			../src_clang/lavaDB.cpp \
			$(PANDA_SRC_PATH)/panda/src/plog.c \
			$(PANDA_BUILD_DIR)/i386-softmmu/plog.pb-c.c \
			../include/lava-odb.cxx

../include/lava-odb.cxx: ../include/lava.hxx
	LD_LIBRARY_PATH=/usr/local/lib odb -d pgsql --std c++11 -o ../include \
	--generate-query --generate-schema --cxx-prologue '#include "../include/pgarray.hxx"' \
	--sql-name-case lower $<

fbi_objs=$(addsuffix .o,$(basename $(fbi_sources)))

fbi: $(fbi_objs)
	clang++ -o $@ $^ $(LDFLAGS)

clean:
	rm $(fbi_objs) fbi
