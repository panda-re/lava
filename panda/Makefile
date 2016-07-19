LDFLAGS= -L/usr/local/lib -lprotobuf-c -lz -lpq -ljsoncpp -lodb-pgsql -lodb
CFLAGS= -I ../../panda/qemu -I ../../panda/qemu/panda \
		  -D PANDALOG_READER -O2 -g \
		  -I/usr/include/jsoncpp -D LAVA -D PANDA_LAVA \
		  -I/usr/lib/odb/x86_64-linux-gnu/include
CXXFLAGS=$(CFLAGS) -std=c++14

all: fbi

%.o: %.cpp
	g++ -c -o $@ $< $(CXXFLAGS)

%.o: %.cxx
	g++ -c -o $@ $< $(CXXFLAGS)

%.o: %.c
	gcc -c -o $@ $< $(CFLAGS)

fbi_sources=find_bug_inj.cpp \
			../sql/lava_sql.cpp \
			../src_clang/lavaDB.cpp \
			../../panda/qemu/panda/pandalog.c \
			../../panda/qemu/panda/pandalog.pb-c.c \
			../include/lava-odb.cxx

../include/lava-odb.cxx: ../include/lava.hxx
	odb -d pgsql --std c++11 -o ../include $<

fbi_objs=$(addsuffix .o,$(basename $(fbi_sources)))

fbi: $(fbi_objs)
	g++ -o $@ $^ $(LDFLAGS)

clean:
	rm $(fbi_objs) fbi
