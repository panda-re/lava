# Author: Eli Bendersky (eliben@gmail.com)
# Revised by Ruoxin(Amy) Jiang
#-------------------------------------------------------------------------------

ifneq ($(wildcard config.mak),)
    include config.mak
else
    $(info )
    $(info Error: config.mak not found.  Create one with your LLVM build info.)
    $(info Example:)
    $(info )
    $(info LLVM_SRC_PATH := /home/llvm/llvm-3.6-svn/llvm/)
    $(info LLVM_BUILD_PATH := /home/llvm/llvm-3.6-svn/llvm/)
    $(info LLVM_BIN_PATH := $$(LLVM_BUILD_PATH)/Release+Asserts/bin/)
    $(info )
    $(error Exiting...)
endif

# Run make BUILD_NINJA=1 to enable these paths
ifdef BUILD_NINJA
	LLVM_BUILD_PATH := $$HOME/llvm/build/svn-ninja-release
	LLVM_BIN_PATH 	:= $(LLVM_BUILD_PATH)/bin
endif

$(info -----------------------------------------------)
$(info Using LLVM_SRC_PATH = $(LLVM_SRC_PATH))
$(info Using LLVM_BUILD_PATH = $(LLVM_BUILD_PATH))
$(info Using LLVM_BIN_PATH = $(LLVM_BIN_PATH))
$(info -----------------------------------------------)


#CXX := g++
#CXXFLAGS := -fexceptions -fno-rtti -O0 -g -std=c++11 -I/usr/include/jsoncpp
CXX := g++
CXXFLAGS := -fexceptions -O0 -g -std=c++11 -I/usr/include/jsoncpp -fno-omit-frame-pointer

PLUGIN_CXXFLAGS := -fpic -fexceptions

LLVM_CXXFLAGS := $(filter-out -fno-exceptions,$(shell $(LLVM_BIN_PATH)/llvm-config --cxxflags))
LLVM_LDFLAGS := $(shell $(LLVM_BIN_PATH)/llvm-config --ldflags --libs --system-libs)

LLVM_LDFLAGS_NOLIBS := $(shell $(LLVM_BIN_PATH)/llvm-config --ldflags)

OTHER_LIBS := -lpq -ljsoncpp -lodb -lodb-pgsql -L/usr/local/lib

CLANG_INCLUDES := \
	-I$(LLVM_SRC_PATH)/tools/clang/include \
	-I$(LLVM_BUILD_PATH)/tools/clang/include

CLANG_LIBS := -Wl,--start-group \
	-lclangAST \
	-lclangAnalysis \
	-lclangBasic \
	-lclangDriver \
	-lclangEdit \
	-lclangFrontend \
	-lclangFrontendTool \
	-lclangLex \
	-lclangParse \
	-lclangSema \
	-lclangEdit \
	-lclangASTMatchers \
	-lclangRewrite \
	-lclangRewriteFrontend \
	-lclangStaticAnalyzerFrontend \
	-lclangStaticAnalyzerCheckers \
	-lclangStaticAnalyzerCore \
	-lclangSerialization \
	-lclangToolingCore \
	-lclangTooling \
	-Wl,--end-group

BUILDDIR := build

.PHONY: all
all: make_builddir \
	emit_build_config \
	$(BUILDDIR)/lavaTool\

.PHONY: emit_build_config
emit_build_config: make_builddir
	@echo $(LLVM_BIN_PATH) > $(BUILDDIR)/_build_config

.PHONY: make_builddir
make_builddir:
	@test -d $(BUILDDIR) || mkdir $(BUILDDIR)

%.o: %.cpp
	$(CXX) -c -o $@ $< $(LLVM_CXXFLAGS) $(CLANG_INCLUDES) $(CXXFLAGS)

%.o: %.cxx
	$(CXX) -c -o $@ $< $(LLVM_CXXFLAGS) $(CLANG_INCLUDES) $(CXXFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

includes.h.gch: includes.h
	$(CXX) -c -o $@ $(CXXFLAGS) $(LLVM_CXXFLAGS) $(CLANG_INCLUDES) $^

$(BUILDDIR)/lavaTool: lavaTool.o lavaDB.o ../include/lava-odb.o
	$(CXX) -o $@ $^ $(CLANG_LIBS) $(LLVM_LDFLAGS) $(OTHER_LIBS)

../include/lava-odb.cxx: ../include/lava.hxx
	LD_LIBRARY_PATH=/usr/local/lib odb -d pgsql --std c++11 -o ../include \
	--generate-query --generate-schema --cxx-prologue '#include "../include/pgarray.hxx"' \
	--sql-name-case lower $<

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)/* *~ *.o ../include/lava-odb.o

