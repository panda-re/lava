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

CXX := g++
CXXFLAGS := -fno-rtti -O0 -g
PLUGIN_CXXFLAGS := -fpic

LLVM_CXXFLAGS := `$(LLVM_BIN_PATH)/llvm-config --cxxflags`
LLVM_LDFLAGS := `$(LLVM_BIN_PATH)/llvm-config --ldflags --libs --system-libs`

LLVM_LDFLAGS_NOLIBS := `$(LLVM_BIN_PATH)/llvm-config --ldflags`
PLUGIN_LDFLAGS := -shared

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
	$(BUILDDIR)/example \
	$(BUILDDIR)/lavaTaintQueryTool #\
#	$(BUILDDIR)/lavaTaintQueryPlugin.so

.PHONY: emit_build_config
emit_build_config: make_builddir
	@echo $(LLVM_BIN_PATH) > $(BUILDDIR)/_build_config

.PHONY: make_builddir
make_builddir:
	@test -d $(BUILDDIR) || mkdir $(BUILDDIR)

$(BUILDDIR)/example: example.cpp
	$(CXX) $(CXXFLAGS) $(LLVM_CXXFLAGS) $(CLANG_INCLUDES) $^ \
		$(CLANG_LIBS) $(LLVM_LDFLAGS) -o $@

$(BUILDDIR)/lavaTaintQueryTool: lavaTaintQueryTool.cpp lavaTaintQuery.h
	$(CXX) $(CXXFLAGS) $(LLVM_CXXFLAGS) $(CLANG_INCLUDES) $^ \
		$(CLANG_LIBS) $(LLVM_LDFLAGS) -o $@

#$(BUILDDIR)/lavaTaintQueryPlugin.so: lavaTaintQueryPlugin.cpp lavaTaintQuery.h
#	$(CXX) $(PLUGIN_CXXFLAGS) $(CXXFLAGS) $(LLVM_CXXFLAGS) $(CLANG_INCLUDES) \
#		$^ $(PLUGIN_LDFLAGS) $(LLVM_LDFLAGS_NOLIBS) -o $@

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)/* *~

