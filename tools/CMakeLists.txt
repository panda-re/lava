cmake_minimum_required (VERSION 3.1)
project (Lava)

set (Lava_VERSION_MAJOR 1)
set (Lava_VERSION_MINOR 0)

set (LLVM_LINK_COMPONENTS support)
set (CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "Configs" FORCE)

set (CLANG_LIBS
    clangARCMigrate
    clangAST
    clangASTMatchers
    clangAnalysis
    clangApplyReplacements
    clangBasic
    clangCodeGen
    clangDriver
    clangDynamicASTMatchers
    clangEdit
    clangFormat
    clangFrontend
    clangFrontendTool
    clangIndex
    clangLex
    clangParse
    clangQuery
    clangRename
    clangRewrite
    clangRewriteFrontend
    clangSema
    clangSerialization
    clangStaticAnalyzerCheckers
    clangStaticAnalyzerCore
    clangStaticAnalyzerFrontend
    clangTidy
    clangTidyGoogleModule
    clangTidyLLVMModule
    clangTidyMiscModule
    clangTidyReadabilityModule
    clangTidyUtils
    clangToolingCore
    clangTooling
 )
set (LLVM_LIBS
    LLVMLTO
    LLVMObjCARCOpts
    LLVMLinker
    LLVMipo
    LLVMVectorize
    LLVMBitWriter
    LLVMTableGen
    LLVMDebugInfo
    LLVMOption
    LLVMX86Disassembler
    LLVMX86AsmParser
    LLVMX86CodeGen
    LLVMSelectionDAG
    LLVMAsmPrinter
    LLVMX86Desc
    LLVMMCDisassembler
    LLVMX86Info
    LLVMX86AsmPrinter
    LLVMX86Utils
    LLVMMCJIT
    LLVMIRReader
    LLVMAsmParser
    LLVMLineEditor
    LLVMInstrumentation
    LLVMInterpreter
    LLVMExecutionEngine
    LLVMRuntimeDyld
    LLVMCodeGen
    LLVMScalarOpts
    LLVMProfileData
    LLVMObject
    LLVMMCParser
    LLVMBitReader
    LLVMInstCombine
    LLVMTransformUtils
    LLVMipa
    LLVMAnalysis
    LLVMTarget
    LLVMMC
    LLVMCore
    LLVMSupport
)
find_package(LLVM CONFIG)

set (LLVM_CLANG_LINK_LIBRARIES
    ${CLANG_LIBS}
    ${LLVM_LIBS}
)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

set(CMAKE_VERBOSE_MAKEFILE OFF)

include_directories(${LLVM_INCLUDE_DIRS})

if(LLVM_BUILD_MAIN_SRC_DIR)
    include_directories(${LLVM_BUILD_MAIN_SRC_DIR}/tools/clang/include)
    include_directories(${LLVM_BUILD_BINARY_DIR}/tools/clang/include)
endif()

link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_subdirectory(lavaODB)
add_subdirectory(lavaDB)
add_subdirectory(lavaTool)
add_subdirectory(fbi)

