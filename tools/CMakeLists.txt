cmake_minimum_required(VERSION 3.15)

set (CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "Configs" FORCE)

set(CMAKE_VERBOSE_MAKEFILE OFF)


# Read version number from command line argument
if(DEFINED LAVA_VERSION)
    string(REGEX MATCH "v?([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ ${LAVA_VERSION})
    set(CPACK_PACKAGE_VERSION_MAJOR ${CMAKE_MATCH_1})
    set(CPACK_PACKAGE_VERSION_MINOR ${CMAKE_MATCH_2})
    set(CPACK_PACKAGE_VERSION_PATCH ${CMAKE_MATCH_3})
    set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1})
    set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2})
    set(PROJECT_VERSION_PATCH ${CMAKE_MATCH_3})
else()
    set(CPACK_PACKAGE_VERSION_MAJOR "0")
    set(CPACK_PACKAGE_VERSION_MINOR "0")
    set(CPACK_PACKAGE_VERSION_PATCH "0")
    set(PROJECT_VERSION_MAJOR "0")
    set(PROJECT_VERSION_MINOR "0")
    set(PROJECT_VERSION_PATCH "0")
endif()

# Set default LLVM version, allow override via -DLLVM_VERSION=xx
set(LLVM_VERSION 14 CACHE STRING "LLVM version to use (default: 14)")

# Allow user to specify LLVM_DIR, otherwise construct it from LLVM_VERSION
if(NOT DEFINED LLVM_DIR)
    set(LLVM_DIR "/usr/lib/llvm-${LLVM_VERSION}")
endif()

# Set the project version dynamically
project(LAVA VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH})
include(GNUInstallDirs)
if (DEFINED DEBUG)
    set(CMAKE_VERBOSE_MAKEFILE ON)
else()
    set(CMAKE_VERBOSE_MAKEFILE OFF)
endif()

# Print the project version for debugging
message(STATUS "LAVA Project version: ${PROJECT_VERSION}")

# Install the headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h")

# Install the license file
install(FILES "../LICENSE"
        DESTINATION "${CMAKE_INSTALL_DOCDIR}"
        RENAME "copyright")

add_subdirectory(btrace)
add_subdirectory(lavaODB)
add_subdirectory(lavaDB)
add_subdirectory(lavaTool)
add_subdirectory(fbi)

include(CPackConfig.txt)