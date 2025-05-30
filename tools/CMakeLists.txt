cmake_minimum_required(VERSION 3.15)
project (LAVA VERSION 2.0.0)

set (CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "Configs" FORCE)

set(CMAKE_VERBOSE_MAKEFILE OFF)

CONFIGURE_FILE (
    "${PROJECT_SOURCE_DIR}/include/lava_version.h.in"
    "${PROJECT_SOURCE_DIR}/include/lava_version.h"
)

# Read version number from command line argument
if(DEFINED VERSION)
    string(REGEX MATCH "v?([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ ${VERSION})
    set(CPACK_PACKAGE_VERSION_MAJOR ${CMAKE_MATCH_1})
    set(CPACK_PACKAGE_VERSION_MINOR ${CMAKE_MATCH_2})
    set(CPACK_PACKAGE_VERSION_PATCH ${CMAKE_MATCH_3})
else()
    set(CPACK_PACKAGE_VERSION_MAJOR "0")
    set(CPACK_PACKAGE_VERSION_MINOR "0")
    set(CPACK_PACKAGE_VERSION_PATCH "0")
endif()

add_subdirectory(btrace)
add_subdirectory(lavaODB)
add_subdirectory(lavaDB)
add_subdirectory(lavaTool)
add_subdirectory(fbi)

include(CPackConfig.txt)