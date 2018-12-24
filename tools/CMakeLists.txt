cmake_minimum_required (VERSION 3.1)
project (LAVA VERSION 2.0.0)

set (CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "Configs" FORCE)

set(CMAKE_VERBOSE_MAKEFILE OFF)

CONFIGURE_FILE (
    "${PROJECT_SOURCE_DIR}/include/lava_version.h.in"
    "${PROJECT_SOURCE_DIR}/include/lava_version.h"
    )

add_subdirectory(lavaODB)
add_subdirectory(lavaDB)
add_subdirectory(lavaTool)
add_subdirectory(fbi)

