cmake_minimum_required (VERSION 3.1)
project (Lava)

set (CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "Configs" FORCE)

set(CMAKE_VERBOSE_MAKEFILE OFF)

add_subdirectory(lavaODB)
add_subdirectory(lavaDB)
add_subdirectory(lavaTool)
add_subdirectory(fbi)

