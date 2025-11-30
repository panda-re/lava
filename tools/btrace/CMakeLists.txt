# Define the project
project(sw_btrace C)
include(GNUInstallDirs)

# --- 1. FIND THE PACKAGE ---
# This looks for the CMake config files installed by libcjson-dev.
# It ensures the library exists before trying to compile.
find_package(cJSON REQUIRED)

# Set the C standard to C99
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add compiler definitions and flags
add_definitions(-D_POSIX_SOURCE -D_GNU_SOURCE)
set(CMAKE_POSITION_INDEPENDENT_CODE ON) # Equivalent to -fPIC

# Specify the source files
set(SOURCES
    btrace.c
    btrace_linux.c
)

# Create the shared library
add_library(sw_btrace SHARED ${SOURCES})
set_target_properties(sw_btrace PROPERTIES OUTPUT_NAME "sw-btrace")

# --- 2. LINK THE LIBRARY ---
if(CJSON_INCLUDE_DIRS)
    target_include_directories(sw_btrace PRIVATE ${CJSON_INCLUDE_DIRS})
    target_link_libraries(sw_btrace PRIVATE ${CJSON_LIBRARIES})
else()
    # Fallback if the variable is empty (rare, but happens on some old cmake versions)
    target_link_libraries(sw_btrace PRIVATE cjson)
endif()

# Install the shared library using GNUInstallDirs
install(TARGETS sw_btrace
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}  # For shared libraries
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}  # For executables (if applicable)
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}  # For static libraries (if applicable)
)