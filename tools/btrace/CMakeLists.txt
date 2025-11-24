# Define the project
project(sw_btrace C)
include(GNUInstallDirs)

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

# Install the shared library using GNUInstallDirs
install(TARGETS sw_btrace
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}  # For shared libraries
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}  # For executables (if applicable)
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}  # For static libraries (if applicable)
)