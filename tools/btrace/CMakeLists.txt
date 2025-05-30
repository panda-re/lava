# Define the project
project(sw_btrace C)

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

# Define the output directory for the library
set(LIBEXEC_DIR "${CMAKE_SOURCE_DIR}/libexec")

# Add a custom command to copy the library to the libexec directory
add_custom_command(
    TARGET sw_btrace POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${LIBEXEC_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:sw_btrace> ${LIBEXEC_DIR}
    COMMENT "Moving libsw-btrace.so to ${LIBEXEC_DIR}"
)