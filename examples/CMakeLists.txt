cmake_policy(SET CMP0015 NEW)

include_directories(BEFORE ..)

# Define the executable
set(EXECUTABLE etchash_test)

# Add the source file
add_executable(${EXECUTABLE} etchash_test.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall -Wno-unknown-pragmas -Wextra -Wno-error=parentheses -pedantic")

# Add include directories
target_include_directories(${EXECUTABLE} PUBLIC ${CMAKE_SOURCE_DIR}/libethash)

# Link with the ethash library
target_link_libraries(${EXECUTABLE} PRIVATE ethash)

# Set up installation
include(GNUInstallDirs)
install(TARGETS ${EXECUTABLE} DESTINATION ${CMAKE_INSTALL_BINDIR})
