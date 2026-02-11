CMAKE_MINIMUM_REQUIRED(VERSION 4.2)
SET(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
PROJECT(DarkWire)

# Set compile options
IF (CMAKE_BUILD_TYPE STREQUAL "Debug")
    SET(CMAKE_CXX_FLAGS "-g3 -O0 -fdiagnostics-color=always")
    SET(CMAKE_EXPORT_COMPILE_COMMANDS ON)
ELSE ()
    SET(CMAKE_CXX_FLAGS "-g0 -O2 -static")
ENDIF ()

# Search header files in the 'src' directory
INCLUDE_DIRECTORIES(src)

# Build the client
FILE(GLOB_RECURSE SOURCES "src/*.cpp")
ADD_EXECUTABLE(dw ${SOURCES})

# Build unit tests
FILE(GLOB_RECURSE SOURCES "src/*.cpp" "test/*.cpp")
LIST(FILTER SOURCES EXCLUDE REGEX ".*/src/main\\.cpp$")
ADD_EXECUTABLE(tests ${SOURCES})

# Copy tests directory
ADD_CUSTOM_COMMAND(TARGET tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/test/units $<TARGET_FILE_DIR:dw>/test/units
)
