CMAKE_MINIMUM_REQUIRED(VERSION 4.2)
SET(CMAKE_CXX_STANDARD 20)
SET(CMAKE_CXX_SCAN_FOR_MODULES OFF)
PROJECT(DarkWire)

# Set compile options
IF (CMAKE_BUILD_TYPE STREQUAL "Debug")
    SET(CMAKE_CXX_FLAGS "-g3 -O0 \
        -fdiagnostics-color=always \
        -fsanitize=address \
        -fno-omit-frame-pointer")
    SET(CMAKE_EXPORT_COMPILE_COMMANDS ON)
ELSE ()
    SET(CMAKE_CXX_FLAGS "-g0 -O2 -Winline -static \
        -fdiagnostics-color=always \
        -finline-functions \
        -finline-limit=99999999999999 \
        -finline-small-functions \
        --inline-limit=99999999999999 \
        --param large-stack-frame=2147483647 \
        --param large-stack-frame-growth=2147483647 \
        --param max-inline-insns-single=2147483647 \
        --param max-inline-insns-auto=2147483647 \
        -march=native \
        -flto=128")
ENDIF ()

# Search header files in the 'src' directory
INCLUDE_DIRECTORIES(src)

# Build the client
FILE(GLOB_RECURSE SOURCES "src/*.cpp")
ADD_EXECUTABLE(dw src/main.cpp)

# Build unit tests
FILE(GLOB_RECURSE SOURCES "test/*.cpp")
LIST(FILTER SOURCES EXCLUDE REGEX ".*/src/main\\.cpp$")

# Link libraries
IF(WIN32)
    TARGET_LINK_LIBRARIES(dw PRIVATE sodium ws2_32)
ELSE()
    TARGET_LINK_LIBRARIES(dw PRIVATE sodium)
ENDIF()
