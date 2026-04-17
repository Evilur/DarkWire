CMAKE_MINIMUM_REQUIRED(VERSION 4.2)
SET(CMAKE_CXX_STANDARD 20)
PROJECT(DarkWire VERSION 1.0.0)

# Set compile options
IF (CMAKE_BUILD_TYPE STREQUAL "Debug")
    SET(CMAKE_CXX_FLAGS "-g3 -O0 \
        -fdiagnostics-color=always \
        -fsanitize=address \
        -fno-omit-frame-pointer")
    SET(CMAKE_CXX_SCAN_FOR_MODULES OFF)
    SET(CMAKE_EXPORT_COMPILE_COMMANDS ON)
ELSE ()
    SET(CMAKE_CXX_FLAGS "-g0 -O3 -static \
        -march=native -mtune=native \
        -fomit-frame-pointer -Winline \
        -fdiagnostics-color=always \
        -finline-functions \
        -finline-limit=99999999999999 \
        -finline-small-functions \
        --inline-limit=99999999999999 \
        --param large-stack-frame=2147483647 \
        --param large-stack-frame-growth=2147483647 \
        --param max-inline-insns-single=2147483647 \
        --param max-inline-insns-auto=2147483647 \
        -flto=128")
ENDIF ()

# Search header files in the 'src' directory
INCLUDE_DIRECTORIES(src)

# Set metadata
IF(WIN32)
    SET(APP_COMPANY   "Evilur")
    SET(APP_DESC      "Build the Peer2Peer virtual private network (VPN) "
                      "for fast data transfering between the peers")
    SET(APP_NAME      "DarkWire")
    SET(EXE_NAME      "dw.exe")
    SET(APP_COPYRIGHT "Copyright (C) 2026 Evilur (Andrew Shershunov) <the.evilur@gmail.com>")
    CONFIGURE_FILE(
        ${CMAKE_CURRENT_SOURCE_DIR}/meta.rc
        ${CMAKE_CURRENT_BINARY_DIR}/meta.rc
        @ONLY
    )
ENDIF()


# Build the app and link libraries
IF(WIN32)
    ADD_EXECUTABLE(dw src/main.cpp ${CMAKE_CURRENT_BINARY_DIR}/meta.rc)
    TARGET_LINK_LIBRARIES(dw PRIVATE sodium ws2_32)
ELSE()
    ADD_EXECUTABLE(dw src/main.cpp)
    TARGET_LINK_LIBRARIES(dw PRIVATE sodium)
ENDIF()
