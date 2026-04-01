#pragma once

#include "socket/udp_socket.h"
#include "util/macro.h"

#include <cstring>

template <typename T>
FORCE_INLINE bool equal(const T& e1, const T& e2);

template <>
FORCE_INLINE bool equal(const char* const& e1, const char* const& e2);

template <>
FORCE_INLINE bool equal(const sockaddr_in& e1, const sockaddr_in& e2);

template <typename T>
FORCE_INLINE bool equal(const T& e1, const T& e2) { return e1 == e2; }

template <>
FORCE_INLINE bool equal(const char* const& e1, const char* const& e2) {
    return strcmp(e1, e2) == 0;
}

template <>
FORCE_INLINE bool equal(const sockaddr_in& e1, const sockaddr_in& e2) {
    return e1.sin_addr.s_addr == e2.sin_addr.s_addr
        && e1.sin_port == e2.sin_port;
}
