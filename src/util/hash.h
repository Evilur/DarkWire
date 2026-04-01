#pragma once

#include "type/string.h"
#include "core/key_buffer.h"
#include "socket/udp_socket.h"
#include "util/macro.h"

#include <cstring>
#include <sodium.h>
#include <type_traits>

static FORCE_INLINE uint64_t calculate(const uint8_t* element,
                                      uint64_t size) noexcept;

template <std::integral T>
FORCE_INLINE uint64_t hash(T element);

template <typename T>
FORCE_INLINE uint64_t hash(const T& element) noexcept;

template <>
FORCE_INLINE uint64_t hash(const char* const& element) noexcept;

template <>
FORCE_INLINE uint64_t hash(const sockaddr_in& element) noexcept;

template <>
FORCE_INLINE uint64_t hash(const String& element) noexcept;

template <>
FORCE_INLINE uint64_t hash(const KeyBuffer& element) noexcept;

static uint64_t calculate(const uint8_t* element,
                                      const uint64_t size) noexcept {
    /* The variable to store the hash (751 - random prime number) */
    uint64_t hash = 751;

    /* Evaluate the hash */
    const uint8_t* const element_end = element + size;
    do {
        const uint8_t byte = *element;
        hash = (hash << 5) - hash + byte;
    } while (++element < element_end);

    /* Return the result */
    return hash;
}

template <std::integral T>
FORCE_INLINE uint64_t hash(const T element)
{ return (uint64_t)element; }

template <typename T>
FORCE_INLINE uint64_t hash(const T& element) noexcept {
    /* Get the byte array from the element and calc the hash */
    if constexpr (std::is_pointer_v<T>)
        return hash(*element);
    else if constexpr (!std::is_integral_v<T>)
        return calculate((const uint8_t*)(void*)&element,
                         sizeof(element));
    else return (uint64_t)element;
}

template <>
FORCE_INLINE uint64_t hash(const char* const& element) noexcept {
    return calculate((const uint8_t*)element, strlen(element));
}

template <>
FORCE_INLINE uint64_t hash(const sockaddr_in& element) noexcept {
    return element.sin_addr.s_addr + element.sin_port;
}

template <>
FORCE_INLINE uint64_t hash(const String& element) noexcept {
    return ::hash(element.CStr());
}

template <>
FORCE_INLINE uint64_t hash(const KeyBuffer& element) noexcept {
    return calculate(element.Get(), crypto_scalarmult_BYTES);
}
