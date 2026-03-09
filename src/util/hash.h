#pragma once

#include "type/string.h"
#include "core/key_buffer.h"

#include <cstring>
#include <netinet/in.h>
#include <sodium.h>
#include <type_traits>

static inline unsigned long calculate(const unsigned char* element,
                                      unsigned long size) noexcept;

template <std::integral T>
inline unsigned long hash(T element);

template <typename T>
inline unsigned long hash(const T& element) noexcept;

template <>
inline unsigned long hash(const char* const& element) noexcept;

template <>
inline unsigned long hash(const sockaddr_in& element) noexcept;

template <>
inline unsigned long hash(const String& element) noexcept;

template <>
inline unsigned long hash(const KeyBuffer& element) noexcept;

static inline unsigned long calculate(const unsigned char* element,
                                      const unsigned long size) noexcept {
    /* The variable to store the hash (751 - random prime number) */
    unsigned long hash = 751;

    /* Evaluate the hash */
    const unsigned char* const element_end = element + size;
    do {
        const unsigned char byte = *element;
        hash = (hash << 5) - hash + byte;
    } while (++element < element_end);

    /* Return the result */
    return hash;
}

template <std::integral T>
inline unsigned long hash(T element) { return (unsigned long)element; }

template <typename T>
inline unsigned long hash(const T& element) noexcept {
    /* Get the byte array from the element and calc the hash */
    if constexpr (std::is_pointer_v<T>)
        return hash(*element);
    else if constexpr (!std::is_integral_v<T>)
        return calculate((const unsigned char*)(void*)&element,
                         sizeof(element));
    else return (unsigned long)element;
}

template <>
inline unsigned long hash(const char* const& element) noexcept {
    return calculate((const unsigned char*)element, strlen(element));
}

template <>
inline unsigned long hash(const sockaddr_in& element) noexcept {
    return element.sin_addr.s_addr + element.sin_port;
}

template <>
inline unsigned long hash(const String& element) noexcept {
    return ::hash((const char*)element);
}

template <>
inline unsigned long hash(const KeyBuffer& element) noexcept {
    return calculate(element.Get(), crypto_scalarmult_BYTES);
}
