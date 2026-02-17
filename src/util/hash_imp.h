#pragma once

#include "hash.h"

#include <cstring>
#include <type_traits>

static inline unsigned long calculate(const unsigned char* element,
                                      const unsigned short size) noexcept {
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

template <typename T>
inline unsigned long hash(const T& element) noexcept {
    /* Get the byte array from the element and calc the hash */
    if constexpr (std::is_pointer_v<T>)
        return hash(*element);
    else
        return calculate((const unsigned char*)(void*)&element,
                         sizeof(element));
}

template <>
inline unsigned long hash(const char* const& element) noexcept {
    return calculate((const unsigned char*)(void*)element,
                     strlen(element) + 1);
}

template <>
inline unsigned long hash(char* const& element) noexcept {
    return calculate((const unsigned char*)(void*)element,
                     strlen(element) + 1);
}
