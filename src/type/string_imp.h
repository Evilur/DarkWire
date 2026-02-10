#pragma once

#include "type/string.h"
#include <cstdio>

template <typename T>
T String::ToInt(const char* str) noexcept {
    /* Check for integer */
    static_assert(std::is_integral_v<T>, "<T> must be the integer");

    /* If the integer type is unsigned */
    if constexpr (std::is_unsigned_v<T>) {
        T result = 0;
        while (*str >= '0' && *str <= '9') {
            result *= 10;
            result += *str++ - '0';
        }
        return result;
    /* If the integer type is signed */
    } else {
        using unsigned_t = std::make_unsigned_t<T>;
        if (*str == '-') return -ToInt<unsigned_t>(str + 1);
        return ToInt<unsigned_t>(str);
    }
}

template <typename... Args>
String String::Format(const char* const format, Args... args) {
    const int string_size = snprintf(nullptr, 0, format, args...);
    String result(string_size);
    sprintf(result._str, format, args...);
    return result;
}
