#pragma once

#include <string_view>

class String final {
public:
    String() = delete;

    explicit String(unsigned long str_size);

    String(const char* str);

    String(const char* str, unsigned long str_size);

    String(const String& other);

    String& operator=(const String& other);

    String(String&& other) noexcept;

    String& operator=(String&& other) noexcept;

    String operator+(char symbol) const;

    String operator+(const char* str) const;

    bool operator==(const String& other) const noexcept;

    bool operator==(const char* other) const noexcept;

    bool operator!=(const String& other) const noexcept;

    bool operator!=(const char* other) const noexcept;

    operator const char*() const noexcept;

    operator char*() const noexcept;

    operator std::string_view() const noexcept;

    ~String() noexcept;

    [[nodiscard]] const char* CStr() const noexcept;

private:
    char* _str;
    unsigned long _size;

public:
    template<typename... Args>
    static String Format(const char* format, Args... args);

    template <typename T>
    static T ToInt(const char* str) noexcept;
};

#include "string_imp.h"
