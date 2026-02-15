#include "type/string.h"

#include <cstring>

String::String(const unsigned long str_size) :
    _str(new char[str_size + 1]), _size(str_size) {
    _str[str_size] = '\0';
}

String::String(const char* const str) : String(str, strlen(str)) { }

String::String(const char* str, const unsigned long str_size) :
    String(str_size) {
    if (str != nullptr) memcpy(_str, str, str_size);
}

String::String(const String& other) :
    _str(new char[other._size + 1]), _size(other._size) {
    /* Assign a new data */
    memcpy(_str, other._str, other._size + 1);
}

String& String::operator=(const String& other) {
    /* Self-assignment check */
    if (this == &other) return *this;

    /* Delete previous data */
    delete[] _str;

    /* Assign a new data */
    _str = new char[other._size + 1];
    memcpy(_str, other._str, other._size + 1);
    _size = other._size;
    return *this;
}

String::String(String&& other) noexcept :
    _str(other._str), _size(other._size) {
    other._str = nullptr;
    other._size = 0;
}

String& String::operator=(String&& other) noexcept {
    /* Delete previous data */
    delete[] _str;

    /* Assign a new data */
    _str = other._str;
    _size = other._size;

    /* Null the old object */
    other._str = nullptr;
    other._size = 0;
    return *this;
}

String String::operator+(const char symbol) const {
    String result(_str, _size + 1);
    result._str[_size] = symbol;
    return result;
}

String::operator const char*() const noexcept { return _str; }

String::operator std::string_view() const noexcept { return { _str, _size }; }

String::~String() noexcept { delete[] _str; }
