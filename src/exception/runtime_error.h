#pragma once

#include "util/class.h"

#include <cstring>
#include <exception>

/**
 * Replacement of the std::runtime_error class
 * @author Evilur <the.evilur@gmail.com>
 */
class RuntimeError : public std::exception {
public:
    ALLOW_COPY_ALLOW_MOVE(RuntimeError);

    explicit RuntimeError(const char* message);

    ~RuntimeError() noexcept override;

    [[nodiscard]] const char* what() const noexcept override;

private:
    char* _message = nullptr;
};

inline RuntimeError::~RuntimeError() noexcept { delete[] _message; }

inline RuntimeError::RuntimeError(const char* const message) :
    _message(new char[strlen(message) + 1]) { strcpy(_message, message); }

inline const char* RuntimeError::what() const noexcept { return _message; }
