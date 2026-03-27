#pragma once

#include "util/class.h"
#include "util/macro.h"

#include <cstdint>
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

FORCE_INLINE RuntimeError::~RuntimeError() noexcept { delete[] _message; }

FORCE_INLINE RuntimeError::RuntimeError(const char* const message) :
    _message(new char[strlen(message) + 1]) { strcpy(_message, message); }

FORCE_INLINE const char* RuntimeError::what()
const noexcept { return _message; }
