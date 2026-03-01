#pragma once

#include "util/class.h"

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
