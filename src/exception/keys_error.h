#pragma once

#include "runtime_error.h"

/**
 * Wrapper class for the Keys class runtime errors
 * @author Evilur <the.evilur@gmail.com>
 */
class KeysError final : public RuntimeError {
public:
    explicit KeysError(const char* message);
};
