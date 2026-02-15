#pragma once

#include "runtime_error.h"

/**
 * Wrapper class for the TUN class runtime errors
 * @author Evilur <the.evilur@gmail.com>
 */
class TunError final : public RuntimeError {
public:
    explicit TunError(const char* message);
};
