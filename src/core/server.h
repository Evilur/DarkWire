#pragma once

#include "util/class.h"

/**
 * Static class for server only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Client final {
public:
    PREVENT_INSTANTIATION(Client);

    [[nodiscard]]
    static bool HandlePackage(char* buffer) noexcept;
};
