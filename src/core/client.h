#pragma once

#include "util/class.h"

/**
 * Static class for client only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Client final {
public:
    PREVENT_INSTANTIATION(Client);

    [[nodiscard]]
    static bool SendHandshakeToServer(char* buffer,
                                      unsigned char* chain_key) noexcept;
};
