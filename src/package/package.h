#pragma once

#include <netinet/in.h>

/**
 * Class for crypting/decrypting packages for
 * transfering them by the unreliable channel
 * @author Evilur <the.evilur@gmail.com>
 */
class Package final {
public:
    enum Type : unsigned char {
        SERVER_HANDSHAKE_REQUEST = 1,
        SERVER_HANDSHAKE_RESPONSE = 2,
        PEER_HANDSHAKE_REQUEST = 3,
        PEER_HANDSHAKE_RESPONSE = 4,
        KEEPALIVE = 5,
        TRANSFER_DATA = 6,
        INVALID = 255
    };

    static Type GetType(const char* buffer) noexcept;
};
