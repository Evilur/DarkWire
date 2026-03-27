#pragma once

#include <cstdint>

enum PackageType : uint8_t {
    HANDSHAKE_REQUEST = 1,
    HANDSHAKE_RESPONSE = 2,
    GET_PEER_REQUEST = 3,
    GET_PEER_RESPONSE = 4,
    PING_REQUEST = 5,
    PING_RESPONSE = 6,
    KEEPALIVE = 7,
    TRANSFER_DATA = 8
};
