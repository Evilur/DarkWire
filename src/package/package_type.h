#pragma once

#include <cstdint>

enum PackageType : uint8_t {
    HANDSHAKE_REQUEST = 1,
    HANDSHAKE_RESPONSE = 2,
    REHANDSHAKE = 3,
    GET_PEER_REQUEST = 4,
    GET_PEER_RESPONSE = 5,
    PING_REQUEST = 6,
    PING_RESPONSE = 7,
    CHANGED_IP = 8,
    KEEPALIVE = 9,
    TRANSFER_DATA = 10
};
