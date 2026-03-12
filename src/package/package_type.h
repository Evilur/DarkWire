#pragma once

enum PackageType : unsigned char {
    HANDSHAKE_REQUEST = 1,
    HANDSHAKE_RESPONSE = 2,
    GET_PEER_REQUEST = 3,
    GET_PEER_RESPONSE = 4,
    HOLE_PUNCH = 5,
    GENKEY_REQUEST = 6,
    GENKEY_RESPOSNE = 7,
    KEEPALIVE = 8,
    TRANSFER_DATA = 9
};
