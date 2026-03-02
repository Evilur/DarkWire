#pragma once

enum PackageType : unsigned char {
    HANDSHAKE_REQUEST = 1,
    HANDSHAKE_RESPONSE = 2,
    GENKEY_REQUEST = 3,
    GENKEY_RESPOSNE = 4,
    GET_PEER_REQUEST = 5,
    GET_PEER_RESPONSE = 6,
    KEEPALIVE = 7,
    TRANSFER_DATA = 8
};
