#pragma once

enum PackageType : unsigned char {
    HANDSHAKE_REQUEST = 1,
    HANDSHAKE_RESPONSE = 2,
    GET_PEER_REQUEST = 3,
    GET_PEER_RESPONSE = 4,
    GENKEY_REQUEST = 5,
    GENKEY_RESPOSNE = 6,
    KEEPALIVE = 7,
    TRANSFER_DATA = 8
};
