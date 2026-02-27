#pragma once

enum PackageType : unsigned char {
    HANDSHAKE_REQUEST = 1,
    HANDSHAKE_RESPONSE = 2,
    PEERS_LIST = 3,
    GENKEY_REQUEST = 4,
    GENKEY_RESPONSE = 5,
    KEEPALIVE = 6,
    TRANSFER_DATA = 7
};
