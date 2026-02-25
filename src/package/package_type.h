#pragma once

enum PackageType : unsigned char {
    HANDSHAKE_REQUEST = 1,
    HANDSHAKE_RESPONSE = 2,
    GENKEY_REQUEST = 3,
    GENKEY_RESPONSE = 4,
    KEEPALIVE = 5,
    TRANSFER_DATA = 6
};
