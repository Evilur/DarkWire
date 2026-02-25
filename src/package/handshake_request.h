#pragma once

#include "package_type.h"

#include <netinet/in.h>
#include <sodium.h>

struct HandshakeRequest final {
    struct {
        PackageType type;
        unsigned char ephemeral_public_key[crypto_scalarmult_BYTES];
        unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    } __attribute__((packed)) header;
    struct {
        unsigned char static_public_key[crypto_scalarmult_BYTES];
        unsigned long timestamp;
        unsigned int ip;
        unsigned char netmask;
    } __attribute__((packed)) payload;
    unsigned char poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    explicit HandshakeRequest(const unsigned char* epk);
} __attribute__((packed));
