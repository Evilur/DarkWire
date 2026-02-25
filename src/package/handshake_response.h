#pragma once

#include "package_type.h"
#include "util/nonce.h"

#include <sodium.h>

struct HandshakeResponse final {
    struct {
        PackageType type;
        unsigned char ephemeral_public_key[crypto_scalarmult_BYTES];
        unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    } __attribute__((packed)) header;
    struct {
        unsigned int ip;
        unsigned char netmask;
    } __attribute__((packed)) payload;
    unsigned char poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    HandshakeResponse(const unsigned char* epk,
                      Nonce& nonce,
                      unsigned int ip,
                      unsigned char netmask) noexcept;
} __attribute__((packed));
