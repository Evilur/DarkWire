#pragma once

#include "package.h"

#include <sodium.h>

struct ServerHandshakeRequest final {
    Package::Type type;
    unsigned char ephemeral_public_key[crypto_scalarmult_BYTES];
    unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
    struct {
        unsigned char static_public_key[crypto_scalarmult_BYTES];
        unsigned long timestamp;
        unsigned int ip;
        unsigned char netmask;
    } __attribute__((aligned(64))) __attribute__((packed)) payload;

    void Fill(const unsigned char* epk,
              const unsigned char* spk,
              const char* address);
} __attribute__((aligned(128)));
