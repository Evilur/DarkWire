#pragma once

#include "package_type.h"
#include "util/nonce.h"

#include <cstring>
#include <sodium.h>

struct TransferData final {
    struct {
        PackageType type;
        unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    } __attribute__((packed)) header;
    struct {
        char buffer[1472];
    } __attribute__((packed)) payload;
    unsigned char poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    explicit TransferData(Nonce& nonce,
                          const char* buffer,
                          unsigned int buffer_size) noexcept;
} __attribute__((packed));

inline TransferData::TransferData(Nonce& nonce,
                                  const char* const buffer,
                                  const unsigned int buffer_size) noexcept {
    header.type = TRANSFER_DATA;
    nonce.Copy(header.nonce);
    memcpy(payload.buffer, buffer, buffer_size);
}
