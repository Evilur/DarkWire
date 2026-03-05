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
        char buffer[1472 + crypto_aead_chacha20poly1305_ietf_ABYTES];
    } __attribute__((packed)) payload;

    explicit TransferData(Nonce& nonce,
                          const char* buffer,
                          int buffer_size) noexcept;

    [[nodiscard]] unsigned int Size(int buffer_size) const noexcept;
} __attribute__((packed));

inline TransferData::TransferData(Nonce& nonce,
                                  const char* const buffer,
                                  const  int buffer_size) noexcept {
    header.type = TRANSFER_DATA;
    nonce.Copy(header.nonce);
    memcpy(payload.buffer, buffer, buffer_size);
}

inline unsigned int TransferData::Size(const int buffer_size)
const noexcept {
    return sizeof(header) +
           buffer_size +
           crypto_aead_chacha20poly1305_ietf_ABYTES;
}
