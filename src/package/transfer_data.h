#pragma once

#include "package_type.h"
#include "socket/udp_socket.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <cstring>
#include <sodium.h>

struct TransferData final {
    struct {
        PackageType type;
        unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        unsigned int destination_ip;
    } __attribute__((packed)) header;
    struct {
        char buffer[UDPSocket::MTU - sizeof(header)];
    } __attribute__((packed)) payload;

    explicit TransferData(Nonce& nonce,
                          unsigned int destination_ip,
                          const char* buffer,
                          int buffer_size) noexcept;

    [[nodiscard]] unsigned int Size(int buffer_size) const noexcept;
} __attribute__((packed));

FORCE_INLINE TransferData::TransferData(Nonce& nonce,
                                        const unsigned int destination_ip,
                                        const char* const buffer,
                                        const  int buffer_size) noexcept {
    header.type = TRANSFER_DATA;
    nonce.Copy(header.nonce);
    header.destination_ip = destination_ip;
    memcpy(payload.buffer, buffer, (unsigned long)buffer_size);
}

FORCE_INLINE unsigned int TransferData::Size(const int buffer_size)
const noexcept {
    return sizeof(header) +
           buffer_size +
           crypto_aead_chacha20poly1305_ietf_ABYTES;
}
