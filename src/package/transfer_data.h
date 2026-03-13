#pragma once

#include "main.h"
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
        unsigned int source_ip;
        unsigned int destination_ip;
    } __attribute__((packed)) header;
    char data[UDPSocket::MTU - sizeof(header)];

    explicit TransferData(Nonce& nonce,
                          unsigned int destination_ip,
                          const char* buffer,
                          int buffer_size) noexcept;
} __attribute__((packed));

FORCE_INLINE TransferData::TransferData(Nonce& nonce,
                                        const unsigned int destination_ip,
                                        const char* const buffer,
                                        const  int buffer_size) noexcept {
    header.type = TRANSFER_DATA;
    nonce.Copy(header.nonce);
    header.source_ip = local_ip.Netb();
    header.destination_ip = destination_ip;
    memcpy(data, buffer, (unsigned long)buffer_size);
}
