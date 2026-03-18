#pragma once

#include "main.h"
#include "package_type.h"
#include "socket/udp_socket.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <sodium.h>

struct TransferData final {
    struct {
        PackageType type;
        unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        unsigned int source_ip;
        unsigned int destination_ip;
    } __attribute__((packed)) header;
    char data[UDPSocket::MTU - sizeof(header)];

    TransferData() noexcept;

    void UpdateHeader(Nonce* nonce, unsigned int destination_ip) noexcept;
} __attribute__((packed));

FORCE_INLINE TransferData::TransferData() noexcept {
    header.type = TRANSFER_DATA;
}

FORCE_INLINE void TransferData::UpdateHeader(Nonce* const nonce,
                                             const unsigned int destination_ip)
noexcept {
    /* Copy the nonce */
    nonce->Copy(header.nonce);

    /* Update the source ip */
    header.source_ip = local_ip.Netb();

    /* Set the destination ip */
    header.destination_ip = destination_ip;
}
