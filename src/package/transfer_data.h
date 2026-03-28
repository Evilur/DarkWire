#pragma once

#include "main.h"
#include "package_type.h"
#include "socket/udp_socket.h"
#include "util/macro.h"
#include "util/nonce.h"
#include "util/time.h"

#include <sodium.h>

struct TransferData final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        uint32_t source_ip;
        uint32_t destination_ip;
        uint64_t timestamp;
    } __attribute__((packed)) header;
    char data[UDPSocket::MTU - sizeof(header)];

    TransferData() noexcept;

    void UpdateHeader(Nonce* nonce,
                      uint32_t destination_ip,
                      uint64_t timestamp) noexcept;
} __attribute__((packed));

FORCE_INLINE TransferData::TransferData() noexcept {
    header.type = TRANSFER_DATA;
}

FORCE_INLINE void TransferData::UpdateHeader(Nonce* const nonce,
                                             const uint32_t destination_ip,
                                             const uint64_t timestamp)
noexcept {
    /* Copy the nonce */
    nonce->Copy(header.nonce);

    /* Update the source ip */
    header.source_ip = local_ip.Netb();

    /* Set the destination ip */
    header.destination_ip = destination_ip;

    /* Set the timestamp */
    header.timestamp = timestamp;
}
