#pragma once

#include "main.h"
#include "package_type.h"
#include "socket/udp_socket.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <sodium.h>

#pragma pack(push, 1)
struct TransferData final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        int64_t sequence_number;
        uint32_t source_ip;
        uint32_t destination_ip;
    } header;
    char data[UDPSocket::MTU - sizeof(header)];

    TransferData() noexcept;

    void UpdateHeader(Nonce* nonce,
                      int64_t sequence_number,
                      uint32_t destination_ip) noexcept;
};
#pragma pack(pop)

FORCE_INLINE TransferData::TransferData() noexcept {
    header.type = TRANSFER_DATA;
}

FORCE_INLINE void TransferData::UpdateHeader(Nonce* const nonce,
                                             const int64_t sequence_number,
                                             const uint32_t destination_ip)
noexcept {
    /* Copy the nonce */
    nonce->Copy(header.nonce);

    /* Update the source ip */
    header.source_ip = local_ip.Netb();

    /* Set the sequence number */
    header.sequence_number = sequence_number;

    /* Set the destination ip */
    header.destination_ip = destination_ip;
}
