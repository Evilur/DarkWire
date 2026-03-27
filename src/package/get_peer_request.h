#pragma once

#include "main.h"
#include "package/package_type.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <sodium.h>

struct GetPeerRequest final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        uint32_t source_ip;
    } __attribute__((packed)) header;
    struct {
        uint32_t destination_ip;
    } __attribute__((packed)) data;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    GetPeerRequest(Nonce* nonce, uint32_t peer_ip) noexcept;
} __attribute__((packed));

FORCE_INLINE GetPeerRequest::GetPeerRequest(Nonce* const nonce,
                                            const uint32_t peer_ip) noexcept {
    /* Set the package type */
    header.type = GET_PEER_REQUEST;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the source ip */
    header.source_ip = local_ip.Netb();

    /* Set the peer's ip */
    data.destination_ip = peer_ip;
}
