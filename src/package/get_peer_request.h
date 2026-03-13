#pragma once

#include "package/package_type.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <sodium.h>

struct GetPeerRequest final {
    struct {
        PackageType type;
        unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    } __attribute__((packed)) header;
    struct {
        unsigned int peer_ip;
    } __attribute__((packed)) data;
    unsigned char poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    GetPeerRequest(unsigned int peer_ip, Nonce& nonce) noexcept;
} __attribute__((packed));

FORCE_INLINE GetPeerRequest::GetPeerRequest(const unsigned int peer_ip,
                                            Nonce& nonce) noexcept {
    /* Set the package type */
    header.type = GET_PEER_REQUEST;

    /* Set the nonce */
    nonce.Copy(header.nonce);

    /* Set the peer's ip */
    data.peer_ip = peer_ip;
}
