#pragma once

#include "main.h"
#include "package/package_type.h"
#include "util/macro.h"
#include "util/nonce.h"
#include "util/time.h"

#include <sodium.h>

#pragma pack(push, 1)
struct GetPeerRequest final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        uint32_t source_ip;
        uint64_t timestamp;
    } header;
    struct {
        uint32_t requested_peer_ip;
    } data;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    GetPeerRequest(Nonce* nonce, uint32_t peer_ip) noexcept;
};
#pragma pack(pop)

FORCE_INLINE GetPeerRequest::GetPeerRequest(Nonce* const nonce,
                                            const uint32_t peer_ip) noexcept {
    /* Set the package type */
    header.type = GET_PEER_REQUEST;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the source ip */
    header.source_ip = local_ip.Netb();

    /* Set the timestamp */
    header.timestamp = Time::Nanoseconds();

    /* Set the peer's ip */
    data.requested_peer_ip = peer_ip;
}
