#pragma once

#include "main.h"
#include "package_type.h"
#include "util/nonce.h"

#include <cstring>
#include <sodium.h>

#pragma pack(push, 1)
struct P2PHandshakeRequest final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        uint8_t ephemeral_public_key[crypto_scalarmult_BYTES];
        uint64_t timestamp;
        uint32_t source_ip;
        uint32_t destination_ip;
        bool nat_probe;
    } header;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    explicit P2PHandshakeRequest(Nonce* nonce,
                                 const uint8_t* ephemeral_public_key,
                                 uint64_t timestamp,
                                 uint32_t destination_ip,
                                 bool nat_probe) noexcept;
};
#pragma pack(pop)

FORCE_INLINE
P2PHandshakeRequest::P2PHandshakeRequest(
    Nonce* const nonce,
    const uint8_t* const ephemeral_public_key,
    const uint64_t timestamp,
    const uint32_t destination_ip,
    const bool nat_probe
) noexcept {
    /* Set the package type */
    header.type = P2P_HANDSHAKE_REQUEST;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the ephemeral public key */
    memcpy(header.ephemeral_public_key,
           ephemeral_public_key,
           crypto_scalarmult_BYTES);

    /* Set the timestamp */
    header.timestamp = timestamp;

    /* Set the source ip */
    header.source_ip = local_ip.Netb();

    /* Set the destination ip */
    header.destination_ip = destination_ip;

    /* Set nat probe */
    header.nat_probe = nat_probe;
}
