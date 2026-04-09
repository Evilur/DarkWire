#pragma once

#include "main.h"
#include "package_type.h"
#include "util/nonce.h"

#include <cstring>
#include <sodium.h>

#pragma pack(push, 1)
struct HandshakeResponse final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        uint8_t ephemeral_public_key[crypto_scalarmult_BYTES];
    } header;
    struct {
        uint32_t local_ip;
        uint8_t netmask;
        uint32_t server_ip;
    } data;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    HandshakeResponse(Nonce* nonce,
                      const uint8_t* epk,
                      uint32_t response_local_ip,
                      uint8_t response_netmask) noexcept;
};
#pragma pack(pop)

FORCE_INLINE HandshakeResponse::HandshakeResponse(
    Nonce* const nonce,
    const uint8_t* const epk,
    const uint32_t response_local_ip,
    const uint8_t response_netmask
) noexcept {
    /* Set the type */
    header.type = HANDSHAKE_RESPONSE;

    /* Set the ephemeral public key */
    memcpy(header.ephemeral_public_key, epk, crypto_scalarmult_BYTES);

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the local ip and the netmask */
    data.local_ip = response_local_ip;
    data.netmask = response_netmask;

    /* Set the server's local ip */
    data.server_ip = local_ip.Netb();
}
