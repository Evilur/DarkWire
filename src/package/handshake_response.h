#pragma once

#include "core/global.h"
#include "package_type.h"
#include "util/nonce.h"

#include <cstring>
#include <sodium.h>

struct HandshakeResponse final {
    struct {
        PackageType type;
        unsigned char ephemeral_public_key[crypto_scalarmult_BYTES];
        unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    } __attribute__((packed)) header;
    struct {
        unsigned int local_ip;
        unsigned char netmask;
        unsigned int server_local_ip;
    } __attribute__((packed)) payload;
    unsigned char poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    HandshakeResponse(const unsigned char* epk,
                      Nonce& nonce,
                      unsigned int response_local_ip,
                      unsigned char response_netmask) noexcept;
} __attribute__((packed));

inline HandshakeResponse::HandshakeResponse(
    const unsigned char* const epk,
    Nonce& nonce,
    const unsigned int response_local_ip,
    const unsigned char response_netmask
) noexcept {
    /* Set the type */
    header.type = HANDSHAKE_RESPONSE;

    /* Set the ephemeral public key */
    memcpy(header.ephemeral_public_key, epk, crypto_scalarmult_BYTES);

    /* Set the nonce */
    nonce.Copy(header.nonce);

    /* Set the local ip and the netmask */
    payload.local_ip = response_local_ip;
    payload.netmask = response_netmask;

    /* Set the server's local ip */
    payload.server_local_ip = local_ip.netb;
}
