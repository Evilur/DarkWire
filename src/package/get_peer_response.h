#pragma once

#include "main.h"
#include "package/package_type.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <sodium.h>

struct GetPeerResponse final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    } __attribute__((packed)) header;
    struct {
        uint32_t destination_ip;
        uint8_t public_key[crypto_scalarmult_BYTES];
        uint8_t symmetric_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    } __attribute__((packed)) data;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    GetPeerResponse(uint32_t peer_ip,
                    Nonce* nonce,
                    uint8_t* public_key,
                    uint8_t* symmetric_key) noexcept;
} __attribute__((packed));

FORCE_INLINE GetPeerResponse::GetPeerResponse(const uint32_t peer_ip,
                                              Nonce* const nonce,
                                              uint8_t* publick_key,
                                              uint8_t* symmetric_key)
noexcept {
    /* Set the package type */
    header.type = GET_PEER_RESPONSE;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the peer's ip */
    data.destination_ip = peer_ip;

    /* Copy the peer's public key */
    memcpy(data.public_key, publick_key, crypto_scalarmult_BYTES);

    /* Copy the shared symmetric key */
    memcpy(data.symmetric_key, symmetric_key,
           crypto_aead_chacha20poly1305_ietf_KEYBYTES);
}
