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
        uint32_t local_ip;
        uint32_t real_ip;
        uint16_t real_port;
        uint8_t public_key[crypto_scalarmult_BYTES];
    } __attribute__((packed)) data;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    GetPeerResponse(Nonce* nonce,
                    uint32_t peer_ip) noexcept;

    void SetData(const sockaddr_in& endpoint,
                 uint8_t* public_key) noexcept;
} __attribute__((packed));

FORCE_INLINE
GetPeerResponse::GetPeerResponse(Nonce* const nonce,
                                 const uint32_t peer_ip) noexcept {
    /* Set the package type */
    header.type = GET_PEER_RESPONSE;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the peer's ip */
    data.local_ip = peer_ip;
}

FORCE_INLINE
void GetPeerResponse::SetData(const sockaddr_in& endpoint,
                              uint8_t* public_key) noexcept {
    /* Set the endpoint */
    data.real_ip = endpoint.sin_addr.s_addr;
    data.real_port = endpoint.sin_port;

    /* Copy the peer's public key */
    if (public_key != nullptr)
        memcpy(data.public_key, public_key, crypto_scalarmult_BYTES);
    else
        memset(data.public_key, 0, crypto_scalarmult_BYTES);
}
