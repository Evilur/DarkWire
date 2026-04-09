#pragma once

#include "main.h"
#include "package_type.h"
#include "util/nonce.h"

#include <cstring>
#include <sodium.h>

#pragma pack(push, 1)
struct HandshakeRequest final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        uint8_t ephemeral_public_key[crypto_scalarmult_BYTES];
        uint64_t timestamp;
    } header;
    struct {
        uint8_t static_public_key[crypto_scalarmult_BYTES];
        uint32_t ip;
        uint8_t netmask;
    } data;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    explicit HandshakeRequest(Nonce* nonce,
                              const uint8_t* epk,
                              uint64_t timestamp) noexcept;
};
#pragma pack(pop)

static_assert(sizeof(HandshakeRequest) == 106, "Invalid struct packing");

FORCE_INLINE HandshakeRequest::HandshakeRequest(Nonce* const nonce,
                                                const uint8_t* const epk,
                                                const uint64_t timestamp)
noexcept {
    /* Set the type */
    header.type = HANDSHAKE_REQUEST;

    /* Copy the public keys */
    memcpy(header.ephemeral_public_key, epk, crypto_scalarmult_BYTES);
    memcpy(data.static_public_key,
           static_keys->Public(),
           crypto_scalarmult_BYTES);

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the timestampt */
    header.timestamp = timestamp;

    /* Set the ip and netmask */
    data.ip = local_ip.Netb();
    data.netmask = netmask;
}
