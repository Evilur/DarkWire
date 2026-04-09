#pragma once

#include "main.h"
#include "package_type.h"
#include "socket/udp_socket.h"
#include "util/nonce.h"

#include <cstring>
#include <ctime>
#include <sodium.h>

#pragma pack(push, 1)
struct HandshakeRequest final {
    struct {
        PackageType type;
        uint8_t ephemeral_public_key[crypto_scalarmult_BYTES];
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    } header;
    struct {
        uint8_t static_public_key[crypto_scalarmult_BYTES];
        uint64_t timestamp;
        uint32_t ip;
        uint8_t netmask;
    } data;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    explicit HandshakeRequest(const uint8_t* epk, Nonce* nonce) noexcept;
};
#pragma pack(pop)

FORCE_INLINE HandshakeRequest::HandshakeRequest(const uint8_t* const epk,
                                                Nonce* const nonce) noexcept {
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
    data.timestamp = (uint64_t)std::time(nullptr);

    /* Set the ip and netmask */
    data.ip = local_ip.Netb();
    data.netmask = netmask;
}
