#pragma once

#include "main.h"
#include "package_type.h"
#include "util/nonce.h"

#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <netinet/in.h>
#include <sodium.h>

struct HandshakeRequest final {
    struct {
        PackageType type;
        unsigned char ephemeral_public_key[crypto_scalarmult_BYTES];
        unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    } __attribute__((packed)) header;
    struct {
        unsigned char static_public_key[crypto_scalarmult_BYTES];
        unsigned long timestamp;
        unsigned int ip;
        unsigned char netmask;
    } __attribute__((packed)) payload;
    unsigned char poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    explicit HandshakeRequest(const unsigned char* epk, Nonce& nonce) noexcept;
} __attribute__((packed));

inline HandshakeRequest::HandshakeRequest(const unsigned char* const epk,
                                          Nonce& nonce) noexcept {
    /* Set the type */
    header.type = HANDSHAKE_REQUEST;

    /* Copy the public keys */
    memcpy(header.ephemeral_public_key, epk, crypto_scalarmult_BYTES);
    memcpy(payload.static_public_key,
           static_keys->Public(),
           crypto_scalarmult_BYTES);

    /* Set the nonce */
    nonce.Copy(header.nonce);

    /* Set the timestampt */
    payload.timestamp = (unsigned long)std::time(nullptr);

    /* Set the ip and netmask */
    payload.ip = local_ip.netb;
    payload.netmask = netmask;
}
