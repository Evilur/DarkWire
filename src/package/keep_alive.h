#pragma once

#include "main.h"
#include "package_type.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <sodium.h>

#pragma pack(push, 1)
struct KeepAlive final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
        uint32_t source_ip;
        uint64_t timestamp;
    } header;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    explicit KeepAlive(Nonce* nonce, uint64_t timestamp) noexcept;
};
#pragma pack(pop)

FORCE_INLINE KeepAlive::KeepAlive(Nonce* const nonce,
                                  const uint64_t timestamp) noexcept {
    /* Set the package */
    header.type = KEEPALIVE;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the source ip */
    header.source_ip = local_ip.Netb();

    /* Set the timestamp */
    header.timestamp = timestamp;
}
