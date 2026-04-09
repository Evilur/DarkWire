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
        int64_t sequence_number;
        uint32_t source_ip;
    } header;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    explicit KeepAlive(Nonce* nonce,
                       int64_t sequence_number) noexcept;
};
#pragma pack(pop)

FORCE_INLINE KeepAlive::KeepAlive(Nonce* const nonce,
                                  const int64_t sequence_number) noexcept {
    /* Set the package */
    header.type = KEEPALIVE;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the source ip */
    header.source_ip = local_ip.Netb();

    /* Set the sequence number */
    header.sequence_number = sequence_number;
}
