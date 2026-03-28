#pragma once

#include "main.h"
#include "package_type.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <sodium.h>

struct PingRequest final {
    enum ReplayType : uint8_t { DIRECT, RELAY_SERVER };

    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        uint32_t source_ip;
        uint32_t destination_ip;
        ReplayType replay_type;
    } __attribute__((packed)) header;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    PingRequest(Nonce* nonce,
                uint32_t destination_ip,
                ReplayType replay_type) noexcept;
} __attribute__((packed));

FORCE_INLINE PingRequest::PingRequest(Nonce* const nonce,
                                      const uint32_t destination_ip,
                                      const ReplayType replay_type) noexcept {
    /* Set the package type */
    header.type = PING_REQUEST;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the souce ip */
    header.source_ip = local_ip.Netb();

    /* Set the destination ip */
    header.destination_ip = destination_ip;

    /* Set the replay type */
    header.replay_type = replay_type;
}
