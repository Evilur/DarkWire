#pragma once

#include "main.h"
#include "package_type.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <sodium.h>

#pragma pack(push, 1)
struct NatProbeRequest final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        uint32_t source_ip;
        uint32_t destination_ip;
        uint64_t timestamp;
    } header;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    NatProbeRequest(Nonce* nonce,
                    uint32_t destination_ip,
                    uint64_t timestamp) noexcept;
};
#pragma pack(pop)

FORCE_INLINE NatProbeRequest::NatProbeRequest(
    Nonce* const nonce,
    const uint32_t destination_ip,
    const uint64_t timestamp
) noexcept {
    /* Set the package type */
    header.type = NAT_PROBE_REQUEST;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the souce ip */
    header.source_ip = local_ip.Netb();

    /* Set the destination ip */
    header.destination_ip = destination_ip;

    /* Save the timestamp */
    header.timestamp = timestamp;
}
