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
        int64_t sequence_number;
        uint32_t source_ip;
    } header;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    NatProbeRequest(Nonce* nonce,
                    int64_t sequence_number) noexcept;
};
#pragma pack(pop)

FORCE_INLINE NatProbeRequest::NatProbeRequest(
    Nonce* const nonce,
    const int64_t sequence_number
) noexcept {
    /* Set the package type */
    header.type = NAT_PROBE_REQUEST;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Save the sequence number */
    header.sequence_number = sequence_number;

    /* Set the souce ip */
    header.source_ip = local_ip.Netb();
}
