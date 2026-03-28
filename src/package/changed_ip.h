#pragma once

#include "main.h"
#include "package/package_type.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <sodium.h>

struct ChangedIP final {
    struct {
        PackageType type;
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        uint32_t source_ip;
    } __attribute__((packed)) header;
    struct {
        uint32_t host_which_changed_ip;
    } __attribute__((packed)) data;
    uint8_t poly1305_tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

    ChangedIP(Nonce* nonce, uint32_t host_which_changed_ip) noexcept;
} __attribute__((packed));

FORCE_INLINE ChangedIP::ChangedIP(Nonce* const nonce,
                                  const uint32_t host_which_changed_ip)
noexcept {
    /* Set the package type */
    header.type = CHANGED_IP;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the source ip */
    header.source_ip = local_ip.Netb();

    /* Set the host which changed the IP address */
    data.host_which_changed_ip = host_which_changed_ip;
}
