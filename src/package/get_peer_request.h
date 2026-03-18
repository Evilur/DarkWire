#pragma once

#include "package/package_type.h"
#include "socket/udp_socket.h"
#include "util/macro.h"
#include "util/nonce.h"

#include <sodium.h>

struct GetPeerRequest final {
    struct {
        PackageType type;
        unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    } __attribute__((packed)) header;
    char data[UDPSocket::MTU - sizeof(header)];

    GetPeerRequest(unsigned int peer_ip, Nonce* nonce) noexcept;

    GetPeerRequest(const unsigned int* peer_ips,
                   unsigned short ips_number,
                   Nonce* nonce) noexcept;
} __attribute__((packed));

FORCE_INLINE GetPeerRequest::GetPeerRequest(const unsigned int peer_ip,
                                            Nonce* const nonce) noexcept {
    /* Set the package type */
    header.type = GET_PEER_REQUEST;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the peer's ip */
    memcpy(data, &peer_ip, sizeof(peer_ip));
}

FORCE_INLINE GetPeerRequest::GetPeerRequest(const unsigned int* const peer_ip,
                                            const unsigned short ips_number,
                                            Nonce* const nonce) noexcept {
    /* Set the package type */
    header.type = GET_PEER_REQUEST;

    /* Set the nonce */
    nonce->Copy(header.nonce);

    /* Set the peer ips */
    memcpy(data, peer_ip, sizeof(unsigned int) * ips_number);
}
