#include "handshake_response.h"

#include <cstring>

HandshakeResponse::HandshakeResponse(const unsigned char* const epk,
                                     Nonce& nonce,
                                     const unsigned int ip,
                                     const unsigned char netmask) noexcept {
    /* Set the type */
    header.type = HANDSHAKE_RESPONSE;

    /* Set the ephemeral public key */
    memcpy(header.ephemeral_public_key, epk, crypto_scalarmult_BYTES);

    /* Set the nonce */
    nonce.Copy(header.nonce);

    /* Set the ip and the netmask */
    payload.ip = ip;
    payload.netmask = netmask;
}
