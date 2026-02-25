#include "handshake_request.h"
#include "core/global.h"

#include <arpa/inet.h>
#include <cstring>
#include <ctime>

HandshakeRequest::HandshakeRequest(const unsigned char* const epk) {
    /* Set the type */
    header.type = HANDSHAKE_REQUEST;

    /* Set the nonce */
    randombytes_buf(header.nonce, crypto_stream_chacha20_NONCEBYTES);

    /* Copy the public keys */
    memcpy(header.ephemeral_public_key, epk, crypto_scalarmult_BYTES);
    memcpy(payload.static_public_key,
           static_keys->Public(),
           crypto_scalarmult_BYTES);

    /* Set the timestampt */
    payload.timestamp = (unsigned long)std::time(nullptr);

    /* Set the ip and netmask */
    payload.ip = ip_address;
    payload.netmask = netmask;
}
