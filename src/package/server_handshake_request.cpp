#include "server_handshake_request.h"

#include <arpa/inet.h>
#include <cstring>
#include <ctime>

void ServerHandshakeRequest::Fill(const unsigned char* const epk,
                                  const unsigned char* const spk,
                                  const char* const address) {
    /* Set the type */
    type = Package::SERVER_HANDSHAKE_REQUEST;

    /* Set the nonce */
    randombytes_buf(nonce, crypto_stream_chacha20_NONCEBYTES);

    /* Copy the public keys */
    memcpy(ephemeral_public_key, epk, crypto_scalarmult_BYTES);
    memcpy(payload.static_public_key, spk, crypto_scalarmult_BYTES);

    /* Set the timestampt */
    payload.timestamp = (unsigned long)std::time(nullptr);

    /* Set the ip and netmask */
    char address_buffer[] = "255.255.255.255/32";
    strcpy(address_buffer, address);
    char* address_buffer_sep = strchr(address_buffer, '/');
    if (address_buffer_sep == nullptr) *address_buffer = '\0';
    if (*address_buffer == '\0') {
        payload.ip = INADDR_ANY;
        payload.netmask = 0;
    } else {
        payload.ip = inet_addr(address_buffer);
        payload.netmask = (unsigned char)atoi(address_buffer_sep + 1);
    }
}
