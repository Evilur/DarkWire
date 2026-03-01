#include "client.h"
#include "core/config.h"
#include "core/global.h"
#include "core/keys.h"
#include "package/handshake_request.h"
#include "package/handshake_response.h"
#include "util/equal.h"
#include "util/hkdf.h"
#include "util/logger.h"

#include <cstring>
#include <sodium.h>
#include <thread>
#include <unistd.h>

void Client::Init() {
    /* Get the address */
    Server::endpoint =
        UDPSocket::GetAddress(Config::Server::endpoint);

    /* Allocate memory for keys */
    Server::public_key = new unsigned char[crypto_scalarmult_BYTES];
    Server::chain_key =
        new unsigned char[crypto_aead_chacha20poly1305_KEYBYTES];

    /* Get the server's public key */
    const char* public_key_base64 = Config::Server::public_key;
    sodium_base642bin(Server::public_key, crypto_scalarmult_BYTES,
                      public_key_base64, strlen(public_key_base64),
                      nullptr, nullptr, nullptr,
                      sodium_base64_VARIANT_ORIGINAL);
}

void Client::RunHandshakeLoop() {
    /* Send a handhake request */
    for (;;) {
        /* Check the timestamp */
        const unsigned long current_time = std::time(nullptr);
        if (current_time < _next_handshake_timestamp) {
            usleep((unsigned int)(_next_handshake_timestamp - current_time)
                   * 1000);
            continue;
        }

        INFO_LOG("Sending a handshake request to the server");

        /* Generate the ephemeral keys pair */
        Server::ephemeral_keys = new Keys();

        /* Initialize the nonce */
        Nonce nonce;

        /* Fill the request */
        HandshakeRequest request(Server::ephemeral_keys->Public(), nonce);

        /* Compute the first shared secret */
        unsigned char shared[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(shared,
                              Server::ephemeral_keys->Secret(),
                              Server::public_key) == -1) {
            ERROR_LOG("crypto_scalarmult: "
                      "Failed to compute the shared secret");
            continue;
        }

        /* Get the chained ChaCha20 key */
        hkdf(Server::chain_key, nullptr, shared);

        /* Crypt the payload */
        unsigned long long dummy_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            (unsigned char*)(void*)&request.payload,
            &dummy_len,
            (unsigned char*)(void*)&request.payload,
            sizeof(request.payload),
            (unsigned char*)(void*)&request.header,
            sizeof(request.header),
            nullptr,
            request.header.nonce,
            Server::chain_key
        );

        /* Send the encrypted message */
        main_socket.Send((char*)(void*)&request,
                         sizeof(HandshakeRequest),
                         Server::endpoint);

        /* Set the next handshake time */
        _next_handshake_timestamp = current_time + 6;
    }
}

void Client::HandlePackage(const char* const buffer,
                           const int buffer_size,
                           const sockaddr_in& from) {
    /* Get the type of the package */
    const unsigned char raw_type = *(const unsigned char*)buffer;
    if (raw_type > TRANSFER_DATA) return;
    const PackageType type = (PackageType)raw_type;

#define COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(T)                                  \
    {                                                                         \
        T* request = new T(*(const T*)(const void*)buffer);                   \
        std::thread(&Handle##T, request, from).detach();                      \
    }

    /* Handle the package by its type */
    if (type == HANDSHAKE_RESPONSE)
        if (buffer_size == sizeof(HandshakeResponse)
            && equal(from, Server::endpoint))
            COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(HandshakeResponse);
}

void Client::HandleHandshakeResponse(const UniqPtr<HandshakeResponse> response,
                                     const sockaddr_in from) noexcept {
    /* Compute the second shared secret and update the chain key */
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          Server::ephemeral_keys->Secret(),
                          response->header.ephemeral_public_key) == -1) {
        ERROR_LOG("crypto_scalarmult: "
                  "Failed to compute the shared secret");
        return;
    }
    hkdf(Server::chain_key, Server::chain_key, shared);

    /* Compute the third shared secret and update the chain key */
    if (crypto_scalarmult(shared,
                          static_keys->Secret(),
                          response->header.ephemeral_public_key) == -1) {
        ERROR_LOG("crypto_scalarmult: "
                  "Failed to compute the shared secret");
        return;
    }
    hkdf(Server::chain_key, Server::chain_key, shared);

    /* Decrypt the payload */
    unsigned long long dummy_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        (unsigned char*)(void*)&response->payload,
        &dummy_len,
        nullptr,
        (unsigned char*)(void*)&response->payload,
        sizeof(response->payload) + sizeof(response->poly1305_tag),
        (unsigned char*)(void*)&response->header,
        sizeof(response->header),
        response->header.nonce,
        Server::chain_key
    ) != 0) {
        WARN_LOG("Forged message found");
        return;
    };

    /* If there is the first handshake */
    if (tun == nullptr) {
        /* Set the ip and the netmask */
        ip_address.nb = response->payload.ip;
        ip_address.hb = ntohl(ip_address.nb);
        netmask = response->payload.netmask;

        /* Calculate net-specific variables */
        calc_net();

        /* Up the interface */
        up_interface();
    }

    /* If all is OK, next handshake will be after 3 minutes */
    INFO_LOG("The handshake response has been successfully handled");
    _next_handshake_timestamp += 10;
}
