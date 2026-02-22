#include "client.h"
#include "core/config.h"
#include "main.h"
#include "package/server_handshake_request.h"
#include "util/equal.h"
#include "util/hkdf.h"
#include "util/logger.h"

void Client::PerformHandshakeWithServer() noexcept {
    /* Buffer for requests and responses */
    char buffer[1500];

    /* Buffer for the chained key */
    unsigned char chain_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];

    /* Send the handhake request */
send_request:
    {
        INFO_LOG("Sending the handshake request to the server");

        /* Generate the ephemeral key pair */
        const Keys ephemeral_keys;

        /* Fill the reuqest */
        ServerHandshakeRequest* request = new (buffer) ServerHandshakeRequest(
            ephemeral_keys.Public(),
            static_keys->Public(),
            (const char*)Config::Interface::address
        );

        /* Compute the first shared secret */
        unsigned char shared[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(shared,
                              ephemeral_keys.Secret(),
                              server_public_key) == -1) {
            ERROR_LOG("crypto_scalarmult: Failed to compute the shared secret");
            goto send_request;
        }

        /* Get the chained ChaCha20 key */
        hkdf(chain_key, nullptr, shared);

        /* Crypt the payload */
        unsigned long long dummy_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            (unsigned char*)(void*)&request->payload,
            &dummy_len,
            (unsigned char*)(void*)&request->payload,
            sizeof(request->payload),
            (unsigned char*)(void*)&request->header,
            sizeof(request->header),
            nullptr,
            request->header.nonce,
            chain_key
        );

        /* Send the crypted message */
        main_socket.Send(buffer, sizeof(ServerHandshakeRequest), server);
    }

    /* Try to the get a server response */
receive_response:
    {
        sockaddr_in from;
        int response_size = main_socket.Receive(buffer, &from);

        /* If there is an error */
        if (response_size == -1) goto send_request;

        /* If there is a package not from the server */
        if (!equal(from, server)) goto receive_response;

        /* If all is OK, handle the response */
        INFO_LOG("The response has been received from the server");
    }
}
