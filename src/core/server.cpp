#include "server.h"
#include "main.h"
#include "package/package_type.h"
#include "util/hkdf.h"
#include "util/logger.h"

void Server::HandlePackage(const char* const buffer,
                           const sockaddr_in& client) {
    /* Get the type of the package */
    const unsigned char raw_type = *(const unsigned char*)buffer;
    if (raw_type > TRANSFER_DATA) return;
    const PackageType type = (PackageType)raw_type;

    /* Handle the package by its type */
#define COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(T)                                  \
    {                                                                         \
        const void* data = buffer;                                            \
        T* request = new T(*(const T*)data);                                  \
        Handle##T(request, client);                                           \
    }

    if (type == SERVER_HANDSHAKE_REQUEST)
        COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(ServerHandshakeRequest);
}

void Server::HandleServerHandshakeRequest(
    const ServerHandshakeRequest* const request,
    const sockaddr_in client
) noexcept {
    /* Buffer for the chained key */
    unsigned char chain_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];

    /* Decrypt the request payload */
    {
        /* Compute the first shared secret */
        unsigned char shared[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(shared,
                              static_keys->Secret(),
                              request->header.ephemeral_public_key) == -1) {
            ERROR_LOG("crypto_scalarmult: Failed to compute the shared secret");
            return;
        }

        /* Get the chained ChaCha20 key */
        hkdf(chain_key, nullptr, shared);

        /* Decrypt the message */
        unsigned long long dummy_len;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char*)(void*)&request->payload,
            &dummy_len,
            nullptr,
            (unsigned char*)(void*)&request->payload,
            sizeof(request->payload) + sizeof(request->poly1305_tag),
            (unsigned char*)(void*)&request->header,
            sizeof(request->header),
            request->header.nonce,
            chain_key
        ) != 0) {
            WARN_LOG("Forged message found");
            return;
        };
    }

    /* Check the client */
    {

    }
}
