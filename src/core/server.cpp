#include "server.h"
#include "core/global.h"
#include "core/keys.h"
#include "package/package_type.h"
#include "util/hkdf.h"
#include "util/logger.h"

#include <cstring>

void Server::SavePeer(const unsigned char* const public_key) {
    /* If the peers list isn't defined yet */
    if (Peers::public_keys == nullptr) {
        /* Allocate the memory for the peers list */
        Peers::public_keys = new LinkedList<const unsigned char*>();

        /* Set the program mode */
        mode = SERVER;
    }

    /* Push the peer to the list, and increment the counter */
    Peers::public_keys->Push(public_key);
    ++Peers::number;
}

void Server::Init() {
    /* Allocate the memory for the dictionary */
    Peers::details = new Dictionary<KeyBuffer,
                                    Peers::Details,
                                    unsigned int>(Peers::number);

    /* Fill timestamps dictioary with zeros */
    for (const unsigned char* public_key : *Peers::public_keys)
        Peers::details->Put(public_key, {
            .last_timestamp = 0,
            .ip = INADDR_ANY
        });
}

void Server::HandlePackage(const char* const buffer,
                           const sockaddr_in& client) {
    /* Get the type of the package */
    const unsigned char raw_type = *(const unsigned char*)buffer;
    if (raw_type > TRANSFER_DATA) return;
    const PackageType type = (PackageType)raw_type;

    /* Handle the package by its type */
#define COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(T)                                  \
    {                                                                         \
        T* request = new T(*(const T*)(const void*)buffer);                   \
        Handle##T(request, client);                                           \
    }

    if (type == SERVER_HANDSHAKE_REQUEST)
        COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(ServerHandshakeRequest);
}

void Server::HandleServerHandshakeRequest(
    const UniqPtr<ServerHandshakeRequest> request,
    const sockaddr_in client
) noexcept {
    INFO_LOG("Recieve the handshake request from %s:%hu",
             inet_ntoa(client.sin_addr),
             ntohs(client.sin_port));

    /* Buffer for the chained key */
    unsigned char chain_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];

    /* Decrypt the request payload */
    {
        /* Compute the first shared secret */
        unsigned char shared[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(shared,
                              static_keys->Secret(),
                              request->header.ephemeral_public_key) == -1) {
            ERROR_LOG("crypto_scalarmult: "
                      "Failed to compute the shared secret");
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

    /* Check the client's key */
    {
        /* Try to find such a static key in the allowed peers linked list */
        bool is_allowed = false;
        for (const unsigned char* public_key : *Peers::public_keys)
            if (memcmp(request->payload.static_public_key,
                       public_key,
                       crypto_scalarmult_BYTES) == 0)
                is_allowed = true;
        if (!is_allowed) {
            WARN_LOG("The client is not in the allowed list");
            return;
        }
    }

    /* Check the timestamp */
    {
        /* Get the current time */
        unsigned long current_time = (unsigned long)std::time(nullptr);
        unsigned long client_timestamp = request->payload.timestamp;

        /* Get the delta time */
        unsigned long delta_time = current_time > client_timestamp
                                 ? current_time - client_timestamp
                                 : client_timestamp - current_time;

        /* If the time delta is too big */
        if (delta_time > 120) return;

        /* Get the last client's timestamp */
        unsigned long& last_timestamp = Peers::details->Get(
            request->payload.static_public_key
        ).last_timestamp;

        /* Compare current timestamp with the last one */
        if (client_timestamp <= last_timestamp) return;

        /* If all is ok, update the last timestamp */
        last_timestamp = client_timestamp;
    }

    /* Handle the local ip address */
    {

    }
}
