#include "server.h"
#include "core/global.h"
#include "core/keys.h"
#include "package/handshake_response.h"
#include "package/package_type.h"
#include "util/hkdf.h"
#include "util/logger.h"

#include <cstring>
#include <thread>

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
    /* Allocate the memory for dictionaries */
    Peers::peers = new Dictionary<unsigned int,
                                  Peers::Details,
                                  unsigned int>(Peers::number);
    Peers::timestamps = new Dictionary<KeyBuffer,
                                       unsigned long,
                                       unsigned int>(Peers::number);

    /* Fill timestamps dictionary with zeros */
    for (const unsigned char* public_key : *Peers::public_keys)
        Peers::timestamps->Put(public_key, 0UL);

    /* Add server to the peers list */
    Peers::peers->Put(ip_address, {});
}

void Server::HandlePackage(const char* const buffer, const int buffer_size,
                           const sockaddr_in& client) {
    /* Get the type of the package */
    const unsigned char raw_type = *(const unsigned char*)buffer;
    if (raw_type > TRANSFER_DATA) return;
    const PackageType type = (PackageType)raw_type;

    /* Handle the package by its type */
#define COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(T)                                  \
    {                                                                         \
        T* request = new T(*(const T*)(const void*)buffer);                   \
        if (buffer_size != sizeof(T)) return;                                 \
        std::thread(&Handle##T, request, client).detach();                    \
    }

    if (type == HANDSHAKE_REQUEST)
        COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(HandshakeRequest);
}

void Server::HandleHandshakeRequest(
    const UniqPtr<HandshakeRequest> request,
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

        /* Get the last timestamp for such a key */
        unsigned long& last_timestamp =
            Peers::timestamps->Get(request->payload.static_public_key);

        /* Compare current timestamp with the last one */
        if (client_timestamp <= last_timestamp) return;

        /* If all is ok, update the last timestamp */
        last_timestamp = client_timestamp;
    }

    /* Variables for the response (default is data from the request) */
    unsigned int response_ip = request->payload.ip;
    unsigned char response_netmask = request->payload.netmask;

    /* Handle the local ip address and netmask */
    {
        /* Get the passed ip and the netmask */
        const unsigned int client_ip = response_ip;
        const unsigned char client_netmask = response_netmask;

        /* TODO: try delete the peer with such a static key */

        /* If there already an ip address passed */
        if (client_ip != INADDR_ANY && client_netmask != 0) {
            /* If there is already an element with such a local ip,
             * reset the connection */
            if (Peers::peers->Has(client_ip)) return;
        /* If the user decide to get ip by the server */
        } else {
            /* Set the server's netmask to the response */
            response_netmask = netmask;

            /* Get the network and the broadcast addresses */
            const unsigned int binmask = (netmask == 0) ? 0x0U : (netmask == 32)
                                       ? 0xFFFFFFFFU : (~0U << (32U - netmask));
            const unsigned int network = htonl(ntohl(ip_address) & binmask);
            const unsigned int broadcast = network | htonl(~binmask);

            /* Try to find the free ip in the server's local network */
            const unsigned int start = ntohl(network);
            const unsigned int end = ntohl(broadcast);
            for (unsigned int ip = start + 1; ip < end; ++ip) {
                const unsigned int htonl_ip = htonl(ip);
                if (!Peers::peers->Has(htonl_ip)) {
                    response_ip = htonl_ip;
                    break;
                }
            }

            /* If there is no free ips, reset the connection */
            if (response_ip == INADDR_ANY) return;
        }
    }

    /* Generate the ephemeral keys pair */
    Keys ephemeral_keys;

    /* Compute the second shared secret and update the chain keys */
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          ephemeral_keys.Secret(),
                          request->header.ephemeral_public_key) == -1) {
        ERROR_LOG("crypto_scalarmult: Failed to compute the shared secret");
        return;
    }
    hkdf(chain_key, chain_key, shared);

    /* Compute the third shared secret and update the chain keys */
    if (crypto_scalarmult(shared,
                          ephemeral_keys.Secret(),
                          request->payload.static_public_key) == -1) {
        ERROR_LOG("crypto_scalarmult: Failed to compute the shared secret");
        return;
    }
    hkdf(chain_key, chain_key, shared);

    /* If all is OK, save the current peer */
    Peers::Details details { .endpoint = client };
    memcpy(details.static_public_key,
           request->payload.static_public_key,
           crypto_scalarmult_BYTES);
    memcpy(details.chain_key,
           chain_key,
           crypto_aead_chacha20poly1305_KEYBYTES);
    Peers::peers->Put(response_ip, details);

    /* Assemble the response */
    Nonce nonce(request->header.nonce);
    HandshakeResponse response(ephemeral_keys.Public(),
                               nonce,
                               response_ip,
                               response_netmask);

    /* Encrypt the resposne */
    unsigned long long dummy_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        (unsigned char*)(void*)&response.payload,
        &dummy_len,
        (unsigned char*)(void*)&response.payload,
        sizeof(response.payload),
        (unsigned char*)(void*)&response.header,
        sizeof(response.header),
        nullptr,
        response.header.nonce,
        chain_key
    );

    /* Send the response */
    main_socket.Send((const char*)(const void*)&response,
                     sizeof(HandshakeResponse),
                     client);
}
