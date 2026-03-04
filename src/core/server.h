#pragma once

#include "core/config.h"
#include "core/global.h"
#include "core/keys.h"
#include "core/tun.h"
#include "package/handshake_request.h"
#include "package/handshake_response.h"
#include "package/package_type.h"
#include "package/transfer_data.h"
#include "type/dictionary.h"
#include "type/linked_list.h"
#include "type/uniq_ptr.h"
#include "util/class.h"
#include "util/hkdf.h"
#include "util/logger.h"

#include <cstring>
#include <mutex>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <thread>

/**
 * Static class for server only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Server final {
public:
    PREVENT_INSTANTIATION(Server);

    inline static void SavePeer(const unsigned char* public_key);

    inline static void Init();

    inline static void RunHandlePackagesLoop();

    inline static void HandleTunPackage(const char* buffer,
                                        int package_size,
                                        unsigned int destimation_netb);

private:
    struct Peers {
        struct Details {
            Nonce nonce;
            sockaddr_in endpoint;
            unsigned char static_public_key[crypto_scalarmult_BYTES];
            unsigned char chain_key[crypto_aead_chacha20poly1305_KEYBYTES];
        } __attribute__((aligned(128)));

        static inline unsigned int number = 0;
        static inline LinkedList<const unsigned char*>* public_keys = nullptr;
        static inline std::mutex public_keys_mutex;
        static inline Dictionary<unsigned int,
                                 Details,
                                 unsigned int>* details = nullptr;
        static inline std::mutex details_mutex;
        static inline Dictionary<KeyBuffer,
                                 unsigned long,
                                 unsigned int>* timestamps = nullptr;
        static inline std::mutex timestamps_mutex;
        static inline Dictionary<sockaddr_in,
                                 UniqPtr<unsigned char[]>,
                                 unsigned int>* keys = nullptr;
        static inline std::mutex keys_mutex;
    };

    inline static void HandleHandshakeRequest(
        UniqPtr<HandshakeRequest> request,
        unsigned int request_size,
        sockaddr_in client
    );

    inline static void HandleTransferData(
        UniqPtr<TransferData> request,
        unsigned int request_size,
        sockaddr_in client
    ) noexcept;

    static inline std::mutex _rand_mutex;
};

inline void Server::SavePeer(const unsigned char* const public_key) {
    /* If the peers list isn't defined yet */
    std::lock_guard public_keys_lock(Peers::public_keys_mutex);
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

inline void Server::Init() {
    /* Allocate the memory for dictionaries */
    std::lock_guard peers_lock(Peers::details_mutex);
    Peers::details = new Dictionary<unsigned int,
                                  Peers::Details,
                                  unsigned int>(Peers::number);
    std::lock_guard timestamps_lock(Peers::timestamps_mutex);
    Peers::timestamps = new Dictionary<KeyBuffer,
                                       unsigned long,
                                       unsigned int>(Peers::number);
    std::lock_guard keys_lock(Peers::keys_mutex);
    Peers::keys = new Dictionary<sockaddr_in,
                                 UniqPtr<unsigned char[]>,
                                 unsigned int>(Peers::number);

    /* Fill timestamps dictionary with zeros */
    std::lock_guard public_keys_lock(Peers::public_keys_mutex);
    for (const unsigned char* public_key : *Peers::public_keys)
        Peers::timestamps->Put(public_key, 0UL);

    /* Add server to the peers list */
    Peers::details->Put(local_ip.netb, {});
}

inline void Server::HandleTunPackage(const char* const buffer,
                                     const int package_size,
                                     const unsigned int destimation_netb) {
}

inline void Server::RunHandlePackagesLoop() {
    /* Allocate the memory for the buffer */
    char* buffer = new char[(unsigned int)Config::Interface::mtu];

    /* Start receiving packages */
    for (;;) {
        /* Recieve the request from a client */
        sockaddr_in from;
        const int buffer_size = main_socket.Receive(buffer, &from);

        /* If there is an error */
        if (buffer_size == -1) continue;

        /* Get the type of the package */
        const unsigned char raw_type = *(const unsigned char*)buffer;
        if (raw_type > TRANSFER_DATA) return;
        const PackageType type = (PackageType)raw_type;

#undef COPY_BUFFER_TO_HEAP_AND_HANDLE_IT
#define COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(T)                                  \
        {                                                                     \
            T* request = new T(*(const T*)(const void*)buffer);               \
            std::thread(&Handle##T, request, buffer_size, from).detach();     \
            continue;                                                         \
        }

        /* Handle the package by its type */
        if (type == HANDSHAKE_REQUEST)
            if (buffer_size == sizeof(HandshakeRequest))
                COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(HandshakeRequest);
        if (type == TRANSFER_DATA)
                COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(TransferData);
    }
}

inline void Server::HandleHandshakeRequest(
    const UniqPtr<HandshakeRequest> request,
    const unsigned int request_size,
    const sockaddr_in client
) {
    INFO_LOG("Receive a handshake request from %s:%hu",
             inet_ntoa(client.sin_addr),
             ntohs(client.sin_port));

    /* Buffer for the chained key */
    UniqPtr<unsigned char[]> chain_key =
        new unsigned char[crypto_aead_chacha20poly1305_ietf_KEYBYTES];

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
        std::lock_guard public_keys_lock(Peers::public_keys_mutex);
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
        Peers::timestamps_mutex.lock();
        unsigned long& last_timestamp =
            Peers::timestamps->Get(request->payload.static_public_key);
        Peers::timestamps_mutex.unlock();

        /* Compare current timestamp with the last one */
        if (client_timestamp <= last_timestamp) return;

        /* If all is ok, update the last timestamp */
        last_timestamp = client_timestamp;
    }

    /* Variables for the response (default is data from the request) */
    unsigned int response_ip = request->payload.ip;
    unsigned char response_netmask = request->payload.netmask;

    /* Handle the local ip address and netmask */
    std::lock_guard peers_lock(Peers::details_mutex);
    {
        /* Get the passed ip and the netmask */
        const unsigned int client_ip = response_ip;
        const unsigned char client_netmask = response_netmask;

        /* Try to delete the peer with such a static key (if exists) */
        for (const auto& [local_ip, details] : *Peers::details)
            if (equal((KeyBuffer)details.static_public_key,
                      (KeyBuffer)request->payload.static_public_key))
                Peers::details->Delete(local_ip);

        /* If there already an ip address passed */
        if (client_ip != INADDR_ANY && client_netmask != 0) {
            /* If there is already an element with such a local ip,
             * reset the connection */
            if (Peers::details->Has(client_ip)) return;
        /* If the user decide to get ip by the server */
        } else {
            /* Set the server's netmask to the response */
            response_netmask = netmask;

            /* Try to get the random ip in the local network */
            const unsigned int start = network_prefix.hostb;
            const unsigned int end = broadcast.hostb;
            _rand_mutex.lock();
            const unsigned int random_ip =
                (unsigned int)(start + (rand() % (end - start + 1)));
            _rand_mutex.unlock();
            const unsigned int random_ip_netb = htonl(random_ip);
            if (!Peers::details->Has(random_ip_netb)) {
                response_ip = random_ip_netb;
                goto the_end;
            }

            /* Try to get the free ip */
            for (unsigned int ip = random_ip; ip < end; ++ip) {
                const unsigned int ip_netb = htonl(ip);
                if (!Peers::details->Has(ip_netb)) {
                    response_ip = ip_netb;
                    goto the_end;
                }
            }
            for (unsigned int ip = random_ip; ip > start; --ip) {
                const unsigned int ip_netb = htonl(ip);
                if (!Peers::details->Has(ip_netb)) {
                    response_ip = ip_netb;
                    goto the_end;
                }
            }

            /* If there is no free ips, reset the connection */
        the_end:
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
    Peers::Details details {
        .nonce = Nonce(request->header.nonce),
        .endpoint = client
    };
    memcpy(details.static_public_key,
           request->payload.static_public_key,
           crypto_scalarmult_BYTES);
    memcpy(details.chain_key,
           chain_key,
           crypto_aead_chacha20poly1305_KEYBYTES);
    Peers::details->Put(response_ip, details);

    /* Assemble the response */
    HandshakeResponse response(ephemeral_keys.Public(),
                               details.nonce,
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

    /* Save the peer's chain key */
    std::lock_guard keys_lock(Peers::keys_mutex);
    Peers::keys->Put(client, std::move(chain_key));
    chain_key.Release();
}

inline void Server::HandleTransferData(
    const UniqPtr<TransferData> request,
    const unsigned int request_size,
    const sockaddr_in client
) noexcept {
    TRACE_LOG("Recieve a transfer data from the %s:%hu",
              inet_ntoa(client.sin_addr),
              ntohs(client.sin_port));

    /* Try to decrypt the package */
    unsigned long long buffer_size;
    try {
        std::lock_guard keys_lock(Peers::keys_mutex);
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char*)(void*)&request->payload,
            &buffer_size,
            nullptr,
            (unsigned char*)(void*)&request->payload,
            request_size - sizeof(request->header),
            (unsigned char*)(void*)&request->header,
            sizeof(request->header),
            request->header.nonce,
            Peers::keys->Get(client).Get()
        ) != 0) {
            WARN_LOG("Forged message found");
            return;
        }
    } catch (const DictionaryError&) { return; }

    /* Get the destination IP address */
    const iphdr* const ip_header = (iphdr*)(void*)&request->payload;
    const unsigned int destination_netb = ip_header->daddr;

    /* If this package is our */
    if (destination_netb == local_ip.netb)
        tun->Write((char*)(void*)&request->payload,
                   (unsigned int)buffer_size);
    /* Else send it to the destination */
    else {
        /* TODO */
    }
}
