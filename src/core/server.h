#pragma once

#include "main.h"
#include "core/keys.h"
#include "core/tun.h"
#include "package/handshake_request.h"
#include "package/handshake_response.h"
#include "package/package_type.h"
#include "package/transfer_data.h"
#include "socket/udp_socket.h"
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

/**
 * Static class for server only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Server final {
public:
    PREVENT_INSTANTIATION(Server);

    inline static void SavePeer(const unsigned char* public_key);

    inline static void Init();

    inline static void RunHandlePackagesLoop() noexcept;

    inline static void HandleTunPackage(const char* buffer,
                                        int buffer_size,
                                        unsigned int destination_netb) noexcept;

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
        HandshakeRequest* package,
        unsigned int package_size,
        sockaddr_in from
    );

    inline static void HandleTransferData(
        TransferData* package,
        unsigned int package_size,
        sockaddr_in from
    ) noexcept;
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
    /* Increase send and receive buffers */
    const int rcvbuf = 32 * 1024 * 1024 * (int)Peers::number;
    const int sndbuf = 32 * 1024 * 1024 * (int)Peers::number;
    main_socket.SetOption(SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    main_socket.SetOption(SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* Allocate the memory for dictionaries */
    std::lock_guard details_lock(Peers::details_mutex);
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
                                     const int buffer_size,
                                     const unsigned int destination_netb)
noexcept {
    /* Try to get the peers details */
    std::lock_guard details_lock(Peers::details_mutex);
    Peers::Details* const details = Peers::details->Get(destination_netb);
    if (details == nullptr) return;

    /* Create the response */
    TransferData package(details->nonce,
                         destination_netb,
                         buffer,
                         buffer_size);

    /* Encrypt the package */
    unsigned long long payload_size;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        (unsigned char*)(void*)&package.payload,
        &payload_size,
        (unsigned char*)(void*)&package.payload,
        (unsigned long long)buffer_size,
        (unsigned char*)(void*)&package.header,
        sizeof(package.header),
        nullptr,
        package.header.nonce,
        details->chain_key
    );

    /* Send the encrypted message */
    main_socket.Send((char*)(void*)&package,
                     sizeof(package.header) + payload_size,
                     details->endpoint);
}

inline void Server::RunHandlePackagesLoop() noexcept {
    /* Allocate the memory for the buffer */
    char buffer[UDPSocket::MTU];

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

#undef HANDLE_PACKAGE
#define HANDLE_PACKAGE(T)                                                     \
        {                                                                     \
            T* const package = (T*)(void*)buffer;                             \
            Handle##T(package, (unsigned int)buffer_size, from);              \
            continue;                                                         \
        }

        /* Handle the package by its type */
        if (type == HANDSHAKE_REQUEST)
            if (buffer_size == sizeof(HandshakeRequest))
                HANDLE_PACKAGE(HandshakeRequest);
        if (type == TRANSFER_DATA)
                HANDLE_PACKAGE(TransferData);
    }
}

inline void Server::HandleHandshakeRequest(
    HandshakeRequest* const package,
    const unsigned int package_size,
    const sockaddr_in from
) {
    INFO_LOG("Receive a handshake request from %s:%hu",
             inet_ntoa(from.sin_addr),
             ntohs(from.sin_port));

    /* Buffer for the chained key */
    UniqPtr<unsigned char[]> chain_key =
        new unsigned char[crypto_aead_chacha20poly1305_ietf_KEYBYTES];

    /* Decrypt the request payload */
    {
        /* Compute the first shared secret */
        unsigned char shared[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(shared,
                              static_keys->Secret(),
                              package->header.ephemeral_public_key) == -1) {
            ERROR_LOG("crypto_scalarmult: "
                      "Failed to compute the shared secret");
            return;
        }

        /* Get the chained ChaCha20 key */
        hkdf(chain_key, nullptr, shared);

        /* Decrypt the message */
        unsigned long long dummy_len;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char*)(void*)&package->payload,
            &dummy_len,
            nullptr,
            (unsigned char*)(void*)&package->payload,
            sizeof(package->payload) + sizeof(package->poly1305_tag),
            (unsigned char*)(void*)&package->header,
            sizeof(package->header),
            package->header.nonce,
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
            if (memcmp(package->payload.static_public_key,
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
        unsigned long client_timestamp = package->payload.timestamp;

        /* Get the delta time */
        unsigned long delta_time = current_time > client_timestamp
                                 ? current_time - client_timestamp
                                 : client_timestamp - current_time;

        /* If the time delta is too big */
        if (delta_time > 120) return;

        /* Get the last timestamp for such a key */
        Peers::timestamps_mutex.lock();
        unsigned long last_timestamp =
            *Peers::timestamps->Get(package->payload.static_public_key);
        Peers::timestamps_mutex.unlock();

        /* Compare current timestamp with the last one */
        if (client_timestamp <= last_timestamp) return;

        /* If all is ok, update the last timestamp */
        last_timestamp = client_timestamp;
    }

    /* Variables for the response (default is data from the request) */
    unsigned int response_ip = package->payload.ip;
    unsigned char response_netmask = package->payload.netmask;

    /* Handle the local ip address and netmask */
    {
        /* Get the passed ip and the netmask */
        const unsigned int client_ip = response_ip;
        const unsigned char client_netmask = response_netmask;

        /* Try to delete the peer with such a static key (if exists) */
        std::lock_guard details_lock(Peers::details_mutex);
        for (const auto& [ip, details] : *Peers::details)
            if (equal((KeyBuffer)details.static_public_key,
                      (KeyBuffer)package->payload.static_public_key))
                Peers::details->Delete(ip);

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
            const unsigned int random_ip =
                (unsigned int)(start + (rand() % (end - start + 1)));
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
                          package->header.ephemeral_public_key) == -1) {
        ERROR_LOG("crypto_scalarmult: Failed to compute the shared secret");
        return;
    }
    hkdf(chain_key, chain_key, shared);

    /* Compute the third shared secret and update the chain keys */
    if (crypto_scalarmult(shared,
                          ephemeral_keys.Secret(),
                          package->payload.static_public_key) == -1) {
        ERROR_LOG("crypto_scalarmult: Failed to compute the shared secret");
        return;
    }
    hkdf(chain_key, chain_key, shared);

    /* If all is OK, save the current peer */
    Peers::Details details {
        .nonce = Nonce(package->header.nonce),
        .endpoint = from
    };
    {
        std::lock_guard details_lock(Peers::details_mutex);
        memcpy(details.static_public_key,
               package->payload.static_public_key,
               crypto_scalarmult_BYTES);
        memcpy(details.chain_key,
               chain_key,
               crypto_aead_chacha20poly1305_KEYBYTES);
        Peers::details->Put(response_ip, details);
    }

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
    main_socket.Send((char*)(void*)&response,
                     sizeof(HandshakeResponse),
                     from);

    /* Save the peer's chain key */
    std::lock_guard keys_lock(Peers::keys_mutex);
    Peers::keys->Put(from, std::move(chain_key));
}

inline void Server::HandleTransferData(
    TransferData* const package,
    const unsigned int package_size,
    const sockaddr_in from
) noexcept {
    TRACE_LOG("Receive a transfer data from the %s:%hu",
              inet_ntoa(from.sin_addr),
              ntohs(from.sin_port));

    /* Get the destination IP address */
    const unsigned int destination_netb = package->header.destination_ip;

    /* If the pacakge isn't for the server, send it to the peer */
    if (destination_netb != local_ip.netb) {
        /* Try to get the peer endpoint */
        std::lock_guard details_lock(Peers::details_mutex);
        const Peers::Details* const peer_details =
            Peers::details->Get(destination_netb);
        if (peer_details == nullptr) return;

        /* Send the package to the peer */
        main_socket.Send((char*)(void*)package,
                         package_size,
                         peer_details->endpoint);
        return;
    }

    /* Try to get the key to decrypt the package */
    std::lock_guard keys_lock(Peers::keys_mutex);
    const UniqPtr<unsigned char[]>* const key = Peers::keys->Get(from);
    if (key == nullptr) return;

    /* Decrypt the package */
    unsigned long long buffer_size;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        (unsigned char*)(void*)&package->payload,
        &buffer_size,
        nullptr,
        (unsigned char*)(void*)&package->payload,
        package_size - sizeof(package->header),
        (unsigned char*)(void*)&package->header,
        sizeof(package->header),
        package->header.nonce,
        key->Get()
    ) != 0) {
        WARN_LOG("Forged message found");
        return;
    }

    /* Write the decrypted package to the TUN */
    tun->Write(package->payload.buffer, (unsigned int)buffer_size);
}
