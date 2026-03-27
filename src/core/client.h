#pragma once

#include "main.h"
#include "core/config.h"
#include "core/keys.h"
#include "core/tun.h"
#include "package/get_peer_request.h"
#include "package/handshake_request.h"
#include "package/handshake_response.h"
#include "package/keep_alive.h"
#include "package/transfer_data.h"
#include "socket/udp_socket.h"
#include "type/dictionary.h"
#include "type/uniq_ptr.h"
#include "util/class.h"
#include "util/equal.h"
#include "util/hkdf.h"
#include "util/logger.h"

#include <cstring>
#include <ctime>
#include <mutex>
#include <netinet/in.h>
#include <shared_mutex>
#include <sodium.h>
#include <thread>
#include <unistd.h>

/**
 * Static class for client only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Client final {
public:
    PREVENT_INSTANTIATION(Client);

    static void Init();

    static void RunHandshakeLoop();

    static void RunHandlePackagesLoop() noexcept;

    static void RunKeepAliveLoop() noexcept;

    static void HandleTunPackage(TransferData& package,
                                 int32_t package_size,
                                 uint32_t destination_netb) noexcept;

private:
    struct Server final {
        static inline Nonce* nonce;
        static inline sockaddr_in endpoint;
        static inline uint32_t local_ip_netb;
        static inline uint8_t* public_key = nullptr;
        static inline uint8_t* chain_key = nullptr;
        static inline UniqPtr<Keys> ephemeral_keys = nullptr;
        static inline std::mutex mutex;
    };

    struct Peers final {
        struct Details final {
            sockaddr_in endpoint;
            uint64_t last_package_timestamp;
            uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
            UniqPtr<Nonce> nonce;
        } __attribute__((aligned(64)));

        static inline Dictionary<uint32_t,
                                 Details,
                                 uint8_t>* details = nullptr;
        static inline std::shared_mutex details_mutex;
        static inline Dictionary<uint32_t,
                                 char,
                                 uint8_t>* hole_punching = nullptr;
        static inline std::mutex hole_punching_mutex;
    };

    static inline uint64_t _next_handshake_timestamp =
        (uint64_t)std::time(nullptr);

    static void HandleHandshakeResponse(
        HandshakeResponse* package,
        uint32_t package_size,
        sockaddr_in from
    ) noexcept;

    static void HandleTransferData(
        TransferData* package,
        uint32_t package_size,
        sockaddr_in from
    ) noexcept;

    static void GetPeerFromServer(uint32_t ip_netb) noexcept;
};

FORCE_INLINE void Client::Init() {
    /* Increase send and receive buffers */
    constexpr int32_t RCVBUF = 32 * 1024 * 1024;
    constexpr int32_t SNDBUF = 32 * 1024 * 1024;
    main_socket.SetOption(SO_RCVBUF, &RCVBUF, sizeof(RCVBUF));
    main_socket.SetOption(SO_SNDBUF, &SNDBUF, sizeof(SNDBUF));

    /* Get the address */
    Server::endpoint = UDPSocket::GetAddress(Config::Server::endpoint);

    /* Allocate memory for keys */
    Server::public_key =
        new uint8_t[crypto_scalarmult_BYTES];
    Server::chain_key =
        new uint8_t[crypto_aead_chacha20poly1305_ietf_KEYBYTES];

    /* Get the server's public key */
    const char* public_key_base64 = Config::Server::public_key;
    sodium_base642bin(Server::public_key, crypto_scalarmult_BYTES,
                      public_key_base64, strlen(public_key_base64),
                      nullptr, nullptr, nullptr,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Allocate memory for peers */
    Peers::details = new Dictionary<uint32_t,
                                    Peers::Details,
                                    uint8_t>(16);
    Peers::hole_punching = new Dictionary<uint32_t,
                                          char,
                                          uint8_t>(16);
}

FORCE_INLINE void Client::RunHandshakeLoop() {
    /* Send a handhake request */
    for (;;) {
        /* Check the timestamp */
        const uint64_t current_time = std::time(nullptr);
        if (current_time < _next_handshake_timestamp) {
            usleep((uint32_t)(_next_handshake_timestamp - current_time)
                   * 1000 * 1000);
            continue;
        }

        /* Lock the server */
        Server::mutex.unlock();
        Server::mutex.lock();
        INFO_LOG("Sending a handshake request to the server");

        /* Generate the ephemeral keys pair */
        Server::ephemeral_keys = new Keys();

        /* Initialize the nonce */
        Server::nonce = new Nonce();

        /* Fill the request */
        HandshakeRequest request(Server::ephemeral_keys->Public(),
                                 Server::nonce);

        /* Compute the first shared secret */
        uint8_t shared[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(shared,
                              Server::ephemeral_keys->Secret(),
                              Server::public_key) == -1) {
            ERROR_LOG("crypto_scalarmult: "
                      "Failed to compute the shared secret");
            continue;
        }

        /* Get the chained ChaCha20 key */
        hkdf(Server::chain_key, nullptr, shared);

        /* Crypt the data */
        unsigned long long dummy_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            (uint8_t*)(void*)&request.data,
            &dummy_len,
            (uint8_t*)(void*)&request.data,
            sizeof(request.data),
            (uint8_t*)(void*)&request.header,
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

FORCE_INLINE void Client::RunHandlePackagesLoop() noexcept {
    /* Allocate the memory for the buffer */
    char buffer[UDPSocket::MTU];

    /* Start receiving packages */
    for (;;) {
        /* Recieve the request from a client */
        sockaddr_in from;
        const int32_t buffer_size = main_socket.Receive(buffer, &from);

        /* If there is an error */
        if (buffer_size == -1) continue;

        /* Get the type of the package */
        const uint8_t raw_type = *(uint8_t*)buffer;
        if (raw_type > TRANSFER_DATA) return;
        const PackageType type = (PackageType)raw_type;

#undef HANDLE_PACKAGE
#define HANDLE_PACKAGE(T)                                                     \
        {                                                                     \
            T* const package = (T*)(void*)buffer;                             \
            Handle##T(package, (uint32_t)buffer_size, from);              \
            continue;                                                         \
        }

        /* Handle the package by its type */
        if (type == HANDSHAKE_RESPONSE)
            if (buffer_size == sizeof(HandshakeResponse)
                && equal(from, Server::endpoint))
                    HANDLE_PACKAGE(HandshakeResponse);
        if (type == TRANSFER_DATA)
            HANDLE_PACKAGE(TransferData);
    }
}

FORCE_INLINE void Client::RunKeepAliveLoop() noexcept {
    const KeepAlive keepalive_package;

    /* Send keep-alive package every 30 seconds */
    for (;;) {
        usleep(30 * 1000 * 1000);
        INFO_LOG("Send keep-alive package to the server");
        main_socket.Send((const char*)(const void*)&keepalive_package,
                         sizeof(keepalive_package),
                         Server::endpoint);
    }
}

FORCE_INLINE void Client::HandleTunPackage(TransferData& package,
                                           const int32_t package_size,
                                           uint32_t destination_netb)
noexcept {
    /* Init endpoint, key and nonce variables */
    sockaddr_in endpoint;
    const uint8_t* key;
    Nonce* nonce;

    {
        /* Try to get the details from the peers list */
        std::shared_lock details_lock(Peers::details_mutex);
        Peers::Details* const details = Peers::details->Get(destination_netb);

        /* If there is such and ip in the dictionary */
        if (details != nullptr) {
            endpoint = details->endpoint;
            key = details->key;
            nonce = details->nonce;
            /* If there is no such an ip in the dictionary */
        } else {
            /* Try to get the peer from the server
             * (If we didn't do that yet) */
            {
                std::lock_guard hole_punching_lock(Peers::hole_punching_mutex);
                if ((destination_netb & binmask.Netb()) ==
                    network_prefix.Netb() &&
                    !Peers::hole_punching->Has(destination_netb)) {
                    Peers::hole_punching->Put(destination_netb, -1);
                    std::thread(GetPeerFromServer, destination_netb).detach();
                }
            }

            endpoint = Server::endpoint;
            key = Server::chain_key;
            nonce = Server::nonce;
            destination_netb = Server::local_ip_netb;
        }
    }

    TRACE_LOG("Sending the transfer data to the %s:%hu",
              inet_ntoa(endpoint.sin_addr),
              ntohs(endpoint.sin_port));

    /* Update the package header */
    package.UpdateHeader(nonce, destination_netb);

    /* Encrypt the package */
    unsigned long long data_size;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        (uint8_t*)(void*)&package.data,
        &data_size,
        (uint8_t*)(void*)&package.data,
        (uint64_t)package_size,
        (uint8_t*)(void*)&package.header,
        sizeof(package.header),
        nullptr,
        package.header.nonce,
        key
    );

    /* Send the encrypted message */
    main_socket.Send((char*)(void*)&package,
                     (int64_t)(sizeof(package.header) + data_size),
                     endpoint);
}

FORCE_INLINE void Client::HandleHandshakeResponse(
    HandshakeResponse* const package,
    const uint32_t package_size,
    const sockaddr_in from
) noexcept {
    /* If this package is not from the server */
    if (!equal(from, Server::endpoint)) return;

    /* Compute the second shared secret and update the chain key */
    uint8_t shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          Server::ephemeral_keys->Secret(),
                          package->header.ephemeral_public_key) == -1) {
        ERROR_LOG("crypto_scalarmult: "
                  "Failed to compute the shared secret");
        return;
    }
    hkdf(Server::chain_key, Server::chain_key, shared);

    /* Compute the third shared secret and update the chain key */
    if (crypto_scalarmult(shared,
                          static_keys->Secret(),
                          package->header.ephemeral_public_key) == -1) {
        ERROR_LOG("crypto_scalarmult: "
                  "Failed to compute the shared secret");
        return;
    }
    hkdf(Server::chain_key, Server::chain_key, shared);

    /* Decrypt the data */
    unsigned long long dummy_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        (uint8_t*)(void*)&package->data,
        &dummy_len,
        nullptr,
        (uint8_t*)(void*)&package->data,
        sizeof(package->data) + sizeof(package->poly1305_tag),
        (uint8_t*)(void*)&package->header,
        sizeof(package->header),
        package->header.nonce,
        Server::chain_key
    ) != 0) {
        WARN_LOG("Forged message found");
        return;
    };

    /* If there is the first handshake */
    if (!tun->IsUp()) {
        /* Set the ip and the netmask */
        local_ip.SetNetb(package->data.local_ip);
        netmask = package->data.netmask;

        /* Calculate net-specific variables */
        calc_net();

        /* Up the interface */
        tun->Up();
    }

    /* Save the server's local ip */
    Server::local_ip_netb = package->data.server_local_ip;

    /* Add the server to the peers list */
    {
        /* Try to get the server from the peers dictionary */
        std::unique_lock details_lock(Peers::details_mutex);
        Peers::Details* const server_details =
            Peers::details->Get(package->data.server_local_ip);

        /* If there is no server in the peers dictionary */
        if (server_details == nullptr) {
            /* Assemble the new details */
            Peers::Details details = {
                .endpoint = Server::endpoint,
                .last_package_timestamp = ULONG_MAX,
                .nonce = Server::nonce
            };
            memcpy(details.key, Server::chain_key,
                   crypto_aead_chacha20poly1305_ietf_KEYBYTES);

            /* Put the new data to the lists dictionary */
            Peers::details->Put(package->data.server_local_ip,
                                std::move(details));
        /* Otherwise, update the existing details */
        } else {
            server_details->nonce = Server::nonce;
            memcpy(server_details->key, Server::chain_key,
                   crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        }
    }

    /* If all is OK, next handshake will be after 3 minutes */
    INFO_LOG("The handshake response has been successfully handled");
    _next_handshake_timestamp = (uint64_t)std::time(nullptr) + 180;
    Server::mutex.unlock();
}

FORCE_INLINE void Client::HandleTransferData(
    TransferData* const package,
    uint32_t package_size,
    sockaddr_in from
) noexcept {
    TRACE_LOG("Receive a transfer data from the %s:%hu",
              inet_ntoa(from.sin_addr),
              ntohs(from.sin_port));

    /* Get the key pointer */
    std::shared_lock details_lock(Peers::details_mutex);
    const Peers::Details* const peers_details =
        Peers::details->Get(package->header.source_ip);
    if (peers_details == nullptr) { return; }

    /* Try to decrypt the package */
    unsigned long long data_size;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        (uint8_t*)(void*)&package->data,
        &data_size,
        nullptr,
        (uint8_t*)(void*)&package->data,
        package_size - sizeof(package->header),
        (uint8_t*)(void*)&package->header,
        sizeof(package->header),
        package->header.nonce,
        peers_details->key
    ) != 0) {
        WARN_LOG("Forged message found");
        return;
    }

    /* Write the package to the tun */
    tun->Write(package->data, (uint32_t)data_size);
}

FORCE_INLINE void Client::GetPeerFromServer(const uint32_t ip_netb)
noexcept {
    std::unique_lock hole_punching_lock(Peers::hole_punching_mutex);
    do {
        /* Assemble the package */
        hole_punching_lock.unlock();
        std::unique_lock server_lock(Server::mutex);
        GetPeerRequest package(ip_netb, Server::nonce);

        /* Encrypt the package */
        unsigned long long data_size;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (uint8_t*)(void*)&package.data,
            &data_size,
            nullptr,
            (uint8_t*)(void*)&package.data,
            sizeof(ip_netb),
            (uint8_t*)(void*)&package.header,
            sizeof(package.header),
            package.header.nonce,
            Server::chain_key
        ) != 0) {
            WARN_LOG("Forged message found");
            return;
        }
        server_lock.unlock();

        /* Send the encrypted message */
        main_socket.Send((char*)(void*)&package,
                         (int64_t)(data_size + sizeof(package.header)),
                         Server::endpoint);

        /* Wait for 6 seconds and retry */
        usleep(6 * 1000 * 1000);
        hole_punching_lock.lock();
    } while (*Peers::hole_punching->Get(ip_netb) == -1);
}
