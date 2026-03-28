#pragma once

#include "main.h"
#include "core/config.h"
#include "core/keys.h"
#include "core/tun.h"
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
        static inline uint32_t local_ip;
        static inline uint8_t* public_key = nullptr;
        static inline uint8_t* chain_key = nullptr;
        static inline UniqPtr<Keys> ephemeral_keys = nullptr;
        static inline std::mutex mutex;
    };

    struct Peers final {
        struct Details final {
            sockaddr_in endpoint;
            uint64_t last_to_package_timestamp;
            uint64_t last_from_package_timestamp;
            uint8_t chain_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
            uint8_t public_static_key[crypto_scalarmult_BYTES];
            UniqPtr<Nonce> nonce;
        } __attribute__((aligned(64)));

        static inline Dictionary<uint32_t,
                                 Details,
                                 uint8_t>* details = nullptr;
        static inline std::shared_mutex details_mutex;
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
}

FORCE_INLINE void Client::RunHandshakeLoop() {
    /* Send a handhake request */
    for (;;) {
        /* Check the timestamp */
        const uint64_t current_time = std::time(nullptr);
        if (current_time < _next_handshake_timestamp) {
            usleep((uint32_t)(_next_handshake_timestamp - current_time)
                   * 1'000'000);
            continue;
        }

        /* Lock the server */
        std::lock_guard server_lock(Server::mutex);
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
            Handle##T(package, (uint32_t)buffer_size, from);                  \
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
    /* Check last packages timestamps every 5 seconds */
    for (;;) {
        /* Sleep for 5 seconds */
        usleep(5 * 1'000'000);

        /* Get the current timestamp */
        uint64_t timestamp = Time::Nanoseconds();

        /* Send the keep alive package to the server */
        std::shared_lock details_lock(Peers::details_mutex);

        /* Check the last package timestamp */
        {
            Peers::Details* server_details;
            {
                std::lock_guard server_lock(Server::mutex);
                server_details = Peers::details->Get(Server::local_ip);
            }
            if (server_details == nullptr) continue;
            if (timestamp - server_details->last_to_package_timestamp >=
                10 * 1'000'000'000ULL) {
                /* Assemble the package and decrypt it */
                KeepAlive keep_alive(Server::nonce, timestamp);
                unsigned long long data_size;
                crypto_aead_chacha20poly1305_ietf_encrypt(
                    (uint8_t*)(void*)&keep_alive.data,
                    &data_size,
                    (uint8_t*)(void*)&keep_alive.data,
                    sizeof(keep_alive.data),
                    (uint8_t*)(void*)&keep_alive.header,
                    sizeof(keep_alive.header),
                    nullptr,
                    keep_alive.header.nonce,
                    server_details->chain_key
                );

                /* Send the keep-alive */
                INFO_LOG("Sending a keep-alive package to the server");
                main_socket.Send((const char*)(const void*)&keep_alive,
                                 sizeof(keep_alive),
                                 Server::endpoint);

                /* Update the last package timestamp */
                server_details->last_to_package_timestamp = timestamp;
            }
        }

        /* Send keep-alive packages to all the active peers */
        for (auto& [ _, peer_details ] : *Peers::details) {
            /* Check for server as relay */
            if (::equal(peer_details.endpoint, Server::endpoint)) continue;

            /* If the endpoint is no the server, check the last package time */
            if (timestamp - peer_details.last_to_package_timestamp <
                10 * 1'000'000'000ULL) continue;
            /* Assebmle the package and decrypt it */
            KeepAlive keep_alive(peer_details.nonce, timestamp);
            unsigned long long data_size;
            crypto_aead_chacha20poly1305_ietf_encrypt(
                (uint8_t*)(void*)&keep_alive.data,
                &data_size,
                (uint8_t*)(void*)&keep_alive.data,
                sizeof(keep_alive.data),
                (uint8_t*)(void*)&keep_alive.header,
                sizeof(keep_alive.header),
                nullptr,
                keep_alive.header.nonce,
                peer_details.chain_key
            );

            /* If all is OK, send the keep alive */
            TRACE_LOG("Sending a keep-alive package to the %s:%hu",
                      inet_ntoa(peer_details.endpoint.sin_addr),
                      ntohs(peer_details.endpoint.sin_port));
            main_socket.Send((const char*)(const void*)&keep_alive,
                             sizeof(keep_alive),
                             peer_details.endpoint);

            /* Update the last package timestamp */
            peer_details.last_to_package_timestamp = timestamp;
        }
    }
}

FORCE_INLINE void Client::HandleTunPackage(TransferData& package,
                                           const int32_t package_size,
                                           uint32_t destination_netb)
noexcept {
    /* Get the current timestamp */
    const uint64_t timestamp = Time::Nanoseconds();

    /* Try to get the details from the peers list */
    std::shared_lock details_lock(Peers::details_mutex);
    Peers::Details* peer_details = Peers::details->Get(destination_netb);

    /* If there is no such a peer, get the server peer */
    if (peer_details == nullptr) {
        /* Try to get the peer from the server
         * (If we didn't do that yet) */
        if ((destination_netb & binmask.Netb()) == network_prefix.Netb()) {
            //std::thread(GetPeerFromServer, destination_netb).detach();
        }

        /* Get the server peer */
        {
            std::lock_guard server_lock(Server::mutex);
            peer_details = Peers::details->Get(Server::local_ip);
            if (peer_details == nullptr) return;
            /* Set the destination ip */
            destination_netb = Server::local_ip;
        }
    }

    /* Update the package header */
    package.UpdateHeader(peer_details->nonce, destination_netb, timestamp);

    /* Update the last package timestamp */
    peer_details->last_to_package_timestamp = timestamp;

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
        peer_details->chain_key
    );

    /* Send the encrypted message */
    TRACE_LOG("Sending the transfer data package to the %s:%hu",
              inet_ntoa(peer_details->endpoint.sin_addr),
              ntohs(peer_details->endpoint.sin_port));
    main_socket.Send((char*)(void*)&package,
                     (int64_t)(sizeof(package.header) + data_size),
                     peer_details->endpoint);
}

FORCE_INLINE void Client::HandleHandshakeResponse(
    HandshakeResponse* const package,
    const uint32_t package_size,
    const sockaddr_in from
) noexcept {
    /* If this package is not from the server */
    std::lock_guard server_lock(Server::mutex);
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

    /* Save the server's local ip */
    Server::local_ip = package->data.server_local_ip;

    /* Add the server to the peers list */
    {
        /* Try to get the server from the peers dictionary */
        std::unique_lock details_lock(Peers::details_mutex);
        Peers::Details* const server_details =
            Peers::details->Get(Server::local_ip);

        /* If there is no server in the peers dictionary */
        if (server_details == nullptr) {
            /* Assemble the new details */
            Peers::Details details = {
                .endpoint = Server::endpoint,
                .last_to_package_timestamp = Time::Nanoseconds(),
                .nonce = Server::nonce
            };
            memcpy(details.chain_key, Server::chain_key,
                   crypto_aead_chacha20poly1305_ietf_KEYBYTES);

            /* Put the new data to the lists dictionary */
            Peers::details->Put(package->data.server_local_ip,
                                std::move(details));
        /* Otherwise, update the existing details */
        } else {
            server_details->nonce = Server::nonce;
            memcpy(server_details->chain_key, Server::chain_key,
                   crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        }
    }

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

    /* If all is OK, next handshake will be after 3 minutes */
    INFO_LOG("The handshake response has been successfully handled");
    _next_handshake_timestamp = (uint64_t)std::time(nullptr) + 180;
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
        peers_details->chain_key
    ) != 0) {
        WARN_LOG("Forged message found");
        return;
    }

    /* Write the package to the tun */
    tun->Write(package->data, (uint32_t)data_size);
}

FORCE_INLINE void Client::GetPeerFromServer(const uint32_t ip_netb)
noexcept { }
