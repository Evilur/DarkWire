#pragma once

#include "main.h"
#include "core/config.h"
#include "core/keys.h"
#include "core/tun.h"
#include "package/get_peer_request.h"
#include "package/get_peer_response.h"
#include "package/handshake_request.h"
#include "package/handshake_response.h"
#include "package/keep_alive.h"
#include "package/nat_probe_request.h"
#include "package/nat_probe_response.h"
#include "package/p2p_handshake_request.h"
#include "package/p2p_handshake_response.h"
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
                                 uint32_t destination_ip) noexcept;

private:
    struct Server final {
        static inline sockaddr_in endpoint;
        static inline uint32_t local_ip;
        static inline uint8_t* public_key = nullptr;
        static inline uint8_t* chain_key = nullptr;
        static inline UniqPtr<Nonce> nonce = nullptr;
        static inline UniqPtr<Keys> ephemeral_keys = nullptr;
        static inline std::mutex mutex;
    };

    struct Peers final {
        struct Details final {
            sockaddr_in endpoint;
            uint64_t last_from_package_timestamp;
            uint64_t last_to_package_timestamp;
            uint64_t next_handshake_timestamp;
            uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
            uint8_t public_static_key[crypto_scalarmult_BYTES];
            UniqPtr<Nonce> nonce;
        } __attribute__((aligned(128)));

        struct TempDetails final {
            sockaddr_in endpoint;
            uint8_t public_static_key[crypto_scalarmult_BYTES];
            uint8_t chain_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
            UniqPtr<Nonce> nonce = nullptr;
            UniqPtr<Keys> ephemeral_keys = nullptr;
            bool waiting_get_peer;
            bool waiting_handshake_response;
            bool waiting_nat_probe;
        } __attribute__((aligned(128)));

        static inline Dictionary<uint32_t, Details, uint8_t>*
            details = nullptr;
        static inline std::shared_mutex details_mutex;
        static inline Dictionary<uint32_t, TempDetails, uint8_t>*
            temp_details = nullptr;
        static inline std::shared_mutex temp_details_mutex;
    };

    static inline uint64_t _next_handshake_timestamp =
        (uint64_t)std::time(nullptr);

    static void HandleHandshakeResponse(
        HandshakeResponse* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;

    static void HandleTransferData(
        TransferData* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;

    static void HandleGetPeerResponse(
        GetPeerResponse* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;

    static void HandleP2PHandshakeRequest(
        P2PHandshakeRequest* package,
        uint32_t package_size,
        const sockaddr_in& from
    );

    static void HandleP2PHandshakeResponse(
        P2PHandshakeResponse* package,
        uint32_t package_size,
        const sockaddr_in& from
    );

    static void HandleNatProbeRequest(
        NatProbeRequest* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;

    static void HandleNatProbeResponse(
        NatProbeResponse* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;

    static void GetPeerFromServer(uint32_t peer_ip) noexcept;

    static void SendP2PHandshakeRequest(uint32_t peer_ip, bool nat_probe);

    static void NatProbe(uint32_t peer_ip, sockaddr_in real_endpoint);
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
    Peers::details =
        new Dictionary<uint32_t, Peers::Details, uint8_t>(16);
    Peers::temp_details =
        new Dictionary<uint32_t, Peers::TempDetails, uint8_t>(16);
}

FORCE_INLINE void Client::RunHandshakeLoop() {
    /* Send a handshake request */
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
        INFO_LOG("Sending the handshake request to the server");

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
            WARN_LOG("crypto_scalarmult: "
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
        if (type == TRANSFER_DATA)
            HANDLE_PACKAGE(TransferData);
        if (type == HANDSHAKE_RESPONSE &&
            buffer_size == sizeof(HandshakeResponse) &&
            equal(from, Server::endpoint))
            HANDLE_PACKAGE(HandshakeResponse);
        if (type == P2P_HANDSHAKE_REQUEST &&
            buffer_size == sizeof(P2PHandshakeRequest))
            HANDLE_PACKAGE(P2PHandshakeRequest);
        if (type == P2P_HANDSHAKE_RESPONSE &&
            buffer_size == sizeof(P2PHandshakeResponse))
            HANDLE_PACKAGE(P2PHandshakeResponse);
        if (type == NAT_PROBE_REQUEST &&
            buffer_size == sizeof(NatProbeRequest))
            HANDLE_PACKAGE(NatProbeRequest);
        if (type == NAT_PROBE_RESPONSE &&
            buffer_size == sizeof(NatProbeResponse) &&
            equal(from, Server::endpoint))
            HANDLE_PACKAGE(NatProbeResponse);
        if (type == GET_PEER_RESPONSE &&
            buffer_size == sizeof(GetPeerResponse) &&
            equal(from, Server::endpoint))
            HANDLE_PACKAGE(GetPeerResponse);
    }
}

FORCE_INLINE void Client::RunKeepAliveLoop() noexcept {
    /* A function to send the keep-alives to the peer */
    void (*const send_keepalive)(Peers::Details*, uint64_t timestamp) =
        [](Peers::Details* const peer_details, const uint64_t timestamp) {
        /* Assemble the package */
        KeepAlive package(peer_details->nonce, timestamp);

        /* Sign the package */
        {
            unsigned long long dummy_len;
            crypto_aead_chacha20poly1305_ietf_encrypt(
                package.poly1305_tag,
                &dummy_len,
                nullptr,
                0,
                (uint8_t*)(void*)&package.header,
                sizeof(package.header),
                nullptr,
                package.header.nonce,
                peer_details->key
            );
        }

        /* Update the last package timestamp */
        peer_details->last_to_package_timestamp = timestamp;

        /* Send the package */
        main_socket.Send((char*)(void*)&package,
                         sizeof(package),
                         peer_details->endpoint);
    };

    /* Send keep-alives every 10 seconds */
    constexpr uint64_t keepalive = 10 * 1'000'000'000ULL;
    uint64_t next_keepalive_timestamp = Time::Nanoseconds() + keepalive;
    for (;;) {
        /* Wait for the next keep-alive timestamp */
        Time::NanoWaitUntil(next_keepalive_timestamp);

        /* Get the current timestamp */
        const uint64_t timestamp = Time::Nanoseconds();

        /* Get the server's details */
        std::shared_lock details_lock(Peers::details_mutex);
        Peers::Details* const server_details =
            Peers::details->Get(Server::local_ip);
        if (server_details == nullptr) {
            next_keepalive_timestamp =
                timestamp + (6 * 1'000'000'000ULL);
            continue;
        }

        /* Send the keep-alive */
        if (timestamp - server_details->last_to_package_timestamp >=
            keepalive) {
            TRACE_LOG("Sending a keep-alive to the server");
            send_keepalive(server_details, timestamp);
        }

        /* Set the server's last package timestamp as the oldest one */
        uint64_t oldest_timestamp = server_details->last_to_package_timestamp;

        /* Loop through all the peers */
        for (auto& [ _, peer_details ] : *Peers::details) {
            /* If we use the server as relay */
            if (equal(peer_details.endpoint, Server::endpoint)) continue;

            /* Send the keep-alive */
            if (timestamp - peer_details.last_to_package_timestamp >=
                keepalive) {
                TRACE_LOG("Sending a keep-alive to the %s:%hu",
                          inet_ntoa(peer_details.endpoint.sin_addr),
                          ntohs(peer_details.endpoint.sin_port));
                send_keepalive(&peer_details, timestamp);
            }

            /* Update the oldest timestamp */
            if (peer_details.last_to_package_timestamp < oldest_timestamp)
                oldest_timestamp = peer_details.last_to_package_timestamp;
        }

        /* Update the next keep-alive according to the oldest timestamp */
        next_keepalive_timestamp = oldest_timestamp + keepalive;
    }
}

FORCE_INLINE void Client::HandleTunPackage(TransferData& package,
                                           const int32_t package_size,
                                           uint32_t destination_ip)
noexcept {
    /* Get the current timestamp */
    const uint64_t timestamp = Time::Nanoseconds();

    /* Try to get the details from the peers list */
    std::shared_lock details_lock(Peers::details_mutex);
    Peers::Details* peer_details = Peers::details->Get(destination_ip);

    /* If there is no such a peer, get the server peer */
    if (peer_details == nullptr) {
        /* Try to get the peer from the server
         * (If we didn't do that yet) */
        {
            std::shared_lock temp_details_lock(Peers::temp_details_mutex);
            if ((destination_ip & binmask.Netb()) == network_prefix.Netb() &&
                !Peers::temp_details->Has(destination_ip)) {
                std::thread(GetPeerFromServer, destination_ip).detach();
            }
        }

        /* Get the server peer */
        peer_details = Peers::details->Get(Server::local_ip);
        if (peer_details == nullptr) return;

        /* Set the destination ip */
        destination_ip = Server::local_ip;
    }

    /* Update the last to package timestamp */
    peer_details->last_to_package_timestamp = timestamp;

    /* Update the package header */
    package.UpdateHeader(peer_details->nonce, destination_ip, timestamp);

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
        peer_details->key
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
    const sockaddr_in& from
) noexcept {
    /* If this package is not from the server */
    std::lock_guard server_lock(Server::mutex);

    /* Compute the second shared secret and update the chain key */
    uint8_t shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          Server::ephemeral_keys->Secret(),
                          package->header.ephemeral_public_key) == -1) {
        WARN_LOG("crypto_scalarmult: "
                 "Failed to compute the shared secret");
        return;
    }
    hkdf(Server::chain_key, Server::chain_key, shared);

    /* Compute the third shared secret and update the chain key */
    if (crypto_scalarmult(shared,
                          static_keys->Secret(),
                          package->header.ephemeral_public_key) == -1) {
        WARN_LOG("crypto_scalarmult: "
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
                .nonce = Server::nonce.Get()
            };
            memcpy(details.key, Server::chain_key,
                   crypto_aead_chacha20poly1305_ietf_KEYBYTES);

            /* Put the new data to the dictionary */
            Peers::details->Put(package->data.server_local_ip,
                                std::move(details));
        /* Otherwise, update the existing details */
        } else {
            server_details->nonce = Server::nonce.Get();
            memcpy(server_details->key, Server::chain_key,
                   crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        }

        /* Release the server nonce */
        Server::nonce.Release();
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
    const uint32_t package_size,
    const sockaddr_in& from
) noexcept {
    TRACE_LOG("Receive a transfer data from the %s:%hu",
              inet_ntoa(from.sin_addr),
              ntohs(from.sin_port));

    /* Get the key pointer */
    std::shared_lock details_lock(Peers::details_mutex);
    Peers::Details* const peers_details =
        Peers::details->Get(package->header.source_ip);
    if (peers_details == nullptr) { return; }

    /* Get the package timestamp */
    const uint64_t package_timestamp = package->header.timestamp;

    /* Check the package for duplicate */
    if (package_timestamp <= peers_details->last_from_package_timestamp) {
        WARN_LOG("Duplicate message found");
        return;
    }

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

    /* If all is OK, update the timestamp */
    peers_details->last_from_package_timestamp = package_timestamp;

    /* Write the package to the tun */
    tun->Write(package->data, (uint32_t)data_size);
}

FORCE_INLINE void Client::HandleGetPeerResponse(
    GetPeerResponse* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) noexcept {
    INFO_LOG("Receive a get peer response");

    /* Decrypt the package */
    {
        std::lock_guard server_lock(Server::mutex);
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
    }

    /* Save the peer ip */
    const uint32_t peer_ip = package->data.local_ip;

    /* Try remove the entry if there is no such a peer
     * And exit the method */
    std::unique_lock temp_details_lock(Peers::temp_details_mutex);
    if (package->data.real_ip == INADDR_ANY) {
        Peers::temp_details->Delete(peer_ip);
        return;
    }

    /* Try to get the peer from the temp details dict */
    Peers::TempDetails* peer_temp_details = Peers::temp_details->Get(peer_ip);

    /* Assemble the new endpoint */
    const sockaddr_in new_endpoint = {
        .sin_family = AF_INET,
        .sin_port = package->data.real_port,
        .sin_addr = { package->data.real_ip }
    };

    /* If there is no such a peer in the dictionary yet */
    if (peer_temp_details == nullptr) {
        /* Put the new details to the dictionary */
        Peers::TempDetails new_details = {
            .endpoint = new_endpoint,
            .nonce = nullptr,
            .ephemeral_keys = nullptr,
            .waiting_get_peer = false,
            .waiting_handshake_response = false
        };
        memcpy(new_details.public_static_key,
               package->data.public_key,
               crypto_scalarmult_BYTES);
        Peers::temp_details->Put(peer_ip, std::move(new_details));
        peer_temp_details = Peers::temp_details->Get(peer_ip);
    } else {
        /* Update fields */
        peer_temp_details->endpoint = new_endpoint;
        peer_temp_details->waiting_get_peer = false;
        memcpy(peer_temp_details->public_static_key,
               package->data.public_key,
               crypto_scalarmult_BYTES);
    }

    /* The client with the biggest static key must initialize the handshake */
    if (KeyBuffer(static_keys->Public()) <
        KeyBuffer(package->data.public_key)) return;

    /* If all is OK, send the handshake to the peer */
    std::thread(SendP2PHandshakeRequest, peer_ip, true).detach();
}

FORCE_INLINE void Client::HandleP2PHandshakeRequest(
    P2PHandshakeRequest* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) {
    INFO_LOG("Receive a handshake request from the %s peer%s",
             inet_ntoa({ package->header.source_ip }),
             equal(Server::endpoint, from) ?
             " via the server" : "");

    /* Get the peer ip from the package */
    const uint32_t peer_ip = package->header.source_ip;

    /* Try to get the permanent peer details */
    std::unique_lock details_lock(Peers::details_mutex);
    Peers::Details* peer_details = Peers::details->Get(peer_ip);

    /* Try to get the temporary peer details */
    std::unique_lock temp_details_lock(Peers::temp_details_mutex);
    Peers::TempDetails*  peer_temp_details = Peers::temp_details->Get(peer_ip);

    /* If we know about the peer nothing */
    if (peer_details == nullptr && peer_temp_details == nullptr) return;

    /* Get the current timestamp and the package one */
    const uint64_t timestamp = Time::Nanoseconds();
    const uint64_t package_timestamp = package->header.timestamp;

    /* Check the package timestamps delta */
    if (Time::Delta(package_timestamp, timestamp) >
        180 * 1'000'000'000ULL) {
        WARN_LOG("Invalid timestamp found");
        return;
    }

    /* Compare the last peer timestamp and the package timestamp */
    if (peer_details != nullptr &&
        package_timestamp <= peer_details->last_from_package_timestamp) {
        WARN_LOG("Duplicate message found");
        return;
    }

    /* Init the chain key */
    uint8_t chain_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];

    /* Compute the first shared secret */
    uint8_t shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          static_keys->Secret(),
                          package->header.ephemeral_public_key) == -1) {
        WARN_LOG("crypto_scalarmult: "
                 "Failed to compute the shared secret");
        return;
    }

    /* Get the chained ChaCha20 key */
    hkdf(chain_key, nullptr, shared);

    /* Check the package sign */
    unsigned long long dummy_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        package->poly1305_tag,
        &dummy_len,
        nullptr,
        package->poly1305_tag,
        sizeof(package->poly1305_tag),
        (uint8_t*)(void*)&package->header,
        sizeof(package->header),
        package->header.nonce,
        chain_key
    ) != 0) {
        WARN_LOG("Forged message found");
        return;
    };

    /* Save the current peer */
    if (peer_details == nullptr) {
        /* If we have not enough information about the peer */
        if (peer_temp_details == nullptr) {
            WARN_LOG("Can't save peer: "
                     "Have not enough info");
            return;
        }

        /* If all is OK */
        Peers::details->Put(peer_ip, {
            .endpoint = peer_temp_details->endpoint,
            .last_from_package_timestamp = package->header.timestamp,
            .nonce = new Nonce(package->header.nonce)
        });

        /* Update the peer details */
        peer_details = Peers::details->Get(peer_ip);
        memcpy(peer_details->public_static_key,
               peer_temp_details->public_static_key,
               crypto_scalarmult_BYTES);
    /* If we already have the peer details, just update them */
    } else {
        if (peer_temp_details != nullptr) {
            peer_details->endpoint = peer_temp_details->endpoint;
            memcpy(peer_details->public_static_key,
                   peer_temp_details->public_static_key,
                   crypto_scalarmult_BYTES);
        }
        peer_details->last_from_package_timestamp =
            package->header.timestamp;
        peer_details->nonce = new Nonce(package->header.nonce);
    }

    /* Generate the ephemeral keys pair */
    const Keys ephemeral_keys;

    /* Compute the second shared secret and update the chain keys */
    if (crypto_scalarmult(shared,
                          ephemeral_keys.Secret(),
                          package->header.ephemeral_public_key) == -1) {
        WARN_LOG("crypto_scalarmult: "
                 "Failed to compute the shared secret");
        return;
    }
    hkdf(chain_key, chain_key, shared);

    /* Compute the third shared secret and update the chain keys */
    if (crypto_scalarmult(shared,
                          ephemeral_keys.Secret(),
                          peer_details->public_static_key) == -1) {
        WARN_LOG("crypto_scalarmult: "
                 "Failed to compute the shared secret");
        return;
    }
    hkdf(chain_key, chain_key, shared);

    /* Update the peer's key */
    memcpy(peer_details->key,
           chain_key,
           crypto_aead_chacha20poly1305_ietf_KEYBYTES);

    /* Assemble the resposne */
    P2PHandshakeResponse response(peer_details->nonce,
                                  ephemeral_keys.Public(),
                                  timestamp,
                                  peer_ip,
                                  package->header.nat_probe);

    /* Sign the response package */
    {
        unsigned long long dummy_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            response.poly1305_tag,
            &dummy_len,
            nullptr,
            0,
            (uint8_t*)(void*)&response.header,
            sizeof(response.header),
            nullptr,
            response.header.nonce,
            peer_details->key
        );
    }

    /* Send the encrypted package */
    INFO_LOG("Sending the handshake resposne to %s peer%s",
             inet_ntoa({ peer_ip }),
             package->header.nat_probe ?
             " via the server" : "");
    main_socket.Send((char*)(void*)&response,
                     sizeof(response),
                     package->header.nat_probe ?
                     Server::endpoint : peer_details->endpoint);

    /* If we need to probe the nat type */
    if (package->header.nat_probe) {
        /* Save the real endpoint */
        const sockaddr_in real_endpoint = peer_details->endpoint;

        /* Temporary send all the data throught the relay */
        peer_details->endpoint = Server::endpoint;

        /* Start the nat probing */
        std::thread(NatProbe, peer_ip, real_endpoint).detach();
    /* Remove the temporary entry */
    } else Peers::temp_details->Delete(peer_ip);
}

FORCE_INLINE void Client::HandleP2PHandshakeResponse(
    P2PHandshakeResponse* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) {
    INFO_LOG("Receive a handshake response from the %s peer%s",
             inet_ntoa({ package->header.source_ip }),
             equal(Server::endpoint, from) ?
             " via the server" : "");

    /* Get the peer ip */
    const uint32_t peer_ip = package->header.source_ip;

    /* Try to get temp details */
    std::unique_lock temp_details_lock(Peers::temp_details_mutex);
    Peers::TempDetails* const peer_temp_details =
        Peers::temp_details->Get(peer_ip);
    if (peer_temp_details == nullptr) return;

    /* Try to get permanent details */
    std::unique_lock details_lock(Peers::details_mutex);
    Peers::Details* peer_details = Peers::details->Get(peer_ip);

    /* Get the current timestamp and the package one */
    const uint64_t timestamp = Time::Nanoseconds();
    const uint64_t package_timestamp = package->header.timestamp;

    /* Check the package timestamp */
    if (Time::Delta(package_timestamp, timestamp) >
        180 * 1'000'000'000ULL) {
        WARN_LOG("Invalid timestamp found");
        return;
    }

    /* Compare the last peer timestamp and the package timestamp */
    if (peer_details != nullptr &&
        package_timestamp <= peer_details->last_from_package_timestamp) {
        WARN_LOG("Duplicate message found");
        return;
    }

    /* If all is OK, get the chain key */
    uint8_t chain_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    memcpy(chain_key,
           peer_temp_details->chain_key,
           crypto_aead_chacha20poly1305_ietf_KEYBYTES);

    /* Compute the second shared secret and update the chain keys */
    uint8_t shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          peer_temp_details->ephemeral_keys->Secret(),
                          package->header.ephemeral_public_key) == -1) {
        WARN_LOG("crypto_scalarmult: "
                 "Failed to compute the shared secret");
        return;
    }
    hkdf(chain_key, chain_key, shared);

    /* Compute the third shared secret and update the chain keys */
    if (crypto_scalarmult(shared,
                          static_keys->Secret(),
                          package->header.ephemeral_public_key) == -1) {
        WARN_LOG("crypto_scalarmult: "
                 "Failed to compute the shared secret");
        return;
    }
    hkdf(chain_key, chain_key, shared);

    /* Try to check the sign of the package */
    {
        unsigned long long dummy_len;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
            package->poly1305_tag,
            &dummy_len,
            nullptr,
            package->poly1305_tag,
            sizeof(package->poly1305_tag),
            (uint8_t*)(void*)&package->header,
            sizeof(package->header),
            package->header.nonce,
            chain_key
        ) != 0) {
            WARN_LOG("Forged message found");
            return;
        }
    }

    /* Save the peer to the permanent details dict */
    if (peer_details == nullptr) {
        Peers::Details new_details = {
            .endpoint = peer_temp_details->endpoint,
            .last_from_package_timestamp = package_timestamp,
            .next_handshake_timestamp = timestamp + (180 * 1'000'000'000ULL),
            .nonce = peer_temp_details->nonce.Get()
        };
        memcpy(new_details.key,
               chain_key,
               crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        memcpy(new_details.public_static_key,
               peer_temp_details->public_static_key,
               crypto_scalarmult_BYTES);
        Peers::details->Put(peer_ip, std::move(new_details));
        peer_details = Peers::details->Get(peer_ip);
    /* If it is already exists, just update the fields */
    } else {
        *peer_details = {
            .endpoint = peer_temp_details->endpoint,
            .last_from_package_timestamp = package_timestamp,
            .next_handshake_timestamp = timestamp + (180 * 1'000'000'000ULL),
            .nonce = peer_temp_details->nonce.Get()
        };
        memcpy(peer_details->key,
               chain_key,
               crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        memcpy(peer_details->public_static_key,
               peer_temp_details->public_static_key,
               crypto_scalarmult_BYTES);
    }

    /* Release the old nonce */
    peer_temp_details->nonce.Release();

    INFO_LOG("The handshake from the %s peer has been successfully handled",
             inet_ntoa({ peer_ip }));

    /* If we need to probe the nat type */
    if (package->header.nat_probe) {
        /* Save the real endpoint */
        const sockaddr_in real_endpoint = peer_details->endpoint;

        /* Temporary send all the data throught the relay */
        peer_details->endpoint = Server::endpoint;

        /* Start the nat probing */
        std::thread(NatProbe, peer_ip, real_endpoint).detach();
    /* Remove the temp entry */
    } else Peers::temp_details->Delete(peer_ip);
}

FORCE_INLINE void Client::HandleNatProbeRequest(
    NatProbeRequest* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) noexcept {
    TRACE_LOG("Receive a nat probe request package from the %s peer",
              inet_ntoa({ package->header.source_ip }));

    /* Get the peer ip from the package */
    const uint32_t peer_ip = package->header.source_ip;

    /* Get the current timestamp and the package one */
    const uint64_t timestamp = Time::Nanoseconds();
    const uint64_t package_timestamp = package->header.timestamp;

    /* Try to get the peer details */
    std::shared_lock details_lock(Peers::details_mutex);
    Peers::Details* const peer_details =
        Peers::details->Get(peer_ip);
    if (peer_details == nullptr) return;


    /* Check the package timestamp */
    if (Time::Delta(package_timestamp, timestamp) >
        180 * 1'000'000'000ULL) {
        WARN_LOG("Invalid timestamp found");
        return;
    }

    /* Compare the last peer timestamp and the package timestamp */
    if (package_timestamp <= peer_details->last_from_package_timestamp) {
        WARN_LOG("Duplicate message found");
        return;
    }

    /* Try to check the sign of the package */
    {
        unsigned long long dummy_len;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
            package->poly1305_tag,
            &dummy_len,
            nullptr,
            package->poly1305_tag,
            sizeof(package->poly1305_tag),
            (uint8_t*)(void*)&package->header,
            sizeof(package->header),
            package->header.nonce,
            peer_details->key
        ) != 0) {
            WARN_LOG("Forged message found");
            return;
        }
    }

    /* Assemble the response */
    NatProbeResponse response(peer_details->nonce, peer_ip, timestamp);

    /* Sign the response package */
    {
        unsigned long long dummy_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            response.poly1305_tag,
            &dummy_len,
            nullptr,
            0,
            (uint8_t*)(void*)&response.header,
            sizeof(response.header),
            nullptr,
            response.header.nonce,
            peer_details->key
        );
    }

    /* Send the package via the relay server */
    TRACE_LOG("Sending a nat probe response to the %s peer via the server",
              inet_ntoa({ peer_ip }));
    main_socket.Send((char*)(void*)&response,
                     sizeof(response),
                     Server::endpoint);
}

FORCE_INLINE void Client::HandleNatProbeResponse(
    NatProbeResponse* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) noexcept {
    TRACE_LOG("Receive a nat probe response package from the %s peer "
              "via the server",
              inet_ntoa({ package->header.source_ip }));

    /* Get the peer ip from the package */
    const uint32_t peer_ip = package->header.source_ip;

    /* Get the current timestamp and the package one */
    const uint64_t timestamp = Time::Nanoseconds();
    const uint64_t package_timestamp = package->header.timestamp;

    /* Try to get the peer temp details */
    std::unique_lock temp_details_lock(Peers::temp_details_mutex);
    Peers::TempDetails* const peer_temp_details =
        Peers::temp_details->Get(peer_ip);
    if (peer_temp_details == nullptr) {
        TRACE_LOG("Failed to handle the nat probe response from the %s peer: "
                  "have not enough infomation",
                  inet_ntoa({ peer_ip }));
        return;
    }

    /* Try to get the peer details */
    std::unique_lock details_lock(Peers::details_mutex);
    Peers::Details* const peer_details =
        Peers::details->Get(peer_ip);
    if (peer_temp_details == nullptr) {
        TRACE_LOG("Failed to handle the nat probe response from the %s peer: "
                  "have not enough infomation",
                  inet_ntoa({ peer_ip }));
        return;
    }

    /* Check the package timestamp */
    if (Time::Delta(package_timestamp, timestamp) >
        180 * 1'000'000'000ULL) {
        WARN_LOG("Invalid timestamp found");
        return;
    }

    /* Compare the last peer timestamp and the package timestamp */
    if (peer_details != nullptr &&
        package_timestamp <= peer_details->last_from_package_timestamp) {
        WARN_LOG("Duplicate message found");
        return;
    }

    /* Try to check the sign of the package */
    {
        unsigned long long dummy_len;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
            package->poly1305_tag,
            &dummy_len,
            nullptr,
            package->poly1305_tag,
            sizeof(package->poly1305_tag),
            (uint8_t*)(void*)&package->header,
            sizeof(package->header),
            package->header.nonce,
            peer_details->key
        ) != 0) {
            WARN_LOG("Forged message found");
            return;
        }
    }

    /* If all is OK, update the endpoint in the permanent details */
    peer_details->endpoint = peer_temp_details->endpoint;

    /* Remove the temporary entry */
    Peers::temp_details->Delete(peer_ip);
    INFO_LOG("Direct channel to the %s peer is available",
             inet_ntoa({ peer_ip }));
}

FORCE_INLINE void Client::GetPeerFromServer(const uint32_t peer_ip)
noexcept {
    /* Now we are waiting for the peer */
    {
        std::unique_lock temp_details_lock(Peers::temp_details_mutex);
        Peers::temp_details->Put(peer_ip, { .waiting_get_peer = true });
    }

    std::shared_lock temp_details_lock(Peers::temp_details_mutex);
    Peers::TempDetails* peer_temp_details = nullptr;
    do {
        temp_details_lock.unlock();

        /* Assemble the response package */
        std::shared_lock details_lock(Peers::details_mutex);
        Peers::Details* server_details =
            Peers::details->Get(Server::local_ip);
        if (server_details == nullptr) { usleep(6 * 1'000'000); continue; }
        GetPeerRequest package(server_details->nonce, peer_ip);
        details_lock.unlock();

        /* Encrypt the package */
        {
            std::lock_guard server_mutex(Server::mutex);
            unsigned long long dummy_len;
            crypto_aead_chacha20poly1305_ietf_encrypt(
                (uint8_t*)(void*)&package.data,
                &dummy_len,
                (uint8_t*)(void*)&package.data,
                sizeof(package.data),
                (uint8_t*)(void*)&package.header,
                sizeof(package.header),
                nullptr,
                package.header.nonce,
                Server::chain_key
            );

            /* Send the package to the server */
            INFO_LOG("Sending the get '%s' peer package",
                     inet_ntoa({ peer_ip }));
            main_socket.Send((char*)(void*)&package,
                             sizeof(package),
                             Server::endpoint);
        }

        /* Wait for 6 seconds */
        usleep(6 * 1'000'000);

        /* Get the temp details */
        temp_details_lock.lock();
        peer_temp_details = Peers::temp_details->Get(peer_ip);
    /* While we have not got the response */
    } while (peer_temp_details != nullptr &&
             peer_temp_details->waiting_get_peer);
}

FORCE_INLINE
void Client::SendP2PHandshakeRequest(const uint32_t peer_ip,
                                     const bool nat_probe) {
    /* Try to get the temp peer details */
    std::unique_lock temp_details_lock(Peers::temp_details_mutex);
    Peers::TempDetails* const peer_temp_details =
        Peers::temp_details->Get(peer_ip);
    if (peer_temp_details == nullptr) return; //TODO: Try to get permanent one

    /* If we already are waiting for the response */
    if (peer_temp_details->waiting_handshake_response) return;
    peer_temp_details->waiting_handshake_response = true;

    /* Maximum: 8 attemps
     * Every: 6 seconds
     * Check for response every iteration */
    for (uint8_t i = 0; i < 8 && Peers::temp_details->Has(peer_ip); i++) {
        INFO_LOG("Sending a handshake request to the %s peer%s",
                 inet_ntoa({ peer_ip }),
                 nat_probe ? " via the server" : "");

        /* Get the current timestamp */
        const uint64_t timestamp = Time::Nanoseconds();

        /* Generate ephemeral keys pair */
        const Keys* const ephemeral_keys =
            peer_temp_details->ephemeral_keys =
            new Keys();

        /* Generate the nonce */
        Nonce* const nonce =
            peer_temp_details->nonce =
            new Nonce();

        /* Get the pointer to the chain key */
        uint8_t* const chain_key = peer_temp_details->chain_key;

        /* Assemble the handshake request package */
        P2PHandshakeRequest package(nonce,
                                    ephemeral_keys->Public(),
                                    timestamp,
                                    peer_ip,
                                    nat_probe);

        /* Compute the first shared secret */
        uint8_t shared[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(shared,
                              ephemeral_keys->Secret(),
                              peer_temp_details->public_static_key) == -1) {
            WARN_LOG("crypto_scalarmult: "
                     "Failed to compute the shared secret");
            continue;
        }

        /* Get the chained ChaCha20 key */
        hkdf(chain_key, nullptr, shared);

        /* Sign the package */
        {
            unsigned long long dummy_len;
            crypto_aead_chacha20poly1305_ietf_encrypt(
                package.poly1305_tag,
                &dummy_len,
                nullptr,
                0,
                (uint8_t*)(void*)&package.header,
                sizeof(package.header),
                nullptr,
                package.header.nonce,
                chain_key
            );
        }

        /* Get the endpoint */
        sockaddr_in endpoint;
        if (nat_probe) {
            std::lock_guard server_lock(Server::mutex);
            endpoint = Server::endpoint;
        } else endpoint = peer_temp_details->endpoint;

        /* Send the signed handshake request package */
        main_socket.Send((char*)(void*)&package, sizeof(package), endpoint);

        /* Wait for 6 seconds */
        temp_details_lock.unlock();
        usleep(6 * 1'000'000);
        temp_details_lock.lock();
    }

    /* TODO: Remove temporary entry if there is no response */
}

FORCE_INLINE void Client::NatProbe(const uint32_t peer_ip,
                                   const sockaddr_in real_endpoint) {
    INFO_LOG("Start a nat probing the %s peer", inet_ntoa({ peer_ip }));

    /* Send: 16 ping packages
     * Every: 250 ms
     * <this peer> -> <second peer> -> <relay server> -> <this peer> */
    #pragma unroll
    for (uint8_t i = 0; i < 16; ++i) {
        /* Wait for 250 ms */
        usleep(250 * 1'000);

        /* Try to get the peer details */
        std::shared_lock details_lock(Peers::details_mutex);
        Peers::Details* const peer_details = Peers::details->Get(peer_ip);
        if (peer_details == nullptr) {
            WARN_LOG("Not enough info for the nat probing");
            return;
        }

        /* If we already found that direct channel is available */
        if (equal(peer_details->endpoint, real_endpoint)) return;

        /* Get the current timestamp */
        const uint64_t timestamp = Time::Nanoseconds();

        /* Assemble the nat probe request package */
        NatProbeRequest package(peer_details->nonce, peer_ip, timestamp);

        /* Sign the package */
        {
            unsigned long long dummy_len;
            crypto_aead_chacha20poly1305_ietf_encrypt(
                package.poly1305_tag,
                &dummy_len,
                nullptr,
                0,
                (uint8_t*)(void*)&package.header,
                sizeof(package.header),
                nullptr,
                package.header.nonce,
                peer_details->key
            );
        }

        /* Update the last to package timestamp */
        peer_details->last_to_package_timestamp = timestamp;

        /* Send the package to the real endpoint */
        TRACE_LOG("Sending a nat probe request to the %s peer",
                  inet_ntoa({ peer_ip }));
        main_socket.Send((char*)(void*)&package,
                         sizeof(package),
                         real_endpoint);
    }

    /* Wait for 6 seconds */
    usleep(6 * 1'000'000);

    /* Try to delete the temp details entry */
    std::unique_lock temp_details_lock(Peers::temp_details_mutex);
    Peers::temp_details->Delete(peer_ip);
}
