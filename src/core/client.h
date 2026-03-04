#pragma once

#include "core/config.h"
#include "core/global.h"
#include "core/keys.h"
#include "core/tun.h"
#include "package/handshake_request.h"
#include "package/handshake_response.h"
#include "package/keep_alive.h"
#include "package/transfer_data.h"
#include "type/dictionary.h"
#include "type/uniq_ptr.h"
#include "util/class.h"
#include "util/equal.h"
#include "util/hkdf.h"
#include "util/logger.h"

#include <cstring>
#include <ctime>
#include <netinet/in.h>
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

    inline static void Init();

    inline static void RunHandshakeLoop();

    inline static void RunHandlePackagesLoop();

    inline static void RunKeepAliveLoop() noexcept;

    inline static void HandleTunPackage(const char* buffer,
                                        unsigned int buffer_size,
                                        unsigned int destination_netb);

private:
    struct Server {
        static inline Nonce nonce;
        static inline sockaddr_in endpoint;
        static inline unsigned char* public_key = nullptr;
        static inline unsigned char* chain_key = nullptr;
        static inline UniqPtr<Keys> ephemeral_keys = nullptr;
        static inline std::mutex mutex;
    };

    static inline unsigned long _next_handshake_timestamp =
        (unsigned long)std::time(nullptr);

    inline static void HandleHandshakeResponse(
        UniqPtr<HandshakeResponse> response,
        sockaddr_in from
    ) noexcept;

    struct Peers {
        struct Details {
            sockaddr_in endpoint;
            unsigned long last_package_timestamp;
            unsigned char* key;
            Nonce nonce;
        } __attribute__((aligned(32)));

        static inline Dictionary<unsigned int,
                                 Details,
                                 unsigned int>* peers = nullptr;
        static inline std::mutex mutex;
    };

};

inline void Client::Init() {
    /* Get the address */
    Server::endpoint = UDPSocket::GetAddress(Config::Server::endpoint);

    /* Allocate memory for keys */
    Server::public_key =
        new unsigned char[crypto_scalarmult_BYTES];
    Server::chain_key =
        new unsigned char[crypto_aead_chacha20poly1305_KEYBYTES];

    /* Get the server's public key */
    const char* public_key_base64 = Config::Server::public_key;
    sodium_base642bin(Server::public_key, crypto_scalarmult_BYTES,
                      public_key_base64, strlen(public_key_base64),
                      nullptr, nullptr, nullptr,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Allocate memory for peers */
    std::lock_guard peers_lock(Peers::mutex);
    Peers::peers = new Dictionary<unsigned int,
                                  Peers::Details,
                                  unsigned int>(8);
}

inline void Client::RunHandshakeLoop() {
    /* Send a handhake request */
    for (;;) {
        /* Check the timestamp */
        const unsigned long current_time = std::time(nullptr);
        if (current_time < _next_handshake_timestamp) {
            usleep((unsigned int)(_next_handshake_timestamp - current_time)
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
        Server::nonce = Nonce();

        /* Fill the request */
        HandshakeRequest request(Server::ephemeral_keys->Public(),
                                 Server::nonce);

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

inline void Client::RunHandlePackagesLoop() {
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
            std::thread(&Handle##T, request, from).detach();                  \
        }

        /* Handle the package by its type */
        if (type == HANDSHAKE_RESPONSE)
            if (buffer_size == sizeof(HandshakeResponse)
                && equal(from, Server::endpoint))
                    COPY_BUFFER_TO_HEAP_AND_HANDLE_IT(HandshakeResponse);
    }
}

inline void Client::RunKeepAliveLoop() noexcept {
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

inline void Client::HandleTunPackage(const char* const buffer,
                                     const unsigned int buffer_size,
                                     const unsigned int destination_netb) {
    /* Try to get the details from the peers list */
    sockaddr_in endpoint;
    const unsigned char* key;
    Nonce* nonce;
    try {
        std::lock_guard peers_lock(Peers::mutex);
        Peers::Details& details = Peers::peers->Get(destination_netb);
        endpoint = details.endpoint;
        key = details.key;
        nonce = &details.nonce;
    /* If there is no such an ip in the dictionary */
    } catch (const DictionaryError&) {
        endpoint = Server::endpoint;
        key = Server::chain_key;
        nonce = &Server::nonce;

        /* TODO */
        /* Get the peer from the server */
    }

    TRACE_LOG("Sending the transfer data to the %s:%hu",
              inet_ntoa(endpoint.sin_addr),
              ntohs(endpoint.sin_port));

    /* Assemble the transfer data package */
    TransferData package(*nonce, buffer, buffer_size);
    const unsigned int package_size = package.Size(buffer_size);

    /* Encrypt the package */
    unsigned long long dummy_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        (unsigned char*)(void*)&package.payload,
        &dummy_len,
        (unsigned char*)(void*)&package.payload,
        buffer_size,
        (unsigned char*)(void*)&package.header,
        sizeof(package.header),
        nullptr,
        package.header.nonce,
        key
    );

    /* Send the encrypted message */
    main_socket.Send((char*)(void*)&package,
                     package_size,
                     endpoint);
}

inline void Client::HandleHandshakeResponse(
    const UniqPtr<HandshakeResponse> response,
    const sockaddr_in from
) noexcept {
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
    if (!tun->IsUp()) {
        /* Set the ip and the netmask */
        local_ip.SetNetb(response->payload.local_ip);
        netmask = response->payload.netmask;

        /* Calculate net-specific variables */
        calc_net();

        /* Up the interface */
        up_interface();

        /* Add the server to the peers list */
        std::lock_guard peers_lock(Peers::mutex);
        Peers::peers->Put(response->payload.server_local_ip, {
            .endpoint = Server::endpoint,
            .last_package_timestamp = ULONG_MAX,
            .key = Server::chain_key,
            .nonce = Server::nonce
        });
    }

    /* If all is OK, next handshake will be after 3 minutes */
    INFO_LOG("The handshake response has been successfully handled");
    _next_handshake_timestamp = (unsigned long)std::time(nullptr) + 180;
    Server::mutex.unlock();
}
