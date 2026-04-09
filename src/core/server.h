#pragma once

#include "main.h"
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
#include <shared_mutex>

/**
 * Static class for server only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Server final {
public:
    PREVENT_INSTANTIATION(Server);

    static void SavePeer(const uint8_t* public_key);

    static void Init();

    static void RunHandlePackagesLoop() noexcept;

    static void HandleTunPackage(TransferData& package,
                                 int32_t package_size,
                                 uint32_t destination_ip) noexcept;

private:
    struct Peers final {
        struct Details final {
            UniqPtr<Nonce> nonce;
            sockaddr_in endpoint;
            uint8_t static_public_key[crypto_scalarmult_BYTES];
            uint8_t chain_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
            uint64_t last_timestamp;
        } __attribute__((aligned(128)));

        static inline uint32_t number = 0;
        static inline LinkedList<const uint8_t*>*
            public_keys = nullptr;
        static inline Dictionary<uint32_t, Details, uint32_t>*
            details = nullptr;
        static inline std::shared_mutex details_mutex;
        static inline Dictionary<KeyBuffer, uint64_t, uint32_t>*
            timestamps = nullptr;
        static inline std::mutex timestamps_mutex;
    };

    static void HandleHandshakeRequest(
        HandshakeRequest* package,
        uint32_t package_size,
        const sockaddr_in& from
    );

    static void HandleTransferData(
        TransferData* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;

    static void HandleKeepAlive(
        KeepAlive* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;

    static void HandleGetPeerRequest(
        GetPeerRequest* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;

    static void HandleP2PHandshakeRequest(
        P2PHandshakeRequest* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;

    static void HandleP2PHandshakeResponse(
        P2PHandshakeResponse* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;

    static void HandleNatProbeResponse(
        NatProbeResponse* package,
        uint32_t package_size,
        const sockaddr_in& from
    ) noexcept;
};

FORCE_INLINE void Server::SavePeer(const uint8_t* const public_key) {
    /* If the peers list isn't defined yet */
    if (Peers::public_keys == nullptr) {
        /* Allocate the memory for the peers list */
        Peers::public_keys = new LinkedList<const uint8_t*>();

        /* Set the program mode */
        mode = SERVER;
    }

    /* Push the peer to the list, and increment the counter */
    Peers::public_keys->Push(public_key);
    ++Peers::number;
}

FORCE_INLINE void Server::Init() {
    /* Increase send and receive buffers */
    const int32_t rcvbuf = 32 * 1024 * 1024 * (int32_t)Peers::number;
    const int32_t sndbuf = 32 * 1024 * 1024 * (int32_t)Peers::number;
    main_socket.SetOption(SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    main_socket.SetOption(SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* Allocate the memory for dictionaries */
    Peers::details = new Dictionary<uint32_t,
                                    Peers::Details,
                                    uint32_t>(Peers::number);
    Peers::timestamps = new Dictionary<KeyBuffer,
                                       uint64_t,
                                       uint32_t>(Peers::number);

    /* Fill timestamps dictionary with zeros */
    for (const uint8_t* public_key : *Peers::public_keys)
        Peers::timestamps->Put(public_key, 0ULL);

    /* Add server to the peers list */
    Peers::details->Put(local_ip.Netb(), { .nonce = nullptr });
}

FORCE_INLINE void Server::HandleTunPackage(TransferData& package,
                                           const int32_t package_size,
                                           const uint32_t destination_ip)
noexcept {
    /* Try to get the peers details */
    std::shared_lock details_lock(Peers::details_mutex);
    Peers::Details* const details = Peers::details->Get(destination_ip);
    if (details == nullptr) return;

    /* Update the package header */
    package.UpdateHeader(details->nonce, destination_ip, Time::Nanoseconds());

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
        details->chain_key
    );

    /* Send the encrypted message */
    main_socket.Send((char*)(void*)&package,
                     (int64_t)(sizeof(package.header) + data_size),
                     details->endpoint);
}

FORCE_INLINE void Server::RunHandlePackagesLoop() noexcept {
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
            HANDLE_PACKAGE(TransferData)
        if (type == KEEPALIVE &&
            buffer_size == sizeof(KeepAlive))
            HANDLE_PACKAGE(KeepAlive)
        if (type == HANDSHAKE_REQUEST &&
            buffer_size == sizeof(HandshakeRequest))
            HANDLE_PACKAGE(HandshakeRequest)
        if (type == GET_PEER_REQUEST &&
            buffer_size == sizeof(GetPeerRequest))
            HANDLE_PACKAGE(GetPeerRequest)
        if (type == NAT_PROBE_RESPONSE &&
            buffer_size == sizeof(NatProbeResponse))
            HANDLE_PACKAGE(NatProbeResponse);
        if (type == P2P_HANDSHAKE_REQUEST &&
            buffer_size == sizeof(P2PHandshakeRequest))
            HANDLE_PACKAGE(P2PHandshakeRequest);
        if (type == P2P_HANDSHAKE_RESPONSE &&
            buffer_size == sizeof(P2PHandshakeResponse))
            HANDLE_PACKAGE(P2PHandshakeResponse);
    }
}

FORCE_INLINE void Server::HandleHandshakeRequest(
    HandshakeRequest* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) {
    INFO_LOG("Receive a handshake request from %s:%hu",
             inet_ntoa(from.sin_addr),
             ntohs(from.sin_port));

    /* Buffer for the chained key */
    uint8_t chain_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];

    /* Decrypt the request data */
    {
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

        /* Decrypt the message */
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
        for (const uint8_t* public_key : *Peers::public_keys)
            if (memcmp(package->data.static_public_key,
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
        uint64_t current_time = (uint64_t)std::time(nullptr);
        uint64_t client_timestamp = package->data.timestamp;

        /* Get the delta time */
        uint64_t delta_time = current_time > client_timestamp
                                 ? current_time - client_timestamp
                                 : client_timestamp - current_time;

        /* If the time delta is too big */
        if (delta_time > 120) return;

        /* Get the last timestamp for such a key */
        std::lock_guard timestamps_lock(Peers::timestamps_mutex);
        uint64_t* const last_timestamp =
            Peers::timestamps->Get(package->data.static_public_key);

        /* Compare current timestamp with the last one */
        if (client_timestamp <= *last_timestamp) return;

        /* If all is ok, update the last timestamp */
        *last_timestamp = client_timestamp;
    }

    /* Variables for the response (default is data from the request) */
    uint32_t response_ip = package->data.ip;
    uint8_t response_netmask = package->data.netmask;

    /* Handle the local ip address and netmask */
    {
        /* Get the passed ip and the netmask */
        const uint32_t client_ip = response_ip;
        const uint8_t client_netmask = response_netmask;

        /* Try to delete the peer with such a static key (if exists) */
        std::unique_lock details_lock(Peers::details_mutex);
        for (const auto& [ip, details] : *Peers::details)
            if (equal(KeyBuffer(details.static_public_key),
                      KeyBuffer(package->data.static_public_key))) {
            Peers::details->Delete(ip);
            break;
        }

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
            const uint32_t start = network_prefix.Hostb();
            const uint32_t end = broadcast.Hostb();
            NetAddr random_ip; random_ip.SetHostb(
                (uint32_t)(start + (rand() % (end - start + 1)))
            );

            /* Try to get that ip from the details list */
            if (!Peers::details->Has(random_ip.Netb())) {
                response_ip = random_ip.Netb();
                goto the_end;
            }

            /* If the random ip is busy, try to get the free ip */
            for (uint32_t ip_hostb = random_ip.Hostb();
                 ip_hostb < end; ++ip_hostb) {
                const uint32_t ip_netb = htonl(ip_hostb);
                if (!Peers::details->Has(ip_netb)) {
                    response_ip = ip_netb;
                    goto the_end;
                }
            }
            for (uint32_t ip_hostb = random_ip.Hostb();
                 ip_hostb > start; --ip_hostb) {
                const uint32_t ip_netb = htonl(ip_hostb);
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
    uint8_t shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          ephemeral_keys.Secret(),
                          package->header.ephemeral_public_key) == -1) {
        WARN_LOG("crypto_scalarmult: Failed to compute the shared secret");
        return;
    }
    hkdf(chain_key, chain_key, shared);

    /* Compute the third shared secret and update the chain keys */
    if (crypto_scalarmult(shared,
                          ephemeral_keys.Secret(),
                          package->data.static_public_key) == -1) {
        WARN_LOG("crypto_scalarmult: Failed to compute the shared secret");
        return;
    }
    hkdf(chain_key, chain_key, shared);

    /* Get the nonce from the package */
    Nonce* nonce = new Nonce(package->header.nonce);

    /* If all is OK, save the current peer */
    /* TODO: check this */
    {
        Peers::Details details {
            .nonce = nonce,
            .endpoint = from,
            .last_timestamp = Time::Nanoseconds()
        };
        std::unique_lock details_lock(Peers::details_mutex);
        memcpy(details.static_public_key,
               package->data.static_public_key,
               crypto_scalarmult_BYTES);
        memcpy(details.chain_key,
               chain_key,
               crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        Peers::details->Put(response_ip, std::move(details));
    }

    /* Assemble the response */
    HandshakeResponse response(ephemeral_keys.Public(),
                               nonce,
                               response_ip,
                               response_netmask);

    /* Encrypt the resposne */
    unsigned long long dummy_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        (uint8_t*)(void*)&response.data,
        &dummy_len,
        (uint8_t*)(void*)&response.data,
        sizeof(response.data),
        (uint8_t*)(void*)&response.header,
        sizeof(response.header),
        nullptr,
        response.header.nonce,
        chain_key
    );

    /* Send the response */
    main_socket.Send((char*)(void*)&response,
                     sizeof(HandshakeResponse),
                     from);
}

FORCE_INLINE void Server::HandleTransferData(
    TransferData* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) noexcept {
    TRACE_LOG("Receive a transfer data from the %s:%hu",
              inet_ntoa(from.sin_addr),
              ntohs(from.sin_port));

    /* Get the destination IP address */
    uint32_t destination_netb = package->header.destination_ip;

    /* If we need to decrypt the package */
    if (destination_netb == local_ip.Netb()) {
        /* Try to get the key to decrypt the package */
        std::shared_lock details_lock(Peers::details_mutex);
        Peers::Details* const source_peer_details =
            Peers::details->Get(package->header.source_ip);
        if (source_peer_details == nullptr) { return; }

        /* Get the package timestamp */
        uint64_t package_timestamp = package->header.timestamp;

        /* Decrypt the package */
        unsigned long long data_size;
        if (package_timestamp <= source_peer_details->last_timestamp ||
            crypto_aead_chacha20poly1305_ietf_decrypt(
            (uint8_t*)package->data,
            &data_size,
            nullptr,
            (uint8_t*)package->data,
            package_size - sizeof(package->header),
            (uint8_t*)(void*)&package->header,
            sizeof(package->header),
            package->header.nonce,
            source_peer_details->chain_key
        ) != 0) {
            WARN_LOG("Forged message found");
            return;
        }

        /* Update the endpoint */
        if (!equal(source_peer_details->endpoint, from))
            source_peer_details->endpoint = from;

        /* Update the last timestamp */
        source_peer_details->last_timestamp = package_timestamp;

        /* Get the real destination address */
        destination_netb = ((iphdr*)(void*)package->data)->daddr;

        /* If we need to write the package to the TUN */
        if ((destination_netb & binmask.Netb()) != network_prefix.Netb() ||
            destination_netb == local_ip.Netb()) {
            tun->Write(package->data, (uint32_t)data_size);
            return;
        }

        /* If we need to resend the package to the other peer */
        Peers::Details* const dest_peer_details =
            Peers::details->Get(destination_netb);
        if (dest_peer_details == nullptr) return;

        TRACE_LOG("Resend the package to the %s:%hu",
                  inet_ntoa(dest_peer_details->endpoint.sin_addr),
                  ntohs(dest_peer_details->endpoint.sin_port));

        /* Update the package header */
        package->UpdateHeader(dest_peer_details->nonce,
                              destination_netb,
                              Time::Nanoseconds());

        /* Encrypt the package */
        crypto_aead_chacha20poly1305_ietf_encrypt(
            (uint8_t*)package->data,
            &data_size,
            (uint8_t*)package->data,
            data_size,
            (uint8_t*)(void*)&package->header,
            sizeof(package->header),
            nullptr,
            package->header.nonce,
            dest_peer_details->chain_key
        );

        /* Send the encrypted package */
        main_socket.Send((char*)(void*)package,
                         package_size,
                         dest_peer_details->endpoint);
    /* If we need to transit the package */
    } else {
        /* Try to get the peer endpoint */
        std::shared_lock details_lock(Peers::details_mutex);
        const Peers::Details* const peer_details =
            Peers::details->Get(destination_netb);
        if (peer_details == nullptr) return;

        TRACE_LOG("Transit the package to the %s:%hu",
                  inet_ntoa(peer_details->endpoint.sin_addr),
                  ntohs(peer_details->endpoint.sin_port));

        /* Send the package to the peer */
        main_socket.Send((char*)(void*)package,
                         package_size,
                         peer_details->endpoint);
    }
}

FORCE_INLINE void Server::HandleKeepAlive(
    KeepAlive* package,
    const uint32_t package_size,
    const sockaddr_in& from
) noexcept {
    TRACE_LOG("Receive a keep-alive package from the %s:%hu",
              inet_ntoa(from.sin_addr),
              ntohs(from.sin_port));

    /* Try to get the key to decrypt the package */
    std::shared_lock details_lock(Peers::details_mutex);
    Peers::Details* const peer_details =
        Peers::details->Get(package->header.source_ip);
    if (peer_details == nullptr) { return; }

    /* Get the package timestamp */
    const uint64_t package_timestamp = package->header.timestamp;

    /* Decrypt the package */
    unsigned long long data_size;
    if (package_timestamp <= peer_details->last_timestamp ||
        crypto_aead_chacha20poly1305_ietf_decrypt(
        package->poly1305_tag,
        &data_size,
        nullptr,
        package->poly1305_tag,
        sizeof(package->poly1305_tag),
        (uint8_t*)(void*)&package->header,
        sizeof(package->header),
        package->header.nonce,
        peer_details->chain_key
    ) != 0) {
        WARN_LOG("Forged message found");
        return;
    }
    details_lock.unlock();

    /* Update the endpoint */
    if (!equal(peer_details->endpoint, from)) peer_details->endpoint = from;

    /* Update the last timestamp */
    peer_details->last_timestamp = package_timestamp;
}

FORCE_INLINE void Server::HandleGetPeerRequest(
    GetPeerRequest* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) noexcept {
    INFO_LOG("Receive a get peer package from the %s:%hu",
             inet_ntoa(from.sin_addr),
             ntohs(from.sin_port));

    /* Try to get the key to decrypt the package */
    std::shared_lock details_lock(Peers::details_mutex);
    Peers::Details* const source_peer_details =
        Peers::details->Get(package->header.source_ip);
    if (source_peer_details == nullptr) { return; }

    /* Check the endpoint */
    if (!equal(source_peer_details->endpoint, from)) return;

    /* Get the package timestamp */
    const uint64_t package_timestamp = package->header.timestamp;

    /* Decrypt the package */
    unsigned long long dummy_len;
    if (package_timestamp <= source_peer_details->last_timestamp ||
        crypto_aead_chacha20poly1305_ietf_decrypt(
        (uint8_t*)(void*)&package->data,
        &dummy_len,
        nullptr,
        (uint8_t*)(void*)&package->data,
        sizeof(package->data) + sizeof(package->poly1305_tag),
        (uint8_t*)(void*)&package->header,
        sizeof(package->header),
        package->header.nonce,
        source_peer_details->chain_key
    ) != 0) {
        WARN_LOG("Forged message found");
        return;
    }

    /* Update the endpoint */
    if (!equal(source_peer_details->endpoint, from))
        source_peer_details->endpoint = from;

    /* Update the last timestamp */
    source_peer_details->last_timestamp = package_timestamp;

    /* Get the peer local ip */
    uint32_t peer_ip = package->data.requested_peer_ip;

    /* Get the requested peer */
    Peers::Details* const requested_peer_details =
        Peers::details->Get(peer_ip);

    /* Send the requested peer to the source */
    {
        /* Assemble the response */
        GetPeerResponse response(source_peer_details->nonce, peer_ip);

        /* If there is no such a peer */
        if (requested_peer_details == nullptr)
            response.SetData({ .sin_port = 0, .sin_addr = INADDR_ANY },
                             nullptr);
        /* If we have a peer with such an ip */
        else
            response.SetData(requested_peer_details->endpoint,
                             requested_peer_details->static_public_key);

        /* Encrypt the response */
        crypto_aead_chacha20poly1305_ietf_encrypt(
            (uint8_t*)(void*)&response.data,
            &dummy_len,
            (uint8_t*)(void*)&response.data,
            sizeof(response.data),
            (uint8_t*)(void*)&response.header,
            sizeof(response.header),
            nullptr,
            response.header.nonce,
            source_peer_details->chain_key
        );

        /* Send the response to the client */
        INFO_LOG("Sending the get peer response to the %s:%hu",
                 inet_ntoa(from.sin_addr),
                 ntohs(from.sin_port));
        main_socket.Send((char*)(void*)&response, sizeof(response), from);
    }

    /* Send the source peer to the requested */
    {
        /* Check the requested peer */
        if (requested_peer_details == nullptr) return;

        /* Assemble the response */
        GetPeerResponse response(requested_peer_details->nonce,
                                 package->header.source_ip);

        response.SetData(source_peer_details->endpoint,
                         source_peer_details->static_public_key);

        /* Encrypt the response */
        crypto_aead_chacha20poly1305_ietf_encrypt(
            (uint8_t*)(void*)&response.data,
            &dummy_len,
            (uint8_t*)(void*)&response.data,
            sizeof(response.data),
            (uint8_t*)(void*)&response.header,
            sizeof(response.header),
            nullptr,
            response.header.nonce,
            requested_peer_details->chain_key
        );

        /* Send the response to the client */
        const sockaddr_in& requested_peer = requested_peer_details->endpoint;
        INFO_LOG("Sending the get peer response to the %s:%hu",
                 inet_ntoa(requested_peer.sin_addr),
                 ntohs(requested_peer.sin_port));
        main_socket.Send((char*)(void*)&response,
                         sizeof(response),
                         requested_peer);
    }
}

#define TRANSIT_PACKAGE(T)                                                    \
{                                                                             \
    /* Get the peer to transit for */                                         \
    std::shared_lock details_lock(Peers::details_mutex);                      \
    const Peers::Details* const peer_details =                                \
        Peers::details->Get(package->header.destination_ip);                  \
    if (peer_details == nullptr) return;                                      \
                                                                              \
    /* Transit the package to the other peer */                               \
    TRACE_LOG("Transit the '%s' package to the %s:%hu",                       \
              #T,                                                             \
              inet_ntoa(peer_details->endpoint.sin_addr),                     \
              ntohs(peer_details->endpoint.sin_port));                        \
    main_socket.Send((char*)(void*)package,                                   \
                     package_size,                                            \
                     peer_details->endpoint);                                 \
}

FORCE_INLINE void Server::HandleP2PHandshakeRequest(
    P2PHandshakeRequest* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) noexcept { TRANSIT_PACKAGE(P2PHandshakeRequest); }

FORCE_INLINE void Server::HandleP2PHandshakeResponse(
    P2PHandshakeResponse* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) noexcept { TRANSIT_PACKAGE(P2PHandshakeResponse); }

FORCE_INLINE void Server::HandleNatProbeResponse(
    NatProbeResponse* const package,
    const uint32_t package_size,
    const sockaddr_in& from
) noexcept { TRANSIT_PACKAGE(NatProbeResponse); }
