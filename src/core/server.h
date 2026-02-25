#pragma once

#include "type/dictionary.h"
#include "package/handshake_request.h"
#include "type/linked_list.h"
#include "type/uniq_ptr_imp.h"
#include "util/class.h"

#include <netinet/in.h>

/**
 * Static class for server only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Server final {
public:
    PREVENT_INSTANTIATION(Server);

    static void SavePeer(const unsigned char* public_key);

    static void Init();

    static void HandlePackage(const char* buffer, int buffer_size,
                              const sockaddr_in& client);

private:
    struct Peers {
        struct Details {
            sockaddr_in endpoint;
            unsigned char static_public_key[crypto_scalarmult_BYTES];
            unsigned char chain_key[crypto_aead_chacha20poly1305_KEYBYTES];
        } __attribute__((aligned(128)));

        static inline unsigned int number = 0;
        static inline LinkedList<const unsigned char*>* public_keys = nullptr;
        static inline Dictionary<unsigned int,
                                 Details,
                                 unsigned int>* peers = nullptr;
        static inline Dictionary<KeyBuffer,
                                 unsigned long,
                                 unsigned int>* timestamps = nullptr;
    };

    static void HandleHandshakeRequest(
        UniqPtr<HandshakeRequest> request,
        sockaddr_in client
    ) noexcept;
};
