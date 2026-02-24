#pragma once

#include "type/dictionary.h"
#include "package/server_handshake_request.h"
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

    static void HandlePackage(const char* buffer, const sockaddr_in& client);

private:
    struct Peers {
        struct Details {
            unsigned long last_timestamp;
            unsigned int local_ip;
            sockaddr_in endpoint;
        } __attribute__((aligned(16)));

        static inline LinkedList<const unsigned char*>* public_keys = nullptr;
        static inline unsigned int number = 0;
        static inline Dictionary<KeyBuffer,
                                 Details,
                                 unsigned int>* peers = nullptr;
    };

    static void HandleServerHandshakeRequest(
        UniqPtr<ServerHandshakeRequest> request,
        sockaddr_in client
    ) noexcept;
};
