#pragma once

#include "container/linked_list.h"
#include "package/server_handshake_request.h"
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

    static void HandlePackage(const char* buffer, const sockaddr_in& client);

private:
    static inline LinkedList<const unsigned char*>* _peers = nullptr;

    static inline unsigned int _peers_number = 0;

    static void HandleServerHandshakeRequest(
        UniqPtr<ServerHandshakeRequest> request,
        sockaddr_in client
    ) noexcept;
};
