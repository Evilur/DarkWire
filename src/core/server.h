#pragma once

#include "util/class.h"
#include "package/server_handshake_request.h"
#include <netinet/in.h>

/**
 * Static class for server only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Server final {
public:
    PREVENT_INSTANTIATION(Server);

    static void HandlePackage(const char* buffer,
                              const sockaddr_in& client);

private:
    static void HandleServerHandshakeRequest(
        const ServerHandshakeRequest* request,
        sockaddr_in client
    ) noexcept;
};
