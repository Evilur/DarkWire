#pragma once

#include "util/class.h"
#include "package/server_handshake_request.h"

/**
 * Static class for server only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Server final {
public:
    PREVENT_INSTANTIATION(Server);

    static void HandlePackage(const char* buffer) noexcept;

private:
    static void HandleServerHandshakeRequest(
        const ServerHandshakeRequest* request
    ) noexcept;
};
