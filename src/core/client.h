#pragma once

#include "core/keys.h"
#include "package/handshake_response.h"
#include "type/uniq_ptr.h"
#include "util/class.h"

#include <ctime>
#include <netinet/in.h>
#include <sodium.h>

/**
 * Static class for client only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Client final {
public:
    PREVENT_INSTANTIATION(Client);

    static void Init();

    static void RunHandshakeLoop();

    static void HandlePackage(const char* buffer,
                              int buffer_size,
                              const sockaddr_in& from);

private:
    struct Server {
        static inline sockaddr_in endpoint;
        static inline unsigned char* public_key = nullptr;
        static inline unsigned char* chain_key = nullptr;
        static inline UniqPtr<Keys> ephemeral_keys = nullptr;
    };

    static inline unsigned long _next_handshake_timestamp =
        (unsigned long)std::time(nullptr);

    static void HandleHandshakeResponse(
        UniqPtr<HandshakeResponse> response,
        sockaddr_in from
    ) noexcept;
};
