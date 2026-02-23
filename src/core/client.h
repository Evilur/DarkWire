#pragma once

#include "util/class.h"

#include <netinet/in.h>
#include <sodium.h>

/**
 * Static class for client only methods
 * @author Evilur <the.evilur@gmail.com>
 */
class Client final {
public:
    PREVENT_INSTANTIATION(Client);

    static void SaveServer(const sockaddr_in& address,
                           const char* public_key_base64);

    static void PerformHandshakeWithServer() noexcept;

private:
    struct Server {
        static inline sockaddr_in address;
        static inline unsigned char* public_key = nullptr;
    };
};
