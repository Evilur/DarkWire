#pragma once

#include "util/class.h"

#include <netinet/in.h>

/**
 * Class fo store the ip address in hosts bytes order and net bytes order
 * @author Evilur <the.evilur@gmail.com>
 */
class NetAddr final {
public:
    ALLOW_COPY_ALLOW_MOVE(NetAddr);

    unsigned int hostb = INADDR_ANY;
    unsigned int netb = INADDR_ANY;

     NetAddr() noexcept = default;

    ~NetAddr() noexcept = default;

    inline void SetHostb(unsigned int address) noexcept;

    inline void SetNetb(unsigned int address) noexcept;
};

inline void NetAddr::SetHostb(const unsigned int address) noexcept {
    hostb = address;
    netb = htonl(address);
}

inline void NetAddr::SetNetb(const unsigned int address) noexcept {
    hostb = ntohl(address);
    netb = address;
}
