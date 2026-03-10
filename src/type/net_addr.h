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

    NetAddr() noexcept = default;

    ~NetAddr() noexcept = default;

    inline void SetHostb(unsigned int address) noexcept;

    inline void SetNetb(unsigned int address) noexcept;

    [[nodiscard]] inline unsigned int Hostb() const noexcept;

    [[nodiscard]] inline unsigned int Netb() const noexcept;

private:
    unsigned int _hostb = INADDR_ANY;
    unsigned int _netb = INADDR_ANY;
};

inline void NetAddr::SetHostb(const unsigned int address) noexcept {
    _hostb = address;
    _netb = htonl(address);
}

inline void NetAddr::SetNetb(const unsigned int address) noexcept {
    _hostb = ntohl(address);
    _netb = address;
}

inline unsigned int NetAddr::Hostb() const noexcept { return _hostb; }

inline unsigned int NetAddr::Netb() const noexcept { return _netb; }
