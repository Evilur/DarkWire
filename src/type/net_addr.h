#pragma once

#include "util/class.h"
#include "util/macro.h"

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

    void SetHostb(unsigned int address) noexcept;

    void SetNetb(unsigned int address) noexcept;

    [[nodiscard]] unsigned int Hostb() const noexcept;

    [[nodiscard]] unsigned int Netb() const noexcept;

private:
    unsigned int _hostb = INADDR_ANY;
    unsigned int _netb = INADDR_ANY;
};

FORCE_INLINE void NetAddr::SetHostb(const unsigned int address) noexcept {
    _hostb = address;
    _netb = htonl(address);
}

FORCE_INLINE void NetAddr::SetNetb(const unsigned int address) noexcept {
    _hostb = ntohl(address);
    _netb = address;
}

FORCE_INLINE unsigned int NetAddr::Hostb() const noexcept { return _hostb; }

FORCE_INLINE unsigned int NetAddr::Netb() const noexcept { return _netb; }
