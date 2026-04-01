#pragma once

#include "util/class.h"
#include "socket/udp_socket.h"
#include "util/macro.h"

/**
 * Class fo store the ip address in hosts bytes order and net bytes order
 * @author Evilur <the.evilur@gmail.com>
 */
class NetAddr final {
public:
    ALLOW_COPY_ALLOW_MOVE(NetAddr);

    NetAddr() noexcept = default;

    ~NetAddr() noexcept = default;

    void SetHostb(uint32_t address) noexcept;

    void SetNetb(uint32_t address) noexcept;

    [[nodiscard]] uint32_t Hostb() const noexcept;

    [[nodiscard]] uint32_t Netb() const noexcept;

private:
    uint32_t _hostb = INADDR_ANY;
    uint32_t _netb = INADDR_ANY;
};

FORCE_INLINE void NetAddr::SetHostb(const uint32_t address) noexcept {
    _hostb = address;
    _netb = htonl(address);
}

FORCE_INLINE void NetAddr::SetNetb(const uint32_t address) noexcept {
    _hostb = ntohl(address);
    _netb = address;
}

FORCE_INLINE uint32_t NetAddr::Hostb() const noexcept { return _hostb; }

FORCE_INLINE uint32_t NetAddr::Netb() const noexcept { return _netb; }
