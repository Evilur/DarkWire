#pragma once

#include "main.h"
#include "core/config.h"
#include "exception/tun_error.h"
#include "socket/udp_socket.h"
#include "type/string.h"
#include "util/class.h"
#include "util/logger.h"
#include "util/system.h"

#include <cstring>

#define _WIN32
#ifdef _WIN32
    #include <iphlpapi.h>
    #include <windows.h>
    #include <wintun.h>
    #include <ws2tcpip.h>

    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <fcntl.h>
    #include <linux/if.h>
    #include <linux/if_tun.h>
    #include <linux/ip.h>
    #include <sys/ioctl.h>
    #include <unistd.h>
#endif

/**
 * Class for working with virtual network interface
 * @author Evilur <the.evilur@gmail.com>
 */
class TUN final {
public:
    PREVENT_COPY_AND_MOVE(TUN);

    explicit TUN(const char* name);

    ~TUN() noexcept;

    void Up() noexcept;

    [[nodiscard]] bool IsUp() const noexcept;

    int32_t Read(char* buffer, uint32_t mtu) const noexcept;

    void Write(const char* buffer, uint32_t buffer_size) noexcept;

private:
    const String _tun_name;

#ifdef _WIN32
#else
    const int32_t _tun_fd;
#endif

    bool _is_up = false;
};

#ifdef _WIN32
#else
FORCE_INLINE TUN::TUN(const char* const name) : _tun_name(name),
    /* Open the TUN device */
    _tun_fd(open("/dev/net/tun", O_RDWR | O_CLOEXEC)) {
    if (_tun_fd == -1) throw TunError("Failed to open the TUN device");

    /* Set flags */
    ifreq ifr { };
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    /* Set the name of the new network interface */
    if (name == nullptr)
        throw TunError("Name of the tunnel cannot be nullptr");
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    /* Create a new network interface */
    if (ioctl(_tun_fd, TUNSETIFF, &ifr) == -1) {
        FATAL_LOG("Failed to create the virtual interface\n"
                  "Do you have enough permissions?");
        throw TunError("Ioctl TUNSETIFF failed");
    }

    /* IF all is OK */
    System::Exec(String::Format("sysctl -w net.ipv6.conf.%s.disable_ipv6=1",
                                name));
}

FORCE_INLINE TUN::~TUN() noexcept { close(_tun_fd); }

FORCE_INLINE void TUN::Up() noexcept {
    /* Exec pre up commands */
    for (const String& command : Config::Interface::pre_up)
        System::Exec(command);

    /* Up the interface */
    System::Exec(String::Format("ip addr add %s/%hhu dev %s",
                                inet_ntoa({ local_ip.Netb() }),
                                netmask,
                                _tun_name.CStr()));
    System::Exec(String::Format("ip link set %s mtu %d",
                                _tun_name.CStr(),
                                Config::Interface::mtu));
    System::Exec(String::Format("ip link set %s up", _tun_name.CStr()));
    INFO_LOG("Interface [%s] is up", _tun_name.CStr());
    _is_up = true;

    /* Exec post up commands */
    for (const String& command : Config::Interface::post_up)
        System::Exec(command);
}

FORCE_INLINE bool TUN::IsUp() const noexcept { return _is_up; }

FORCE_INLINE int32_t TUN::Read(char* const buffer, const uint32_t mtu)
const noexcept {
#if LOG_LEVEL == 0
    const int32_t result = (int32_t)read(_tun_fd, buffer, mtu);
    if (result != -1)
        TRACE_LOG("Read %d bytes from the TUN", result);
    else
        WARN_LOG("Failed to read the data from the TUN");
    return result;
#else
    return (int32_t)read(_tun_fd, buffer, mtu);
#endif
}

FORCE_INLINE void TUN::Write(const char* const buffer,
                       const uint32_t buffer_size) noexcept {
    TRACE_LOG("Writing %u bytes to the TUN", buffer_size);
    write(_tun_fd, buffer, buffer_size);
}
#endif
