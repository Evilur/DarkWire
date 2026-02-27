#include "tun.h"
#include "core/config.h"
#include "core/global.h"
#include "exception/tun_error.h"
#include "util/logger.h"
#include "util/system.h"

#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <unistd.h>

TUN::TUN(const char* const name) : _tun_name(name),
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

TUN::~TUN() noexcept { close(_tun_fd); }

void TUN::Up() noexcept {
    System::Exec(String::Format("ip addr add %s/%hhu dev %s",
                                inet_ntoa({ ip_address }), netmask,
                                _tun_name.CStr()));
    System::Exec(String::Format("ip link set %s up", _tun_name.CStr()));
    INFO_LOG("Interface [%s] is up", interface_name.CStr());
}

void TUN::Down() noexcept {
    System::Exec(String::Format("ip addr del dev %s", _tun_name.CStr()));
    System::Exec(String::Format("ip link set %s down", _tun_name.CStr()));
    INFO_LOG("Interface [%s] is down", interface_name.CStr());
}

void TUN::RunReadLoop() const {
    const unsigned int MTU = (unsigned int)(int)Config::Interface::mtu;
    char* const buffer = new char[MTU];
    for (;;) {
        /* Get the ip package */
        const int buffer_size = (int)read(_tun_fd, buffer, MTU);
        const iphdr* const ip_header = (const iphdr*)(const void*)buffer;

        /* Get the destinastion ip (int the host bytes order) */
        const unsigned int destinastion_ip = ntohl(ip_header->daddr);

        /* Drop multicasts */
        /* TODO: handle them (maybe) */
        if (destinastion_ip >= 0xE0000000 && destinastion_ip <= 0xEFFFFFFF)
            continue;

        DEBUG_LOG("Source IP: %s", inet_ntoa({ip_header->saddr}));
        DEBUG_LOG("Dest IP: %s", inet_ntoa({ip_header->daddr}));
    }
}

void TUN::Write() noexcept {
}
