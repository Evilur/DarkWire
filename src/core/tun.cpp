#include "tun.h"
#include "core/config.h"
#include "exception/tun_error.h"
#include "util/logger.h"
#include "util/system.h"

#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

TUN::TUN(const char* const name) : _tun_name(name),
    /* Open the TUN device */
    _tun_fd(open("/dev/net/tun", O_RDWR | O_CLOEXEC)) {
    if (_tun_fd == -1) throw TunError("Failed to open the TUN device");

    /* Set the name of the new network interface */
    ifreq ifr { };
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (name == nullptr)
        throw TunError("Name of the tunnel cannot be nullptr");
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    /* Create a new network interface */
    if (ioctl(_tun_fd, TUNSETIFF, (void*)&ifr) == -1) {
        FATAL_LOG("Failed to create the virtual interface\n"
                  "Do you have enough permissions?");
        throw TunError("Ioctl TUNSETIFF failed");
    }

    /* IF all is OK */
    System::Exec(String::Format("sysctl -w net.ipv6.conf.%s.disable_ipv6=1",
                                name));
    System::Exec(String::Format("ip addr add %s dev %s",
                                (const char*)Config::Interface::address,
                                name));
}

TUN::~TUN() noexcept { close(_tun_fd); }

void TUN::Up() const noexcept {
    System::Exec(String::Format("ip link set %s up",
                                (const char*)_tun_name));
}

void TUN::Down() const noexcept {
    System::Exec(String::Format("ip link set %s down",
                                (const char*)_tun_name));
}
